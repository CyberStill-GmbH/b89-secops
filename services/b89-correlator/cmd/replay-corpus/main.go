// replay-corpus compares two pattern configurations using independent in-memory engines.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/evaluation"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/model"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/risk"
)

type frame struct {
	CorpusID, SourceSnapshotSHA256, AnnotationProtocol string
	EvaluationStart, EvaluationEnd                     time.Time
	BaselinePatterns, CandidatePatterns                json.RawMessage
	Families                                           []family
}

type family struct {
	PatternID            string
	EligibleSourceEvents *int64
	Windows              []window
}

type window struct {
	ID, EntityKey, Source, Label, BaselinePriority, DuplicateGroup string
	Start, End                                                     time.Time
}

type windowRef struct {
	start, end time.Time
	example    *evaluation.Example
	group      string
}

type pivot struct{ pattern, entity string }

type variant struct {
	engine     *risk.Engine
	version    string
	seenGroups map[pivot]map[string]bool
}

func newVariant(raw json.RawMessage) (variant, error) {
	if len(raw) == 0 {
		return variant{}, errors.New("both pattern configurations are required")
	}
	patterns, err := risk.ConfiguredPatterns(string(raw))
	if err != nil {
		return variant{}, err
	}
	h := sha256.New()
	for _, p := range patterns {
		fmt.Fprintln(h, p.Fingerprint())
	}
	return variant{
		engine:     risk.NewEngine(risk.DefaultPolicy(), patterns, nil, nil, 7),
		version:    fmt.Sprintf("patterns-%x", h.Sum(nil)),
		seenGroups: make(map[pivot]map[string]bool),
	}, nil
}

func decode(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("expected exactly one JSON value")
	}
	return nil
}

func replay(f frame, snapshot []byte) (evaluation.Corpus, error) {
	var empty evaluation.Corpus
	if f.EvaluationStart.IsZero() || !f.EvaluationEnd.After(f.EvaluationStart) {
		return empty, errors.New("both holdout bounds are required and end must follow start")
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(snapshot))
	if !strings.EqualFold(hash, f.SourceSnapshotSHA256) {
		return empty, errors.New("observation snapshot hash differs from frame")
	}
	base, err := newVariant(f.BaselinePatterns)
	if err != nil {
		return empty, err
	}
	next, err := newVariant(f.CandidatePatterns)
	if err != nil {
		return empty, err
	}
	known := map[string]bool{}
	for _, p := range base.engine.Patterns {
		known[p.ID] = true
	}
	output := evaluation.Corpus{
		SchemaVersion: evaluation.SchemaVersion, CorpusID: f.CorpusID, SourceSnapshotSHA256: hash,
		AnnotationProtocol: f.AnnotationProtocol, BaselineVersion: base.version, CandidateVersion: next.version,
		EvaluationStart: f.EvaluationStart.Format(time.RFC3339Nano), EvaluationEnd: f.EvaluationEnd.Format(time.RFC3339Nano),
	}
	index := make(map[pivot][]windowRef)
	selected := make(map[string]bool)
	for _, fam := range f.Families {
		if !known[fam.PatternID] || fam.EligibleSourceEvents == nil || len(fam.Windows) == 0 {
			return empty, errors.New("each family requires a known pattern, eligible event count and adjudicated windows")
		}
		selected[fam.PatternID] = true
		row := evaluation.Family{ID: fam.PatternID, EligibleSourceEvents: *fam.EligibleSourceEvents, Examples: make([]evaluation.Example, len(fam.Windows))}
		for i, w := range fam.Windows {
			if _, ok := model.ParseKey(w.EntityKey); !ok || w.Source == "" || w.DuplicateGroup == "" || !w.End.After(w.Start) || w.Start.Before(f.EvaluationStart) || w.End.After(f.EvaluationEnd) {
				return empty, fmt.Errorf("invalid attribution or holdout bounds for window %q", w.ID)
			}
			row.Examples[i] = evaluation.Example{ID: w.ID, OccurredAt: w.Start.Format(time.RFC3339Nano), Label: w.Label, Source: w.Source, BaselinePriority: w.BaselinePriority}
			key := pivot{fam.PatternID, w.EntityKey}
			index[key] = append(index[key], windowRef{w.Start, w.End, &row.Examples[i], w.DuplicateGroup})
		}
		output.Families = append(output.Families, row)
	}
	for _, windows := range index {
		sort.Slice(windows, func(i, j int) bool { return windows[i].start.Before(windows[j].start) })
		for i := 1; i < len(windows); i++ {
			if windows[i].start.Before(windows[i-1].end) {
				return empty, errors.New("overlapping windows for same entity and pattern")
			}
		}
	}
	var observations []model.Observation
	if err := decode(snapshot, &observations); err != nil {
		return empty, err
	}
	if len(observations) == 0 {
		return empty, errors.New("observation snapshot is empty")
	}
	var last, lastPrune time.Time
	for i, o := range observations {
		if o.ID == "" || o.Source == "" || o.RuleID == "" || o.Time.IsZero() || o.IngestedAt.IsZero() || o.Level < 0 || o.Level > 15 || o.IngestedAt.Before(last) || !o.IngestedAt.Before(f.EvaluationEnd) {
			return empty, fmt.Errorf("invalid observation or arrival order at row %d", i+1)
		}
		for _, ent := range o.Entities {
			pv := o.Provenance[ent.Key()]
			if _, ok := model.ParseKey(ent.Key()); !ok || pv.Key != ent.Key() || pv.Confidence.Rank() == 0 {
				return empty, fmt.Errorf("invalid entity provenance at row %d", i+1)
			}
		}
		last = o.IngestedAt
		if lastPrune.IsZero() || last.Sub(lastPrune) >= time.Hour {
			base.engine.Prune(last)
			next.engine.Prune(last)
			lastPrune = last
		}
		for version, v := range []*variant{&base, &next} {
			for _, c := range v.engine.Process(o) {
				if last.Before(f.EvaluationStart) || c.Kind != "pattern" || !selected[c.PatternID] {
					continue
				}
				key := pivot{c.PatternID, c.Entity.Key()}
				windows := index[key]
				j := sort.Search(len(windows), func(k int) bool { return windows[k].end.After(last) })
				if j == len(windows) || windows[j].start.After(last) {
					return empty, fmt.Errorf("unadjudicated %s opening at row %d", c.PatternID, i+1)
				}
				w := windows[j]
				if v.seenGroups[key] == nil {
					v.seenGroups[key] = map[string]bool{}
				}
				duplicate := v.seenGroups[key][w.group]
				v.seenGroups[key][w.group] = true
				if version == 0 {
					if w.example.BaselineDetected {
						return empty, fmt.Errorf("multiple baseline openings in window %q", w.example.ID)
					}
					w.example.BaselineDetected = true
					w.example.BaselineDuplicate = &duplicate
					w.example.BaselinePriority = c.Priority
				} else {
					if w.example.CandidateDetected {
						return empty, fmt.Errorf("multiple candidate openings in window %q", w.example.ID)
					}
					w.example.CandidateDetected = true
					w.example.CandidateDuplicate = duplicate
				}
			}
		}
	}
	if _, err := evaluation.Evaluate(output); err != nil {
		return empty, err
	}
	return output, nil
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, evaluation.MaxInputBytes+1))
	if int64(len(b)) > evaluation.MaxInputBytes {
		return nil, errors.New("file exceeds 32 MiB")
	}
	return b, err
}

func run(framePath, snapshotPath string, out io.Writer) error {
	raw, err := readFile(framePath)
	if err != nil {
		return err
	}
	var f frame
	if err := decode(raw, &f); err != nil {
		return err
	}
	raw, err = readFile(snapshotPath)
	if err != nil {
		return err
	}
	corpus, err := replay(f, raw)
	if err != nil {
		return err
	}
	result, err := json.Marshal(corpus)
	if err != nil {
		return err
	}
	if int64(len(result))+1 > evaluation.MaxInputBytes {
		return errors.New("result exceeds evaluator input limit")
	}
	_, err = out.Write(append(result, '\n'))
	return err
}

func main() {
	framePath := flag.String("frame", "", "adjudicated holdout frame JSON")
	snapshotPath := flag.String("observations", "", "normalized observation array JSON")
	flag.Parse()
	if *framePath == "" || *snapshotPath == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*framePath, *snapshotPath, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
