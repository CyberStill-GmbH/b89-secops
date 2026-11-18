package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/evaluation"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/model"
)

func fixture(t *testing.T) (frame, []byte) {
	t.Helper()
	start := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	ent := model.Entity{Type: model.EntityIP, Value: "ip-01"}
	obs := func(id string, stage model.Stage, event, arrival time.Time) model.Observation {
		return model.Observation{ID: id, Source: "linux", RuleID: id, Level: 5, Time: event, IngestedAt: arrival, Entities: []model.Entity{ent}, Stages: []model.Stage{stage}, Provenance: map[string]model.Provenance{ent.Key(): {Key: ent.Key(), Method: "exact", Confidence: model.ConfidenceHigh}}}
	}
	// The late first stage completes the baseline sequence on arrival in holdout.
	prior := obs("one", model.StageSSHSuccess, start.Add(-time.Minute), start.Add(-time.Minute))
	late := obs("two", model.StageSSHBruteForce, start.Add(-2*time.Hour), start)
	raw, err := json.Marshal([]model.Observation{prior, late, late})
	if err != nil {
		t.Fatal(err)
	}
	count := int64(1)
	win := window{ID: "w1", EntityKey: ent.Key(), Source: "linux", Label: "positive", BaselinePriority: "P3", Start: start, End: start.Add(time.Hour), DuplicateGroup: "case-1"}
	quiet := win
	quiet.ID = "w2"
	quiet.Start = win.End
	quiet.End = quiet.Start.Add(time.Hour)
	quiet.Label = "negative"
	return frame{CorpusID: "test", SourceSnapshotSHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), AnnotationProtocol: "synthetic", EvaluationStart: start, EvaluationEnd: quiet.End,
		BaselinePatterns: json.RawMessage("[]"), CandidatePatterns: json.RawMessage(`[{"ID":"ssh-bruteforce-then-access","Window":"1h"}]`),
		Families: []family{{PatternID: "ssh-bruteforce-then-access", EligibleSourceEvents: &count, Windows: []window{win, quiet}}}}, raw
}

func TestFilesProduceEvaluableCorpus(t *testing.T) {
	f, observations := fixture(t)
	dir := t.TempDir()
	framePath := filepath.Join(dir, "frame.json")
	observationPath := filepath.Join(dir, "observations.json")
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(framePath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(observationPath, observations, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(framePath, observationPath, &out); err != nil {
		t.Fatal(err)
	}
	corpus, err := evaluation.Decode(&out)
	if err != nil {
		t.Fatal(err)
	}
	report, err := evaluation.Evaluate(corpus)
	if err != nil {
		t.Fatal(err)
	}
	if report.Overall.ConfusionMatrix.FalseNegative != 1 || report.OverallBaseline.ConfusionMatrix.TruePositive != 1 || report.GuardrailsPassed || report.SufficientEvidence {
		t.Fatalf("unexpected metrics or release guardrails")
	}
}

func TestPairedLateOpeningAndNonDetection(t *testing.T) {
	f, raw := fixture(t)
	out, err := replay(f, raw)
	if err != nil {
		t.Fatal(err)
	}
	w := out.Families[0].Examples
	if !w[0].BaselineDetected || w[0].CandidateDetected || w[0].BaselinePriority != "P1" || w[0].BaselineDuplicate == nil || *w[0].BaselineDuplicate || w[1].BaselineDetected || w[1].CandidateDetected {
		t.Fatalf("unexpected windows: %+v", w)
	}
}

func TestPairedIndependentDuplicateGroups(t *testing.T) {
	f, raw := fixture(t)
	var rows []model.Observation
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	second := f.EvaluationStart.Add(48 * time.Hour)
	for i, stage := range []model.Stage{model.StageSSHBruteForce, model.StageSSHSuccess} {
		o := rows[0]
		o.ID = fmt.Sprint("next-", i)
		o.Time = second.Add(time.Duration(i) * time.Minute)
		o.IngestedAt = o.Time
		o.Stages = []model.Stage{stage}
		rows = append(rows, o)
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	f.SourceSnapshotSHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
	w := &f.Families[0].Windows[1]
	w.Start = second
	w.End = second.Add(time.Hour)
	f.EvaluationEnd = w.End
	out, err := replay(f, raw)
	if err != nil {
		t.Fatal(err)
	}
	d := out.Families[0].Examples[1]
	if !d.CandidateDetected || !d.BaselineDetected || d.BaselineDuplicate == nil || !*d.BaselineDuplicate || d.CandidateDuplicate {
		t.Fatalf("unexpected duplicate attribution %+v", d)
	}
}

func TestRejectUnusableFrames(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		modify       func(*frame)
	}{
		{"digest", "hash", func(f *frame) { f.SourceSnapshotSHA256 = "bad" }},
		{"unmatched", "unadjudicated", func(f *frame) { f.Families[0].Windows[0].Start = f.EvaluationStart.Add(time.Nanosecond) }},
		{"overlap", "overlapping", func(f *frame) { f.Families[0].Windows[1].Start = f.EvaluationStart }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, raw := fixture(t)
			tc.modify(&f)
			if _, err := replay(f, raw); err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
