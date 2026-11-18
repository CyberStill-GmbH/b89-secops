package risk

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/model"
)

const seqUser = "user:ana@b89.io"

func withProvenance(o model.Observation, confidence model.Confidence, method string) model.Observation {
	o.Provenance = map[string]model.Provenance{}
	for _, e := range o.Entities {
		o.Provenance[e.Key()] = model.Provenance{Key: e.Key(), Field: "fixture", Method: method, Confidence: confidence}
	}
	return o
}

// identityChain returns, in event order: a baseline sign-in (known location), an MFA change,
// a sign-in from a new country and endpoint activity, each from a distinct rule.
func identityChain() []model.Observation {
	baseline := obs("base", 0, "91545", 3, "m365", nil, []model.Stage{model.StageAuthSuccess}, seqUser, "ip:198.51.100.10")
	baseline.Location = "peru"
	change := obs("mfa", 2*time.Hour, "91600", 8, "m365", nil, []model.Stage{model.StageIdentityChange}, seqUser)
	change.StageCriteria = map[model.Stage]string{model.StageIdentityChange: "data.office365.Operation=User registered security info"}
	login := obs("login", 3*time.Hour, "91545", 3, "m365", nil, []model.Stage{model.StageAuthSuccess}, seqUser, "ip:203.0.113.7")
	login.Location = "romania"
	endpoint := obs("logon", 4*time.Hour, "60106", 5, "windows", nil, []model.Stage{model.StageEndpointActivity}, seqUser, "host:ws-ana")
	out := []model.Observation{baseline, change, login, endpoint}
	for i := range out {
		out[i] = withProvenance(out[i], model.ConfidenceHigh, "exact")
		out[i].IngestedAt = out[i].Time
	}
	return out
}

func shadowPatternActive() []Pattern {
	ps := DefaultPatterns()
	for i := range ps {
		ps[i].Mode = model.ModeActive
	}
	return ps
}

func sequenceCandidates(e *Engine) []model.Candidate {
	out := []model.Candidate{}
	for _, c := range e.Candidates("", 0) {
		if c.PatternID == "identity-change-new-location-endpoint" {
			out = append(out, c)
		}
	}
	return out
}

func TestIdentitySequenceExplainsEachStepAndRunsInShadow(t *testing.T) {
	e := newEngine()
	for _, o := range identityChain() {
		e.Process(o)
	}
	got := sequenceCandidates(e)
	if len(got) != 1 {
		t.Fatalf("want one sequence candidate, got %d", len(got))
	}
	c := got[0]
	if c.Status != model.CandidateShadow || c.Mode != model.ModeShadow {
		t.Fatalf("new rule must run in shadow mode: %s/%s", c.Status, c.Mode)
	}
	stages := []model.Stage{}
	for _, h := range c.Stages {
		stages = append(stages, h.Stage)
		if h.Criteria == "" {
			t.Fatalf("step %s has no satisfying evidence", h.Stage)
		}
	}
	want := []model.Stage{model.StageIdentityChange, model.StageNewLocation, model.StageEndpointActivity}
	if !reflect.DeepEqual(stages, want) {
		t.Fatalf("stages %v", stages)
	}
	if !strings.Contains(c.Stages[1].Criteria, "romania") || !strings.Contains(c.Stages[1].Criteria, "peru") {
		t.Fatalf("new-location criteria must name the new and previous locations: %q", c.Stages[1].Criteria)
	}
	checks := map[string]model.Check{}
	for _, ch := range c.Explanation.Checks {
		checks[ch.Name] = ch
	}
	for _, name := range []string{"etapas", "ventana", "fuentes distintas", "reglas distintas", "orden temporal", "confianza del pivote"} {
		if !checks[name].Met {
			t.Fatalf("check %q not met or missing: %+v", name, c.Explanation.Checks)
		}
	}
	if !strings.HasPrefix(c.Explanation.Narrative, "Correlación temporal; no demuestra causalidad") {
		t.Fatal("narrative must state that order is not causality")
	}
	if c.Explanation.Lifecycle != CandidateLifecycle || c.Explanation.PatternVersion == "" {
		t.Fatal("explanation must carry lifecycle and rule version")
	}
	if e.Stats().ShadowCandidates != 1 {
		t.Fatal("shadow candidates must be counted")
	}
}

func TestSequenceRequiresOrderAndDiversity(t *testing.T) {
	chain := identityChain()
	// Endpoint activity before the identity change breaks the order.
	chain[3].Time = t0.Add(time.Hour)
	e := NewEngine(DefaultPolicy(), shadowPatternActive(), nil, nil, 7)
	for _, o := range chain {
		e.Process(o)
	}
	if n := len(sequenceCandidates(e)); n != 0 {
		t.Fatalf("out-of-order steps must not match, got %d", n)
	}
	// Same source for every step does not satisfy the source quorum.
	chain = identityChain()
	chain[3].Source = "m365"
	e = NewEngine(DefaultPolicy(), shadowPatternActive(), nil, nil, 7)
	for _, o := range chain {
		e.Process(o)
	}
	if n := len(sequenceCandidates(e)); n != 0 {
		t.Fatalf("single-source chain must not match, got %d", n)
	}
}

func TestFirstLocationIsNeverNew(t *testing.T) {
	chain := identityChain()[1:] // no baseline sign-in
	e := NewEngine(DefaultPolicy(), shadowPatternActive(), nil, nil, 7)
	for _, o := range chain {
		e.Process(o)
	}
	if n := len(sequenceCandidates(e)); n != 0 {
		t.Fatalf("without a location baseline there is no new location, got %d", n)
	}
}

func TestLowConfidenceIdentityNeverPivotsASequence(t *testing.T) {
	e := NewEngine(DefaultPolicy(), shadowPatternActive(), nil, nil, 7)
	for _, o := range identityChain() {
		e.Process(withProvenance(o, model.ConfidenceLow, "bare_name"))
	}
	if n := len(sequenceCandidates(e)); n != 0 {
		t.Fatalf("bare-name attribution must not connect steps, got %d", n)
	}
	// Risk still accrues: the entity is tracked, it simply cannot connect a sequence.
	if _, ok := e.Detail(seqUser, t0.Add(5*time.Hour)); !ok {
		t.Fatal("low-confidence entity must still be tracked for context")
	}
}

func TestMediumConfidencePivotIsExplainedAsContradiction(t *testing.T) {
	e := NewEngine(DefaultPolicy(), shadowPatternActive(), nil, nil, 7)
	for _, o := range identityChain() {
		e.Process(withProvenance(o, model.ConfidenceMedium, "domain_default"))
	}
	got := sequenceCandidates(e)
	if len(got) != 1 {
		t.Fatalf("medium confidence may pivot, got %d", len(got))
	}
	found := false
	for _, line := range got[0].Explanation.Contradictions {
		found = found || strings.Contains(line, "domain_default")
	}
	if !found {
		t.Fatalf("pivot normalization must be surfaced: %v", got[0].Explanation.Contradictions)
	}
}

// signature is the order-independent identity of the complete sequence candidates.
func signature(e *Engine) []string {
	out := []string{}
	for _, c := range sequenceCandidates(e) {
		if len(c.Stages) != 3 {
			continue
		}
		ids := []string{}
		for _, h := range c.Stages {
			ids = append(ids, h.ObsID)
		}
		out = append(out, c.ID+"="+strings.Join(ids, ","))
	}
	sort.Strings(out)
	return out
}

func TestLateEvidenceCompletesTheSameCandidateInAnyArrivalOrder(t *testing.T) {
	forward := NewEngine(DefaultPolicy(), shadowPatternActive(), nil, nil, 7)
	for _, o := range identityChain() {
		forward.Process(o)
	}
	want := signature(forward)
	if len(want) != 1 {
		t.Fatalf("forward order: %v", want)
	}
	chain := identityChain()
	orders := [][]int{{0, 3, 2, 1}, {0, 1, 3, 2}, {0, 2, 3, 1}}
	for _, order := range orders {
		e := NewEngine(DefaultPolicy(), shadowPatternActive(), nil, nil, 7)
		for _, i := range order {
			e.Process(chain[i])
		}
		if got := signature(e); !reflect.DeepEqual(got, want) {
			t.Fatalf("arrival order %v produced %v, want %v", order, got, want)
		}
	}
}

func TestLateStepEvidenceRevisesTheExistingCandidate(t *testing.T) {
	e := NewEngine(DefaultPolicy(), shadowPatternActive(), nil, nil, 7)
	for _, o := range identityChain() {
		e.Process(o)
	}
	before := sequenceCandidates(e)[0]
	late := obs("logon-late", 3*time.Hour+30*time.Minute, "60107", 5, "windows", nil, []model.Stage{model.StageEndpointActivity}, seqUser, "host:ws-ana")
	late = withProvenance(late, model.ConfidenceHigh, "exact")
	late.IngestedAt = t0.Add(6 * time.Hour)
	if created := e.Process(late); len(created) != 0 {
		t.Fatalf("late evidence of the same episode must not open a new candidate: %d", len(created))
	}
	got := sequenceCandidates(e)
	if len(got) != 1 {
		t.Fatalf("still one candidate, got %d", len(got))
	}
	after := got[0]
	if after.ID != before.ID || after.Revision != before.Revision+1 {
		t.Fatalf("candidate must be revised in place: %d -> %d", before.Revision, after.Revision)
	}
	if len(after.Explanation.AdditionalStageEvidence) != 1 || after.Explanation.AdditionalStageEvidence[0].ObsID != "logon-late" {
		t.Fatalf("late step evidence must be listed: %+v", after.Explanation.AdditionalStageEvidence)
	}
	// Replaying the same late observation is a duplicate and changes nothing.
	e.Process(late)
	if again := sequenceCandidates(e)[0]; again.Revision != after.Revision {
		t.Fatal("replay must be idempotent")
	}
	if e.Stats().CandidatesUpdated != 1 {
		t.Fatalf("updates counted: %d", e.Stats().CandidatesUpdated)
	}
}

func TestReplayAndRestartRebuildIdenticalCandidatesAndMembership(t *testing.T) {
	dir := t.TempDir()
	run := func() (*Engine, []string) {
		e := NewEngine(DefaultPolicy(), shadowPatternActive(), nil, nil, 7)
		if err := e.EnableMemberLedger(dir); err != nil {
			t.Fatal(err)
		}
		// Overlapping reads: the whole chain twice, then a reversed replay.
		chain := identityChain()
		for pass := 0; pass < 2; pass++ {
			for _, o := range chain {
				e.Process(o)
			}
		}
		for i := len(chain) - 1; i >= 0; i-- {
			e.Process(chain[i])
		}
		if err := e.FlushMembers(); err != nil {
			t.Fatal(err)
		}
		ids := []string{}
		for _, c := range e.Candidates("", 0) {
			ids = append(ids, fmt.Sprintf("%s|%s|%d", c.ID, c.Status, len(c.Stages)))
		}
		sort.Strings(ids)
		return e, ids
	}
	first, firstIDs := run()
	if first.Stats().Duplicates != 8 {
		t.Fatalf("overlap must be skipped by id: %d duplicates", first.Stats().Duplicates)
	}
	restarted, restartedIDs := run() // a new process over the same ledger directory
	if !reflect.DeepEqual(firstIDs, restartedIDs) {
		t.Fatalf("restart changed candidates:\n%v\n%v", firstIDs, restartedIDs)
	}
	c := sequenceCandidates(restarted)[0]
	page, ok, err := restarted.MemberPageByKind(c.ID, "observations", 0, 500)
	if err != nil || !ok {
		t.Fatalf("members: %v %v", ok, err)
	}
	seen := map[string]bool{}
	for _, id := range page.Items {
		if seen[id] {
			t.Fatalf("ledger duplicated %s after replay/restart", id)
		}
		seen[id] = true
	}
	for _, want := range []string{"mfa", "login", "logon"} {
		if !seen[want] {
			t.Fatalf("ledger lost step evidence %s: %v", want, page.Items)
		}
	}
}

func TestShadowModeOverrideAndCoverageGapsInExplanation(t *testing.T) {
	ps, err := ConfiguredPatterns(`[{"ID":"identity-change-new-location-endpoint","Mode":"active","MinDistinctRules":3}]`)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(DefaultPolicy(), ps, nil, nil, 7)
	e.SetCoverage(func(sources []string, from, to time.Time) []string {
		return []string{"Cobertura incompleta de windows (collector_behind_provider)."}
	})
	for _, o := range identityChain() {
		e.Process(o)
	}
	got := sequenceCandidates(e)
	if len(got) != 1 || got[0].Status != model.CandidateProposed || got[0].Mode != model.ModeActive {
		t.Fatalf("activated rule must propose: %+v", got)
	}
	if !contains(got[0].Explanation.MissingData, "Cobertura incompleta de windows (collector_behind_provider).") {
		t.Fatalf("coverage gaps must be stated: %v", got[0].Explanation.MissingData)
	}
	if _, err := ConfiguredPatterns(`[{"ID":"identity-change-new-location-endpoint","Mode":"loud"}]`); err == nil {
		t.Fatal("unknown mode must be rejected")
	}
	if _, err := ConfiguredPatterns(`[{"ID":"edge-to-ssh","MinStages":0}]`); err == nil {
		t.Fatal("stage quorum below required stages must be rejected")
	}
}

func TestBenignVerdictsAreSurfacedAsContradictions(t *testing.T) {
	e := NewEngine(DefaultPolicy(), shadowPatternActive(), nil, nil, 7)
	for _, o := range identityChain() {
		e.Process(o)
	}
	c := sequenceCandidates(e)[0]
	err := e.AttachAlerts([]model.B89Alert{
		{ID: "00000000-0000-4000-8000-000000000001", RuleID: "91600", EntityKeys: []string{seqUser}, OccurredAt: c.FirstSeen, Verdict: "benign"},
		{ID: "00000000-0000-4000-8000-000000000002", RuleID: "60106", EntityKeys: []string{seqUser}, OccurredAt: c.LastSeen, Verdict: "true_positive"},
	})
	if err != nil {
		t.Fatal(err)
	}
	c = sequenceCandidates(e)[0]
	found := false
	for _, line := range c.Explanation.Contradictions {
		found = found || strings.HasPrefix(line, "1 alertas vinculadas tienen veredicto")
	}
	if !found || c.LinkedAlertCount != 2 {
		t.Fatalf("benign verdict must be a contradiction and originals stay linked: %v %d", c.Explanation.Contradictions, c.LinkedAlertCount)
	}
}
