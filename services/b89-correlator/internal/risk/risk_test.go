package risk

import (
	"math"
	"testing"
	"time"

	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/model"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/resolve"
)

var t0 = time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)

func obs(id string, at time.Duration, rule string, level int, source string, tactics []string, stages []model.Stage, ents ...string) model.Observation {
	o := model.Observation{ID: id, Time: t0.Add(at), RuleID: rule, Level: level, Source: source, Tactics: tactics, Stages: stages}
	for _, k := range ents {
		e, _ := model.ParseKey(k)
		o.Entities = append(o.Entities, e)
	}
	return o
}

func newEngine() *Engine {
	return NewEngine(DefaultPolicy(), DefaultPatterns(), resolve.New(nil, ""), nil, 7)
}

func TestDecayHalvesPerHalfLife(t *testing.T) {
	got := Decay(100, t0, t0.Add(12*time.Hour), 12*time.Hour)
	if math.Abs(got-50) > 1e-9 {
		t.Fatalf("decay after one half-life = %v", got)
	}
	if Decay(100, t0, t0.Add(-time.Hour), 12*time.Hour) != 100 {
		t.Fatal("no negative decay")
	}
	if got := Decay(80, t0, t0.Add(36*time.Hour), 12*time.Hour); math.Abs(got-10) > 1e-9 {
		t.Fatalf("three half-lives = %v", got)
	}
}

func TestContributionWeights(t *testing.T) {
	if LevelPoints(12) != 20 || LevelPoints(3) != 0.5 || LevelPoints(2) != 0 {
		t.Fatal("level points")
	}
	if TacticWeight([]string{"discovery", "exfiltration"}) != 1.8 || TacticWeight(nil) != 1 {
		t.Fatal("tactic weight uses the max")
	}
	e := NewEngine(DefaultPolicy(), nil, nil, func(en model.Entity) string {
		if en.Value == "crown-jewel" {
			return "critical"
		}
		return ""
	}, 7)
	e.Process(obs("a", 0, "r1", 10, "wazuh", nil, nil, "host:crown-jewel"))
	e.Process(obs("b", 0, "r1", 10, "wazuh", nil, nil, "host:plain"))
	crit := e.states["host:crown-jewel"].Base(t0, e.P)
	plain := e.states["host:plain"].Base(t0, e.P)
	if crit != 2*plain || plain != 10 {
		t.Fatalf("criticality multiplier: %v vs %v", crit, plain)
	}
}

func TestRepetitionIsDampenedAndCapped(t *testing.T) {
	e := newEngine()
	for i := 0; i < 50; i++ {
		e.Process(obs(string(rune('a'+i)), time.Duration(i)*time.Minute, "5710", 10, "linux-ssh", nil, nil, "ip:203.0.113.1"))
	}
	base := e.states["ip:203.0.113.1"].Base(t0.Add(49*time.Minute), e.P)
	// 10 + 5 + 2.5 + ... < 20: a single noisy rule can never reach the threshold alone.
	if base > e.P.RulePointCap || base >= e.P.Threshold {
		t.Fatalf("noisy rule not bounded: %v", base)
	}
	if len(e.Candidates("", 0)) != 0 {
		t.Fatal("a single repeating rule must not create a candidate")
	}
}

func TestDiversityAndProgressionRaiseEffectiveScore(t *testing.T) {
	e := newEngine()
	e.Process(obs("1", 0, "r1", 9, "m365", []string{"credential-access"}, nil, "user:u@x.example"))
	single := e.states["user:u@x.example"].Effective(t0, e.P)
	e.Process(obs("2", time.Minute, "r2", 9, "aws", []string{"privilege-escalation"}, nil, "user:u@x.example"))
	both := e.states["user:u@x.example"].Effective(t0.Add(time.Minute), e.P)
	if both.Diversity != 1.25 {
		t.Fatalf("diversity multiplier = %v", both.Diversity)
	}
	// credential-access (7) after privilege-escalation (5)? order by first seen: cred then priv => backwards.
	if both.Progression != e.P.TacticStepBonus {
		t.Fatalf("progression = %v", both.Progression)
	}
	e2 := newEngine()
	e2.Process(obs("1", 0, "r1", 9, "m365", []string{"initial-access"}, nil, "user:v@x.example"))
	e2.Process(obs("2", time.Minute, "r2", 9, "aws", []string{"privilege-escalation"}, nil, "user:v@x.example"))
	fwd := e2.states["user:v@x.example"].Effective(t0.Add(time.Minute), e2.P)
	if fwd.Progression != e2.P.TacticStepBonus+e2.P.ProgressionBonus {
		t.Fatalf("forward progression = %v", fwd.Progression)
	}
	if fwd.Effective <= single.Effective {
		t.Fatal("effective score should grow")
	}
}

func TestThresholdCandidateOncePerEpisode(t *testing.T) {
	e := newEngine()
	ent := "host:web-1"
	rules := []string{"a", "b", "c", "d", "e", "f"}
	var created []*model.Candidate
	for i, r := range rules {
		created = append(created, e.Process(obs("x"+r, time.Duration(i)*time.Minute, r, 12, []string{"wazuh", "fim", "web"}[i%3], []string{"execution"}, nil, ent))...)
	}
	if len(created) != 1 || created[0].Kind != "threshold" || created[0].Entity.Key() != ent {
		t.Fatalf("expected one threshold candidate, got %+v", created)
	}
	// More activity in the same episode: no new candidate, but it joins the group.
	more := e.Process(obs("y", 10*time.Minute, "g", 12, "wazuh", nil, nil, ent))
	if len(more) != 0 {
		t.Fatal("same episode must not emit twice")
	}
	if c, _ := e.Candidate(created[0].ID); c.MemberCount < 2 {
		t.Fatalf("member count = %d", c.MemberCount)
	}
	// After cooling below half the threshold, a new crossing is a new episode.
	later := 5 * 24 * time.Hour
	e.Process(obs("z0", later, "zz", 3, "wazuh", nil, nil, ent))
	var again []*model.Candidate
	for i, r := range rules {
		again = append(again, e.Process(obs("w"+r, later+time.Duration(i+1)*time.Minute, "n"+r, 12, []string{"wazuh", "fim", "web"}[i%3], nil, nil, ent))...)
	}
	if len(again) != 1 || again[0].ID == created[0].ID {
		t.Fatalf("expected a new episode candidate, got %d", len(again))
	}
}

func TestEdgeToSSHPattern(t *testing.T) {
	e := newEngine()
	ip := "ip:203.0.113.77"
	if c := e.Process(obs("1", 0, "101501", 6, "cloudflare", nil, []model.Stage{model.StageEdgeWAFBlock}, ip)); len(c) != 0 {
		t.Fatal("one stage is not a pattern")
	}
	if c := e.Process(obs("2", 20*time.Minute, "31151", 10, "web", nil, []model.Stage{model.StageEdgeScan}, ip)); len(c) != 0 {
		t.Fatal("waf+scan without the required SSH stage is not a candidate")
	}
	c := e.Process(obs("3", 40*time.Minute, "5712", 10, "linux-ssh", nil, []model.Stage{model.StageSSHBruteForce}, ip))
	var pat *model.Candidate
	for _, x := range c {
		if x.PatternID == "edge-to-ssh" {
			pat = x
		}
	}
	if pat == nil || len(pat.Stages) != 3 || pat.Priority != "P2" {
		t.Fatalf("edge-to-ssh complete: %+v", c)
	}
	if again := e.Process(obs("4", 41*time.Minute, "5712", 10, "linux-ssh", nil, []model.Stage{model.StageSSHBruteForce}, ip)); len(again) != 0 {
		t.Fatal("the same pattern episode is emitted once")
	}
}

func TestOrderedPatternRequiresOrder(t *testing.T) {
	e := newEngine()
	u := "user:v@x.example"
	// privileged change BEFORE the failures/success: no credential-to-privilege.
	e.Process(obs("1", 0, "p", 12, "aws", nil, []model.Stage{model.StagePrivilegedChange}, u))
	e.Process(obs("2", time.Minute, "f", 5, "aws", nil, []model.Stage{model.StageAuthFailure}, u))
	c := e.Process(obs("3", 2*time.Minute, "s", 3, "aws", nil, []model.Stage{model.StageAuthSuccess}, u))
	for _, x := range c {
		if x.PatternID == "credential-to-privilege" {
			t.Fatal("out-of-order stages must not match")
		}
	}
	c = e.Process(obs("4", 3*time.Minute, "p2", 12, "aws", nil, []model.Stage{model.StagePrivilegedChange}, u))
	found := false
	for _, x := range c {
		if x.PatternID == "credential-to-privilege" && x.Priority == "P1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("in-order chain should match: %+v", c)
	}
}

func TestUnorderedPatternAndWindow(t *testing.T) {
	e := newEngine()
	h := "host:pc-ep-a"
	e.Process(obs("1", 0, "m", 12, "bitdefender", nil, []model.Stage{model.StageEndpointMalware}, h))
	c := e.Process(obs("2", 80*time.Hour, "off", 10, "bitdefender", nil, []model.Stage{model.StageProtectionOff}, h))
	for _, x := range c {
		if x.PatternID == "endpoint-protection-and-malware" {
			t.Fatal("outside the 72h window")
		}
	}
	c = e.Process(obs("3", 81*time.Hour, "m", 12, "bitdefender", nil, []model.Stage{model.StageEndpointMalware}, h))
	found := false
	for _, x := range c {
		found = found || x.PatternID == "endpoint-protection-and-malware"
	}
	if !found {
		t.Fatal("unordered pattern inside window")
	}
}

type fixedSuppressor struct{ rule, key string }

func (f fixedSuppressor) Suppressed(rule, key string, _ time.Time) bool {
	return rule == f.rule && key == f.key
}

func TestSuppressionZeroesContribution(t *testing.T) {
	e := newEngine()
	e.SetSuppressor(fixedSuppressor{"r1", "ip:192.0.2.200"})
	e.Process(obs("1", 0, "r1", 12, "cloudflare", nil, []model.Stage{model.StageEdgeWAFBlock}, "ip:192.0.2.200"))
	st := e.states["ip:192.0.2.200"]
	if st.Base(t0, e.P) != 0 || st.Suppressed != 1 || !st.Contributors[0].Suppressed {
		t.Fatalf("suppressed contribution: %+v", st.Contributors)
	}
	if e.Stats().Suppressed != 1 {
		t.Fatal("suppressed counter")
	}
}

func TestDuplicateObservationIgnored(t *testing.T) {
	e := newEngine()
	e.Process(obs("same", 0, "r", 10, "w", nil, nil, "ip:192.0.2.1"))
	e.Process(obs("same", 0, "r", 10, "w", nil, nil, "ip:192.0.2.1"))
	if e.Stats().Duplicates != 1 || e.Stats().Observations != 1 {
		t.Fatalf("dedup: %+v", e.Stats())
	}
}

func TestAliasMergeFoldsState(t *testing.T) {
	r := resolve.New(nil, "")
	e := NewEngine(DefaultPolicy(), nil, r, nil, 7)
	e.Process(obs("1", 0, "a", 10, "bitdefender", nil, nil, "host:pc-ep-a-laptop"))
	// A later document links both names through a shared private IP.
	o1, _ := r.Observe(resolve.Doc{"timestamp": "2026-11-04T10:01:00Z", "id": "2", "rule": map[string]any{"id": "b", "level": 10.0},
		"agent": map[string]any{"id": "003", "name": "pc-ep-a", "ip": "10.89.0.30"}})
	e.Process(o1)
	o2, _ := r.Observe(resolve.Doc{"timestamp": "2026-11-04T10:02:00Z", "id": "3", "rule": map[string]any{"id": "c", "level": 10.0},
		"data":  map[string]any{"b89": map[string]any{"vendor": "bitdefender"}, "bitdefender": map[string]any{"endpoint": map[string]any{"name": "PC-EP-A-LAPTOP", "ip": "10.89.0.30"}}},
		"agent": map[string]any{"id": "000", "name": "mgr"}})
	e.Process(o2)
	counts := e.EntityCounts()
	if counts["host"] != 1 {
		t.Fatalf("hosts after merge: %v (%v)", counts, e.Keys("host"))
	}
	d, ok := e.Detail("host:pc-ep-a-laptop", t0.Add(3*time.Minute))
	if !ok || d.Observations != 3 {
		t.Fatalf("merged detail: %+v", d.EntitySummary)
	}
}

func TestGroupingAndReduction(t *testing.T) {
	at := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }
	alerts := []model.B89Alert{}
	for i := 0; i < 10; i++ {
		alerts = append(alerts, model.B89Alert{ID: string(rune('a' + i)), RuleID: "r", EntityKeys: []string{"user:u@x.example", "ip:1.2.3.4"}, OccurredAt: at(i * 30)})
	}
	// Same user after a 5h gap: a new group.
	alerts = append(alerts, model.B89Alert{ID: "late", RuleID: "r", EntityKeys: []string{"user:u@x.example"}, OccurredAt: at(9*30 + 300)})
	// No entities: grouped by rule.
	alerts = append(alerts, model.B89Alert{ID: "n1", RuleID: "510", OccurredAt: at(1)}, model.B89Alert{ID: "n2", RuleID: "510", OccurredAt: at(2)})
	res := DedupAlerts(alerts, func(k string) string { return k }, 4*time.Hour, 24*time.Hour)
	if res.Alerts != 13 || res.Groups != 3 || res.Reduction != 4.33 {
		t.Fatalf("dedup: %+v", res)
	}
	if res.ByPivot["user"] != 2 || res.ByPivot["rule"] != 1 {
		t.Fatalf("pivots: %v", res.ByPivot)
	}
	if PivotOf([]string{"ip:1.2.3.4", "host:h", "cloud:c"}, "r") != "host:h" {
		t.Fatal("pivot precedence")
	}
	g := NewGrouper(time.Hour, 2*time.Hour)
	for i := 0; i < 5; i++ {
		g.Add("ip:x", "r", at(i*40)) // spans 160 min > 2h max span -> 2 groups
	}
	if g.Groups != 2 {
		t.Fatalf("max span split: %d", g.Groups)
	}
}
