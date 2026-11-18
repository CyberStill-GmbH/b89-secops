package risk

import (
	"fmt"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/model"
	"testing"
	"time"
)

func TestMemberLedgerReplayAndRestart(t *testing.T) {
	dir := t.TempDir()
	e := newEngine()
	if err := e.EnableMemberLedger(dir); err != nil {
		t.Fatal(err)
	}
	pivot := "host:ledger"
	id := candidateID("ledger-test")
	c := &model.Candidate{ID: id, FirstSeen: t0, LastSeen: t0}
	e.open[pivot] = []*model.Candidate{c}
	alerts := make([]model.B89Alert, 75)
	for i := range alerts {
		alerts[i] = model.B89Alert{ID: fmt.Sprintf("alert-%02d", i), EntityKeys: []string{pivot}, OccurredAt: t0}
	}
	for n := 0; n < 2; n++ {
		if err := e.AttachAlerts(alerts); err != nil {
			t.Fatal(err)
		}
	}
	if c.LinkedAlertCount != 75 || len(c.B89AlertIDs) != 50 {
		t.Fatalf("unexpected summary %d/%d", c.LinkedAlertCount, len(c.B89AlertIDs))
	}
	resumed := newEngine()
	if err := resumed.EnableMemberLedger(dir); err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for offset := 0; ; {
		page, ok, err := resumed.MemberPage(id, offset, 20)
		if err != nil || !ok || page.Total != 75 {
			t.Fatalf("invalid page %v %v %d", err, ok, page.Total)
		}
		got = append(got, page.Items...)
		if page.NextOffset == nil {
			break
		}
		offset = *page.NextOffset
	}
	for i, a := range alerts {
		if got[i] != a.ID {
			t.Fatalf("wrong member at %d", i)
		}
	}
}

func TestObservationMembersPersistAcrossPagesAndRestart(t *testing.T) {
	dir := t.TempDir()
	e := newEngine()
	if err := e.EnableMemberLedger(dir); err != nil {
		t.Fatal(err)
	}
	pivot := "host:ledger-endpoint"
	e.Process(obs("start", 0, "a", 9, "bitdefender", nil, []model.Stage{model.StageProtectionOff}, pivot))
	created := e.Process(obs("finish", time.Minute, "b", 9, "bitdefender", nil, []model.Stage{model.StageEndpointMalware}, pivot))
	var id string
	for _, c := range created {
		if c.PatternID == "endpoint-protection-and-malware" {
			id = c.ID
		}
	}
	if id == "" {
		t.Fatal("candidate missing")
	}
	for i := 0; i < 80; i++ {
		o := obs(fmt.Sprintf("obs-%02d", i), 2*time.Minute, "c", 7, "siem", nil, nil, pivot)
		e.Process(o)
		e.Process(o)
		if i%10 == 0 {
			if err := e.FlushMembers(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := e.FlushMembers(); err != nil {
		t.Fatal(err)
	}
	fresh := newEngine()
	if err := fresh.EnableMemberLedger(dir); err != nil {
		t.Fatal(err)
	}
	c, found, err := fresh.ArchivedCandidate(id)
	if err != nil || !found || c.PatternID != "endpoint-protection-and-malware" {
		t.Fatalf("candidate snapshot %v %v", found, err)
	}
	page, found, err := fresh.MemberPageByKind(id, "observations", 50, 50)
	if err != nil || !found || page.Total != 82 || len(page.Items) != 32 {
		t.Fatalf("unexpected observation page %+v %v %v", page, found, err)
	}
}

func TestEmittedCandidateLookupSurvivesRestartAndReplay(t *testing.T) {
	dir := t.TempDir()
	start := func() *Engine {
		e := newEngine()
		if err := e.EnableMemberLedger(dir); err != nil {
			t.Fatal(err)
		}
		return e
	}
	e := start()
	id := candidateID("archived-emission")
	entity := &EntityState{Entity: model.Entity{Type: "host", Value: "example"}}
	register := func(e *Engine) *model.Candidate {
		return e.register(entity, &model.Candidate{ID: id, Status: model.CandidateProposed})
	}
	register(e)
	if err := e.RecordEmission(id, "alert-emitted"); err != nil {
		t.Fatal(err)
	}
	resumed := start()
	check := func(e *Engine) {
		c, found, err := e.CandidateByAlert("alert-emitted")
		if err != nil || !found || c.ID != id || c.Status != model.CandidateEmitted || c.AlertID != "alert-emitted" {
			t.Fatalf("emitted lookup: %+v, %v, %v", c, found, err)
		}
		page, found, err := e.MemberPage(id, 0, 100)
		if err != nil || !found || page.Total != 0 {
			t.Fatalf("empty alert members: %+v %v %v", page, found, err)
		}
	}
	check(resumed)
	register(resumed)
	check(resumed)
	// Pruning may evict a dirty candidate before the next page flush.
	delete(resumed.byID, id)
	if err := resumed.FlushMembers(); err != nil {
		t.Fatal(err)
	}
	check(start())
}
