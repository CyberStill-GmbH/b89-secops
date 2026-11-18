package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/sources"
)

func heartbeatDoc(at time.Time, vendor, outcome string, lag float64) map[string]any {
	return map[string]any{
		"timestamp": at.Format(time.RFC3339Nano), "id": "hb-" + vendor + at.Format("150405"),
		"rule": map[string]any{"id": "100900", "level": float64(3)},
		"data": map[string]any{"b89": map[string]any{"vendor": vendor, "event_type": "source_heartbeat",
			"heartbeat": map[string]any{"outcome": outcome, "finished_at": at.Format(time.RFC3339Nano),
				"provider_lag_seconds": lag, "cursor_position": "pos-1"}}},
	}
}

func TestCoverageIsIncompleteWhenCollectorIsBehindNotSilent(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	docs := []map[string]any{
		heartbeatDoc(now.Add(-30*time.Second), "m365", "ok", 3600), // collector an hour behind
		heartbeatDoc(now.Add(-30*time.Second), "aws", "ok", 30),
	}
	docs = append(docs, pageDocs(now.Add(-40*time.Second), "evt")...)
	gw := &paginationGateway{pages: []paginationPage{{docs: docs}}}
	r := paginationRunner(gw, &now, 1)
	if _, err := r.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := r.Readiness(now)
	if state.CoverageComplete {
		t.Fatal("coverage must not be complete while a collector is behind")
	}
	if p := state.Sources["m365"]; p.Coverage != "incomplete" || p.CoverageReason != "collector_behind_provider" || p.ProviderWatermark != "pos-1" {
		t.Fatalf("m365 coverage %+v", p)
	}
	if p := state.Sources["aws"]; p.Coverage != "complete" {
		t.Fatalf("aws coverage %+v", p)
	}
	// Events without any collector heartbeat: unknown, never "no activity".
	if p := state.Sources["wazuh"]; p.Coverage != "unknown" || p.Processed != 1 {
		t.Fatalf("wazuh coverage %+v", p)
	}
	if r.C.Heartbeats.Load() != 2 || r.Eng.Stats().Observations != 1 {
		t.Fatal("heartbeats are coverage evidence, not observations")
	}
	gaps := r.coverageGaps([]string{"m365", "aws", "snyk"}, now.Add(-time.Hour), now)
	joined := strings.Join(gaps, "\n")
	if !strings.Contains(joined, "Cobertura incompleta de m365") || strings.Contains(joined, "de aws") || !strings.Contains(joined, "snyk no verificada") {
		t.Fatalf("gaps: %v", gaps)
	}
}

func TestCorrelatorCatchingUpMarksEverySourceIncomplete(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	eventAt := now.Add(-30 * time.Second)
	docs := append([]map[string]any{heartbeatDoc(eventAt, "aws", "ok", 0)}, pageDocs(eventAt, "a")...)
	gw := &paginationGateway{pages: []paginationPage{{docs: docs, next: pageCursor(eventAt, "a")}}}
	r := paginationRunner(gw, &now, 1)
	if _, err := r.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := r.Readiness(now)
	if !state.PollWindowPending || state.PendingWindowDocs == 0 {
		t.Fatalf("pending window progress must be visible: %+v", state)
	}
	if p := state.Sources["aws"]; p.Coverage != "incomplete" || p.CoverageReason != "correlator_catching_up" {
		t.Fatalf("a healthy collector is still incomplete while the correlator is behind: %+v", p)
	}
	_ = sources.Cursor{}
}

func TestDuplicateReadsAreCountedPerSource(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	eventAt := now.Add(-30 * time.Second)
	gw := &paginationGateway{pages: []paginationPage{
		{docs: pageDocs(eventAt, "a", "b")},
		{docs: pageDocs(eventAt, "a", "b", "c")}, // overlapping re-read
	}}
	r := paginationRunner(gw, &now, 1)
	for i := 0; i < 2; i++ {
		if _, err := r.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
	}
	p := r.Readiness(now).Sources["wazuh"]
	if p.Processed != 3 || p.Duplicates != 2 || p.Reads != 5 {
		t.Fatalf("per-source counts %+v", p)
	}
}
