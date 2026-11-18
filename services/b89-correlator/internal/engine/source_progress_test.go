package engine

import (
	"context"
	"testing"
	"time"
)

func TestReadinessPreservesSourceEventTimeOnLateArrival(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	gw := &paginationGateway{pages: []paginationPage{
		{docs: pageDocs(now.Add(-time.Second), "first")},
		{docs: pageDocs(now.Add(-30*time.Second), "late")},
	}}
	r := paginationRunner(gw, &now, 1)
	for i := 0; i < 2; i++ {
		if _, err := r.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
	}
	p := r.Readiness(now).Sources["wazuh"]
	if p.Reads != 2 || p.LastEventAgeSeconds != 3 || !p.LastRead.Equal(now.Add(-time.Second)) {
		t.Fatalf("source progress after late arrival: %+v", p)
	}
}
