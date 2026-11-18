package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRestartRebuildsHistoryAndScansEntireOfflineInterval(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "poll-watermark.v1")
	before := paginationRunner(&paginationGateway{pages: []paginationPage{{}}}, &now, 1)
	before.Opt.WatermarkPath = path
	if _, err := before.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	checkpoint := now
	now = now.Add(50 * time.Hour)
	gw := &paginationGateway{pages: []paginationPage{{}, {}, {}}}
	after := paginationRunner(gw, &now, 1)
	after.Opt.WatermarkPath = path
	if _, err := after.Backfill(context.Background()); err != nil {
		t.Fatal(err)
	}
	cursor := checkpoint.Add(-after.Opt.Backfill)
	for _, call := range gw.calls {
		if !call.from.Equal(cursor) || call.to.Before(cursor) || call.to.Sub(cursor) > 24*time.Hour {
			t.Fatalf("non-contiguous or oversized interval at %v: %+v", cursor, call)
		}
		cursor = call.to
	}
	last, err := loadWatermark(path)
	if err != nil || !last.Equal(now) || !cursor.Equal(now) {
		t.Fatalf("offline interval not fully recovered: cursor=%v checkpoint=%v err=%v", cursor, last, err)
	}
}

func TestIncompletePollAndInvalidCheckpointNeverAdvanceCoverage(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	old := now.Add(-time.Hour)
	path := filepath.Join(t.TempDir(), "poll-watermark.v1")
	if err := saveWatermark(path, old); err != nil {
		t.Fatal(err)
	}
	gw := &paginationGateway{pages: []paginationPage{{docs: pageDocs(now, "a"), next: pageCursor(now, "a")}}}
	r := paginationRunner(gw, &now, 1)
	r.Opt.WatermarkPath = path
	if _, err := r.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	last, err := loadWatermark(path)
	if err != nil || !last.Equal(old) {
		t.Fatalf("partial poll committed %v: %v", last, err)
	}
	if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Backfill(context.Background()); err == nil || len(gw.calls) != 1 {
		t.Fatal("corrupt checkpoint silently skipped")
	}
}
