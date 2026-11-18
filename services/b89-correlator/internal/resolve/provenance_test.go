package resolve

import (
	"testing"
	"time"

	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/model"
)

func observe(t *testing.T, r *Resolver, doc Doc) model.Observation {
	t.Helper()
	o, ok := r.Observe(doc)
	if !ok {
		t.Fatal("document not observed")
	}
	return o
}

func TestProvenanceRecordsFieldMethodAndConfidence(t *testing.T) {
	r := New(map[string]string{"svc-deploy": "deploy@b89.io"}, "corp.b89.io")
	cases := []struct {
		user       string
		key        string
		method     string
		confidence model.Confidence
	}{
		{"Ana@B89.io", "user:ana@b89.io", "exact", model.ConfidenceHigh},
		{"svc-deploy", "user:deploy@b89.io", "alias", model.ConfidenceHigh},
		{`CORP\jdoe`, "user:jdoe@corp.b89.io", "domain_default", model.ConfidenceMedium},
		{"jdoe", "user:jdoe", "bare_name", model.ConfidenceLow},
	}
	for _, c := range cases {
		o := observe(t, r, Doc{
			"timestamp": "2026-11-17T10:00:00Z", "id": c.user,
			"rule": map[string]any{"id": "60106", "level": float64(5), "groups": []any{"windows"}},
			"data": map[string]any{"win": map[string]any{"eventdata": map[string]any{"targetUserName": c.user}}},
		})
		pv, ok := o.Provenance[c.key]
		if !ok || pv.Method != c.method || pv.Confidence != c.confidence || pv.Field != "data.win.eventdata.targetUserName" {
			t.Fatalf("%s: provenance %+v (entities %v)", c.user, pv, o.Entities)
		}
	}
}

func TestTruncatedHostNamesAreNotExactIdentities(t *testing.T) {
	r := New(nil, "")
	a := observe(t, r, Doc{"timestamp": "2026-11-17T10:00:00Z", "id": "a", "rule": map[string]any{"id": "1", "level": float64(5)},
		"agent": map[string]any{"id": "001", "name": "web.prod.example.com"}})
	b := observe(t, r, Doc{"timestamp": "2026-11-17T10:00:00Z", "id": "b", "rule": map[string]any{"id": "1", "level": float64(5)},
		"agent": map[string]any{"id": "002", "name": "web.dev.example.com"}})
	// Both collapse to host:web; the attribution must say so instead of claiming exactness.
	for _, o := range []model.Observation{a, b} {
		if pv := o.Provenance["host:web"]; pv.Method != "first_label" || pv.Confidence != model.ConfidenceMedium {
			t.Fatalf("FQDN truncation must be medium confidence: %+v", pv)
		}
	}
	c := observe(t, r, Doc{"timestamp": "2026-11-17T10:00:00Z", "id": "c", "rule": map[string]any{"id": "1", "level": float64(5)},
		"agent": map[string]any{"id": "003", "name": "db01"}})
	if pv := c.Provenance["host:db01"]; pv.Method != "exact" || pv.Confidence != model.ConfidenceHigh {
		t.Fatalf("short agent name is exact: %+v", pv)
	}
}

func TestSimilarUserNamesAndSuffixesStaySeparate(t *testing.T) {
	r := New(nil, "")
	keys := map[string]bool{}
	for i, u := range []string{"ana@b89.io", "ana@b89.io.attacker.example", "ana.b89@b89.io", "xana@b89.io"} {
		o := observe(t, r, Doc{"timestamp": "2026-11-17T10:00:00Z", "id": string(rune('a' + i)),
			"rule": map[string]any{"id": "91545", "level": float64(3), "groups": []any{"office365"}},
			"data": map[string]any{"office365": map[string]any{"UserId": u}}})
		for _, e := range o.Entities {
			if e.Type == model.EntityUser {
				keys[e.Key()] = true
			}
		}
	}
	if len(keys) != 4 {
		t.Fatalf("text similarity must never merge identities: %v", keys)
	}
}

func TestProviderEventTimeAndIngestTime(t *testing.T) {
	r := New(nil, "")
	o := observe(t, r, Doc{"timestamp": "2026-11-17T10:30:00Z", "id": "late",
		"rule": map[string]any{"id": "91545", "level": float64(3), "groups": []any{"office365"}},
		"data": map[string]any{"office365": map[string]any{"CreationTime": "2026-11-17T09:00:00", "Operation": "UserLoggedIn", "UserId": "ana@b89.io"}}})
	if o.TimeSource != "provider" || !o.Time.Equal(time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)) || !o.IngestedAt.Equal(time.Date(2026, 11, 17, 10, 30, 0, 0, time.UTC)) {
		t.Fatalf("event %v (%s) ingest %v", o.Time, o.TimeSource, o.IngestedAt)
	}
	future := observe(t, r, Doc{"timestamp": "2026-11-17T10:30:00Z", "id": "future",
		"rule": map[string]any{"id": "91545", "level": float64(3)},
		"data": map[string]any{"office365": map[string]any{"CreationTime": "2026-11-17T12:00:00"}}})
	if future.TimeSource != "ingest" || !future.Time.Equal(future.IngestedAt) {
		t.Fatal("a provider clock ahead of ingestion is not trusted")
	}
}

func TestIdentityChangeAndEndpointActivityStages(t *testing.T) {
	r := New(nil, "")
	change := observe(t, r, Doc{"timestamp": "2026-11-17T10:00:00Z", "id": "mfa",
		"rule": map[string]any{"id": "91600", "level": float64(8), "groups": []any{"office365"}},
		"data": map[string]any{"office365": map[string]any{"Operation": "User registered security info", "UserId": "ana@b89.io"}}})
	if change.StageCriteria[model.StageIdentityChange] != "data.office365.Operation=User registered security info" {
		t.Fatalf("identity change criteria: %v", change.StageCriteria)
	}
	logon := observe(t, r, Doc{"timestamp": "2026-11-17T10:00:00Z", "id": "logon",
		"rule":  map[string]any{"id": "60106", "level": float64(5), "groups": []any{"windows", "authentication_success"}},
		"agent": map[string]any{"id": "004", "name": "ws-ana"},
		"data":  map[string]any{"win": map[string]any{"eventdata": map[string]any{"targetUserName": "ana@b89.io"}}}})
	if _, ok := logon.StageCriteria[model.StageEndpointActivity]; !ok {
		t.Fatalf("user+host on an endpoint source is endpoint activity: %v", logon.Stages)
	}
	failed := observe(t, r, Doc{"timestamp": "2026-11-17T10:00:00Z", "id": "fail",
		"rule":  map[string]any{"id": "60122", "level": float64(5), "groups": []any{"windows", "authentication_failed"}},
		"agent": map[string]any{"id": "004", "name": "ws-ana"},
		"data":  map[string]any{"win": map[string]any{"eventdata": map[string]any{"targetUserName": "ana@b89.io"}}}})
	if _, ok := failed.StageCriteria[model.StageEndpointActivity]; ok {
		t.Fatal("a failed logon is an attempt, not account activity")
	}
}

func TestCollectorHeartbeatIsCoverageNotObservation(t *testing.T) {
	doc := Doc{"timestamp": "2026-11-17T10:00:00Z", "id": "hb", "rule": map[string]any{"id": "100900", "level": float64(3)},
		"data": map[string]any{"b89": map[string]any{"vendor": "m365", "event_type": "source_heartbeat",
			"heartbeat": map[string]any{"outcome": "ok", "finished_at": "2026-11-17T09:59:00Z", "provider_lag_seconds": float64(1200),
				"cursor_position": "2026-11-17T09:39:00Z", "cursor_advanced": true, "items_fetched": float64(10)}}}}
	hb, ok := ParseHeartbeat(doc)
	if !ok || hb.Vendor != "m365" || hb.LagSeconds == nil || *hb.LagSeconds != 1200 || hb.Position != "2026-11-17T09:39:00Z" {
		t.Fatalf("heartbeat %+v", hb)
	}
	if _, ok := ParseHeartbeat(Doc{"data": map[string]any{"b89": map[string]any{"vendor": "m365"}}}); ok {
		t.Fatal("ordinary provider events are not heartbeats")
	}
}
