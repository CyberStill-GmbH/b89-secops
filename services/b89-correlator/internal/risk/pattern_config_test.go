package risk

import (
	"testing"
	"time"
)

func TestConfiguredPatterns(t *testing.T) {
	base := DefaultPatterns()[0]
	ps, err := ConfiguredPatterns(`[{"id":"edge-to-ssh","window":"4h","minSources":3}]`)
	if err != nil || ps[0].Window != 4*time.Hour || ps[0].MinSources != 3 || base.Fingerprint() == ps[0].Fingerprint() {
		t.Fatalf("invalid effective policy: %v", err)
	}
	for _, invalid := range []string{`null`, `[{"id":"no-rule"}]`, `[{"id":"edge-to-ssh","window":"90h"}]`, `[{"id":"edge-to-ssh","minSources":4}]`, `[{"id":"edge-to-ssh","typo":2}]`, `[{"id":"edge-to-ssh"},{"id":"edge-to-ssh"}]`, `[] {}`} {
		if _, err := ConfiguredPatterns(invalid); err == nil {
			t.Errorf("accepted %s", invalid)
		}
	}
}
