package config

import "testing"

// The deploy compose sets these; Load must accept them or the correlator refuses to start.
func TestLoadAcceptsPatternAndMembershipVariables(t *testing.T) {
	t.Setenv("B89_CORRELATOR_PATTERNS_JSON", `[{"ID":"edge-to-ssh","Mode":"shadow"}]`)
	t.Setenv("B89_CORRELATOR_MEMBERS_DIR", t.TempDir())
	if _, err := Load(); err != nil {
		t.Fatalf("documented variables rejected: %v", err)
	}
	t.Setenv("B89_CORRELATOR_PATERNS_JSON", "[]")
	if _, err := Load(); err == nil {
		t.Fatal("typos must still be rejected")
	}
}
