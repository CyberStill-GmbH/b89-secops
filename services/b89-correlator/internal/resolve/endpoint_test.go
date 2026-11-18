package resolve

import "testing"

func TestTypedActorEndpoint(t *testing.T) {
	for raw, want := range map[string]string{"192.0.2.1:443": "192.0.2.1", "[2001:db8::1]:443": "2001:db8::1", "192.0.2.1:haha": "", "192.0.2.10": "192.0.2.10", "[192.0.2.1": "", "192.0.2.1/24": ""} {
		if got := NormalizeIP(stripPort(raw)); got != want {
			t.Errorf("%q = %q, want %q", raw, got, want)
		}
	}
}

func TestDeclaredTenantSession(t *testing.T) {
	r := New(nil, "")
	org := "00000000-0000-4000-8000-000000000001"
	sid := "00000000-0000-4000-8000-000000000002"
	obs, _ := r.Observe(doc("123", 8, []any{"office365"}, manager, map[string]any{"office365": map[string]any{"OrganizationId": org, "SessionId": sid}}))
	if obs.ProviderTenant != "m365:"+org || len(obs.SessionRef) != 64 {
		t.Fatalf("missing scoped session reference")
	}
	other, _ := r.Observe(doc("123", 8, []any{"office365"}, manager, map[string]any{"office365": map[string]any{"SessionId": sid}}))
	if other.ProviderTenant != "" || other.SessionRef != "" {
		t.Fatal("inferred scoped session from unscoped id")
	}
}
