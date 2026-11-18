package risk

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/model"
)

// Run write and recover in separate containers with the same disposable named volume.
func TestVolumeReplacement(t *testing.T) {
	dir := os.Getenv("B89_TEST_RECOVERY_DIR")
	if dir == "" {
		t.Skip("requires a disposable volume and a separate recovery process")
	}
	e := newEngine()
	if err := e.EnableMemberLedger(dir); err != nil {
		t.Fatal(err)
	}
	const pivot = "host:volume-test"
	const emitted = "synthetic-volume-alert"
	switch os.Getenv("B89_TEST_RECOVERY_PHASE") {
	case "write":
		e.Process(obs("start", 0, "a", 9, "bitdefender", nil, []model.Stage{model.StageProtectionOff}, pivot))
		created := e.Process(obs("finish", time.Minute, "b", 9, "bitdefender", nil, []model.Stage{model.StageEndpointMalware}, pivot))
		var id string
		for _, c := range created {
			if c.PatternID == "endpoint-protection-and-malware" {
				id = c.ID
			}
		}
		if id == "" {
			t.Fatal("missing synthetic pattern")
		}
		var alerts []model.B89Alert
		for i := 0; i < 101; i++ {
			alerts = append(alerts, model.B89Alert{ID: fmt.Sprintf("linked-%03d", i), EntityKeys: []string{pivot}, OccurredAt: t0.Add(time.Minute)})
		}
		if err := e.AttachAlerts(alerts); err != nil {
			t.Fatal(err)
		}
		if err := e.FlushMembers(); err != nil {
			t.Fatal(err)
		}
		if err := e.RecordEmission(id, emitted); err != nil {
			t.Fatal(err)
		}
	case "recover":
		c, ok, err := e.CandidateByAlert(emitted)
		if err != nil || !ok || c.Status != model.CandidateEmitted || c.PatternID != "endpoint-protection-and-malware" {
			t.Fatalf("recover alert: found=%v err=%v status=%s", ok, err, c.Status)
		}
		offset := 0
		for offset < 101 {
			page, ok, err := e.MemberPage(c.ID, offset, 50)
			if err != nil || !ok || page.Total != 101 || len(page.Items) == 0 {
				t.Fatalf("recover linked alerts at offset %d: %+v %v", offset, page, err)
			}
			for _, item := range page.Items {
				if item != fmt.Sprintf("linked-%03d", offset) {
					t.Fatalf("unexpected member %q at %d", item, offset)
				}
				offset++
			}
		}
		page, ok, err := e.MemberPageByKind(c.ID, "observations", 0, 50)
		if err != nil || !ok || page.Total != 2 || len(page.Items) != 2 || page.Items[0] != "start" || page.Items[1] != "finish" {
			t.Fatalf("recover source observations: %+v %v", page, err)
		}
	default:
		t.Fatal("expected write or recover phase")
	}
}
