package risk

import (
	"testing"
	"time"

	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/model"
)

func TestCorroboratedSequence(t *testing.T) {
	p := DefaultPatterns()[0]
	ssh := model.StageHit{At: t0.Add(time.Hour), ObsID: "ssh", Source: "linux"}
	h := stageHistory{model.StageSSHBruteForce: {ssh}, model.StageEdgeScan: {{At: t0, ObsID: "scan", Source: "linux"}}}
	if hits, _ := p.Match(h, ssh.At); len(hits) != 0 {
		t.Fatal("single source matched")
	}
	h[model.StageEdgeScan] = append(h[model.StageEdgeScan], model.StageHit{At: t0.Add(-time.Minute), ObsID: "other", Source: "edge"})
	hits, _ := p.Match(h, ssh.At)
	if len(hits) != 2 || hits[0].ObsID != "other" {
		t.Fatalf("wrong supporting evidence: %+v", hits)
	}
	for _, other := range []model.StageHit{{At: t0, ObsID: "ssh", Source: "edge"}, {At: ssh.At.Add(time.Second), ObsID: "different", Source: "edge"}} {
		h[model.StageEdgeScan] = []model.StageHit{other}
		if hits, _ := p.Match(h, ssh.At); len(hits) != 0 {
			t.Fatal("ambiguous or duplicate evidence matched")
		}
	}
}

func TestDifferentKnownTenantsDoNotCorroborate(t *testing.T) {
	p := DefaultPatterns()[2]
	h := stageHistory{
		model.StageSSHBruteForce: {{At: t0, ObsID: "a", ProviderTenant: "m365:a"}},
		model.StageSSHSuccess:    {{At: t0.Add(time.Second), ObsID: "b", ProviderTenant: "m365:b"}},
	}
	if hits, _ := p.Match(h, t0.Add(time.Second)); len(hits) != 0 {
		t.Fatal("conflicting tenant evidence was joined")
	}
}
