package risk

import (
	"sort"
	"time"

	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/model"
)

// Pattern is a multi-stage sequence on one pivot entity.
type Pattern struct {
	ID              string
	Title           string
	Pivots          []model.EntityType
	Stages          []model.Stage
	Required        []model.Stage // must be part of any match
	MinStages       int
	Ordered         bool
	Window          time.Duration
	Priority        string // complete match
	PartialPriority string // >= MinStages but not every stage
	Signal          string // B89 signal class of the resulting alert
}

// DefaultPatterns are the multi-stage detections the correlator ships with.
func DefaultPatterns() []Pattern {
	return []Pattern{
		{
			ID:              "edge-to-ssh",
			Title:           "Misma IP: bloqueo WAF de Cloudflare, escaneo del borde y fuerza bruta SSH",
			Pivots:          []model.EntityType{model.EntityIP},
			Stages:          []model.Stage{model.StageEdgeWAFBlock, model.StageEdgeScan, model.StageSSHBruteForce},
			Required:        []model.Stage{model.StageSSHBruteForce},
			MinStages:       2,
			Ordered:         true,
			Window:          24 * time.Hour,
			Priority:        "P2",
			PartialPriority: "P3",
			Signal:          "initial_access",
		},
		{
			ID:              "credential-to-privilege",
			Title:           "Fallos de credencial, acceso exitoso y cambio privilegiado del mismo usuario",
			Pivots:          []model.EntityType{model.EntityUser},
			Stages:          []model.Stage{model.StageAuthFailure, model.StageAuthSuccess, model.StagePrivilegedChange},
			MinStages:       3,
			Ordered:         true,
			Window:          24 * time.Hour,
			Priority:        "P1",
			PartialPriority: "P1",
			Signal:          "privilege_escalation",
		},
		{
			ID:              "ssh-bruteforce-then-access",
			Title:           "Fuerza bruta SSH seguida de acceso exitoso desde la misma IP",
			Pivots:          []model.EntityType{model.EntityIP},
			Stages:          []model.Stage{model.StageSSHBruteForce, model.StageSSHSuccess},
			MinStages:       2,
			Ordered:         true,
			Window:          6 * time.Hour,
			Priority:        "P1",
			PartialPriority: "P1",
			Signal:          "initial_access",
		},
		{
			ID:              "endpoint-protection-and-malware",
			Title:           "Protección del endpoint desactivada y malware en el mismo equipo",
			Pivots:          []model.EntityType{model.EntityHost},
			Stages:          []model.Stage{model.StageProtectionOff, model.StageEndpointMalware},
			MinStages:       2,
			Ordered:         false,
			Window:          72 * time.Hour,
			Priority:        "P1",
			PartialPriority: "P1",
			Signal:          "defense_evasion",
		},
		{
			ID:              "access-then-audit-tamper",
			Title:           "Acceso exitoso seguido de manipulación de la auditoría de AWS",
			Pivots:          []model.EntityType{model.EntityUser},
			Stages:          []model.Stage{model.StageAuthSuccess, model.StageCloudTamper},
			MinStages:       2,
			Ordered:         true,
			Window:          24 * time.Hour,
			Priority:        "P1",
			PartialPriority: "P1",
			Signal:          "defense_evasion",
		},
	}
}

func (p Pattern) pivots(t model.EntityType) bool {
	for _, v := range p.Pivots {
		if v == t {
			return true
		}
	}
	return false
}

func (p Pattern) uses(s model.Stage) bool {
	for _, v := range p.Stages {
		if v == s {
			return true
		}
	}
	return false
}

// stageHistory keeps recent hits per stage for one entity.
type stageHistory map[model.Stage][]model.StageHit

const maxHitsPerStage = 32

func (h stageHistory) add(hit model.StageHit, horizon time.Duration) {
	list := append(h[hit.Stage], hit)
	sort.SliceStable(list, func(i, j int) bool { return list[i].At.Before(list[j].At) })
	// Drop hits older than the longest pattern window relative to the newest one.
	newest := list[len(list)-1].At
	cut := 0
	for cut < len(list) && newest.Sub(list[cut].At) > horizon {
		cut++
	}
	list = list[cut:]
	if len(list) > maxHitsPerStage {
		list = list[len(list)-maxHitsPerStage:]
	}
	h[hit.Stage] = list
}

// Match evaluates a pattern at time `now` over the history. It returns the matched hits (one
// per stage, in stage order for ordered patterns) and whether every stage matched.
func (p Pattern) Match(h stageHistory, now time.Time) ([]model.StageHit, bool) {
	from := now.Add(-p.Window)
	inWindow := func(s model.Stage) []model.StageHit {
		out := []model.StageHit{}
		for _, hit := range h[s] {
			if !hit.At.Before(from) && !hit.At.After(now) {
				out = append(out, hit)
			}
		}
		return out
	}
	n := len(p.Stages)
	var best []model.StageHit
	for mask := 1; mask < 1<<n; mask++ {
		count := 0
		for i := 0; i < n; i++ {
			if mask&(1<<i) != 0 {
				count++
			}
		}
		if count < p.MinStages || count <= len(best) {
			continue
		}
		ok := true
		for _, req := range p.Required {
			found := false
			for i, s := range p.Stages {
				if s == req && mask&(1<<i) != 0 {
					found = true
				}
			}
			if !found {
				ok = false
			}
		}
		if !ok {
			continue
		}
		picked := []model.StageHit{}
		var prev time.Time
		for i := 0; i < n && ok; i++ {
			if mask&(1<<i) == 0 {
				continue
			}
			hits := inWindow(p.Stages[i])
			chosen := -1
			for j, hit := range hits {
				if !p.Ordered || prev.IsZero() || !hit.At.Before(prev) {
					chosen = j
					break
				}
			}
			if chosen < 0 {
				ok = false
				break
			}
			picked = append(picked, hits[chosen])
			if p.Ordered {
				prev = hits[chosen].At
			}
		}
		if ok {
			best = picked
		}
	}
	return best, len(best) == n
}
