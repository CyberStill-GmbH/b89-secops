package risk

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/model"
)

// ConfiguredPatterns applies an optional list of bounded policy overrides at startup.
func ConfiguredPatterns(raw string) ([]Pattern, error) {
	patterns := DefaultPatterns()
	if strings.TrimSpace(raw) == "" {
		return patterns, nil
	}
	var changes []struct {
		ID               string
		Window           string
		MinSources       *int
		MinStages        *int
		MinDistinctRules *int
		Mode             string
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&changes); err != nil || changes == nil {
		return nil, fmt.Errorf("invalid correlation pattern overrides")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("trailing correlation pattern settings")
	}
	byID := make(map[string]*Pattern, len(patterns))
	for i := range patterns {
		byID[patterns[i].ID] = &patterns[i]
	}
	for _, change := range changes {
		p := byID[change.ID]
		if p == nil {
			return nil, fmt.Errorf("unknown or repeated pattern %q", change.ID)
		}
		delete(byID, change.ID)
		if change.Window != "" {
			w, err := time.ParseDuration(change.Window)
			if err != nil || w < time.Second || w > 72*time.Hour {
				return nil, fmt.Errorf("invalid window for %s", change.ID)
			}
			p.Window = w
		}
		if change.MinSources != nil {
			if *change.MinSources < 1 || *change.MinSources > len(p.Stages) {
				return nil, fmt.Errorf("invalid source quorum for %s", change.ID)
			}
			p.MinSources = *change.MinSources
		}
		if change.MinStages != nil {
			// Required stages must still fit: a quorum below them could never match.
			if *change.MinStages < max(1, len(p.Required)) || *change.MinStages > len(p.Stages) {
				return nil, fmt.Errorf("invalid stage quorum for %s", change.ID)
			}
			p.MinStages = *change.MinStages
		}
		if change.MinDistinctRules != nil {
			if *change.MinDistinctRules < 0 || *change.MinDistinctRules > len(p.Stages) {
				return nil, fmt.Errorf("invalid rule diversity for %s", change.ID)
			}
			p.MinDistinctRules = *change.MinDistinctRules
		}
		switch change.Mode {
		case "":
		case model.ModeActive, model.ModeShadow:
			p.Mode = change.Mode
		default:
			return nil, fmt.Errorf("invalid mode for %s", change.ID)
		}
	}
	return patterns, nil
}

// Fingerprint ties an explanation to the effective rule and matching semantics.
func (p Pattern) Fingerprint() string {
	b, _ := json.Marshal(p)
	return fmt.Sprintf("sequence-v2-%x", sha256.Sum256(b))
}
