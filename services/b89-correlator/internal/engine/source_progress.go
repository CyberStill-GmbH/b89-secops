package engine

import (
	"fmt"
	"sort"
	"time"

	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/resolve"
)

// SourceProgress describes the Indexer read path per source. Reads include overlap and
// replay. The latest observed timestamp is not a provider acknowledgement of coverage:
// coverage comes only from collector heartbeats and the correlator's own read window.
type SourceProgress struct {
	Reads               uint64    `json:"readsIncludingReplay"`
	Processed           uint64    `json:"processed"`
	Duplicates          uint64    `json:"duplicates"`
	LateEvents          uint64    `json:"lateEvents"`
	LatestEvent         time.Time `json:"latestEvent"`
	LatestIngest        time.Time `json:"latestIngest"`
	LastRead            time.Time `json:"lastRead"`
	LastEventAgeSeconds float64   `json:"lastEventAgeSeconds"`
	// MaxIngestDelaySeconds is the largest (ingest - provider event time) seen since start.
	MaxIngestDelaySeconds float64 `json:"maxIngestDelaySeconds"`

	// Collector heartbeat (provider side). Absent when no heartbeat reached the correlator.
	HeartbeatAt        *time.Time `json:"heartbeatAt,omitempty"`
	HeartbeatOutcome   string     `json:"heartbeatOutcome,omitempty"`
	ProviderLagSeconds *float64   `json:"providerLagSeconds,omitempty"`
	ProviderWatermark  string     `json:"providerWatermark,omitempty"`

	// Coverage is complete, incomplete or unknown. "unknown" means no evidence of coverage
	// either way; it must never be presented as "no activity".
	Coverage       string `json:"coverage"`
	CoverageReason string `json:"coverageReason,omitempty"`
}

// Coverage policy for collector heartbeats.
const (
	maxProviderLag   = 15 * time.Minute
	maxHeartbeatAge  = time.Hour
	lateEventMinimum = 5 * time.Minute
)

var knownSources = map[string]bool{
	"m365": true, "aws": true, "cloudflare": true, "bitdefender": true, "linux-ssh": true, "windows": true,
	"web": true, "fim": true, "wazuh": true, "snyk": true, "sharepoint": true, "entra": true,
}

func sourceLabel(source string) string {
	if knownSources[source] {
		return source
	}
	return "other"
}

func (r *Runner) progressLocked(source string) SourceProgress {
	if r.sourceProgress == nil {
		r.sourceProgress = make(map[string]SourceProgress)
	}
	return r.sourceProgress[sourceLabel(source)]
}

// Called with r.mu held. Restrict labels because decoder and vendor are input data.
func (r *Runner) noteSourceRead(source string, eventAt, ingestAt, readAt time.Time, duplicate bool) {
	label := sourceLabel(source)
	progress := r.progressLocked(label)
	progress.Reads++
	if duplicate {
		progress.Duplicates++
	} else {
		progress.Processed++
	}
	progress.LastRead = readAt
	if eventAt.After(progress.LatestEvent) {
		progress.LatestEvent = eventAt
	}
	if ingestAt.After(progress.LatestIngest) {
		progress.LatestIngest = ingestAt
	}
	if delay := ingestAt.Sub(eventAt); !ingestAt.IsZero() && delay > 0 {
		if delay.Seconds() > progress.MaxIngestDelaySeconds {
			progress.MaxIngestDelaySeconds = delay.Seconds()
		}
		if delay >= lateEventMinimum {
			progress.LateEvents++
		}
	}
	r.sourceProgress[label] = progress
}

// Called with r.mu held.
func (r *Runner) noteHeartbeat(hb resolve.Heartbeat, readAt time.Time) {
	label := sourceLabel(hb.Vendor)
	progress := r.progressLocked(label)
	at := hb.FinishedAt
	if at.IsZero() {
		at = readAt
	}
	if progress.HeartbeatAt != nil && at.Before(*progress.HeartbeatAt) {
		return // replayed or out-of-order heartbeat
	}
	progress.HeartbeatAt = &at
	progress.HeartbeatOutcome = hb.Outcome
	progress.ProviderLagSeconds = hb.LagSeconds
	if hb.Position != "" {
		progress.ProviderWatermark = hb.Position
	}
	r.sourceProgress[label] = progress
}

// coverageLocked derives each source's coverage state at `at`. The correlator's own read
// window bounds every source: while it is catching up or failing, coverage is incomplete.
func (r *Runner) coverageLocked(at time.Time) map[string]SourceProgress {
	out := make(map[string]SourceProgress, len(r.sourceProgress))
	correlatorBehind, behindReason := false, ""
	switch {
	case !r.backfilled:
		correlatorBehind, behindReason = true, "correlator_backfilling"
	case r.lastPollErr != "":
		correlatorBehind, behindReason = true, "correlator_read_failed"
	case r.pendingPoll != nil:
		correlatorBehind, behindReason = true, "correlator_catching_up"
	}
	for source, p := range r.sourceProgress {
		p.LastEventAgeSeconds = 0
		if !p.LatestEvent.IsZero() && at.After(p.LatestEvent) {
			p.LastEventAgeSeconds = at.Sub(p.LatestEvent).Seconds()
		}
		p.Coverage, p.CoverageReason = "unknown", "no_collector_heartbeat"
		if p.HeartbeatAt != nil {
			switch {
			case p.HeartbeatOutcome != "" && p.HeartbeatOutcome != "ok":
				p.Coverage, p.CoverageReason = "incomplete", "collector_run_"+p.HeartbeatOutcome
			case at.Sub(*p.HeartbeatAt) > maxHeartbeatAge:
				p.Coverage, p.CoverageReason = "incomplete", "collector_heartbeat_stale"
			case p.ProviderLagSeconds != nil && *p.ProviderLagSeconds > maxProviderLag.Seconds():
				p.Coverage, p.CoverageReason = "incomplete", "collector_behind_provider"
			default:
				p.Coverage, p.CoverageReason = "complete", ""
			}
		}
		if correlatorBehind {
			p.Coverage, p.CoverageReason = "incomplete", behindReason
		}
		out[source] = p
	}
	return out
}

// coverageGaps is the engine's CoverageFunc: it states, in analyst language, which sources
// of a candidate lacked complete coverage. Unknown coverage is reported as unverified.
func (r *Runner) coverageGaps(sources []string, from, to time.Time) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	coverage := r.coverageLocked(r.Now().UTC())
	gaps := []string{}
	for _, source := range sources {
		p, ok := coverage[sourceLabel(source)]
		switch {
		case !ok:
			gaps = append(gaps, fmt.Sprintf("Cobertura de %s no verificada: sin lecturas registradas.", source))
		case p.Coverage == "incomplete":
			gaps = append(gaps, fmt.Sprintf("Cobertura incompleta de %s (%s): pueden faltar eventos entre %s y %s.", source, p.CoverageReason,
				from.UTC().Format("2006-01-02 15:04Z"), to.UTC().Format("2006-01-02 15:04Z")))
		case p.Coverage == "unknown":
			gaps = append(gaps, fmt.Sprintf("Cobertura de %s no verificada: no llegó latido del colector al correlador.", source))
		}
	}
	sort.Strings(gaps)
	return gaps
}
