// Package engine wires the correlator: it reads Wazuh alerts through the B89 wazuh-gateway,
// the B89 alert/verdict feed through the API's internal endpoints, runs the risk engine and
// the feedback loop, and emits candidates and audit records back through the API.
package engine

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/feedback"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/model"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/resolve"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/risk"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/sources"
)

// Gateway is the read path to wazuh-alerts-*.
type Gateway interface {
	Page(ctx context.Context, from, to time.Time, after *sources.Cursor) ([]map[string]any, *sources.Cursor, error)
	Health(ctx context.Context) error
}

// API is the B89 API internal surface.
type API interface {
	Alerts(ctx context.Context, since time.Time) ([]model.B89Alert, bool, error)
	CreateCandidate(ctx context.Context, req sources.CandidateRequest) (sources.CandidateResponse, error)
	Audit(ctx context.Context, req sources.AuditRequest) (bool, error)
}

// Options are the runner tunables (a subset of config.Config, decoupled for tests).
type Options struct {
	Backfill         time.Duration
	PollInterval     time.Duration
	FeedbackInterval time.Duration
	Lag              time.Duration
	Overlap          time.Duration
	Emit             bool
	EmitMaxAge       time.Duration
	EmitMaxPerHour   int
	Audit            bool // record feedback decisions in the B89 audit chain
	FeedbackLookback time.Duration
	Feedback         feedback.Policy
	MaxPagesPerPoll  int
}

// Counters are monotonic metrics.
type Counters struct {
	GatewayErrors  atomic.Int64
	APIErrors      atomic.Int64
	Emitted        atomic.Int64
	EmitErrors     atomic.Int64
	EmitSkipped    atomic.Int64
	AuditRecorded  atomic.Int64
	Polls          atomic.Int64
	Pages          atomic.Int64
	Unparseable    atomic.Int64
}

// Runner owns the loops and the derived views.
type Runner struct {
	Opt      Options
	Eng      *risk.Engine
	Res      *resolve.Resolver
	Gateway  Gateway
	API      API
	Log      *slog.Logger
	Now      func() time.Time
	C        Counters

	mu           sync.RWMutex
	fb           feedback.Result
	alerts       []model.B89Alert
	truncated    bool
	dedup        risk.DedupResult
	lastTo       time.Time
	cursorAt     time.Time
	ready        bool
	backfilled   bool
	lastPoll     time.Time
	lastFeedback time.Time
	lastPollErr  string
	audited      map[string]bool
	emitTimes    []time.Time
}

// New builds a runner.
func New(opt Options, eng *risk.Engine, res *resolve.Resolver, gw Gateway, api API, log *slog.Logger) *Runner {
	if opt.MaxPagesPerPoll <= 0 {
		opt.MaxPagesPerPoll = 200
	}
	return &Runner{Opt: opt, Eng: eng, Res: res, Gateway: gw, API: api, Log: log, Now: time.Now, audited: map[string]bool{}}
}

// Readiness describes whether the initial backfill completed and upstream data remains fresh.
// A failed poll degrades readiness immediately. Otherwise, polling older than three
// configured intervals (at least 30 seconds) is considered stale.
type Readiness struct {
	Ready       bool      `json:"ready"`
	Status      string    `json:"status"`
	Reason      string    `json:"reason,omitempty"`
	LastPoll    time.Time `json:"lastPoll,omitempty"`
	PollAgeSecs float64   `json:"pollAgeSeconds,omitempty"`
}

func (r *Runner) Readiness(at time.Time) Readiness {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.readinessLocked(at)
}

func (r *Runner) readinessLocked(at time.Time) Readiness {
	state := Readiness{Status: "backfilling", Reason: "initial_backfill_incomplete"}
	if !r.backfilled || !r.ready {
		if r.lastPollErr != "" {
			state.Status, state.Reason = "degraded", "upstream_backfill_failed"
		}
		return state
	}
	state.LastPoll = r.lastPoll
	if r.lastPoll.IsZero() {
		state.Status, state.Reason = "degraded", "upstream_poll_not_succeeded"
		return state
	}
	age := at.Sub(r.lastPoll)
	if age < 0 {
		age = 0
	}
	state.PollAgeSecs = age.Seconds()
	if r.lastPollErr != "" {
		state.Status, state.Reason = "degraded", "upstream_poll_failed"
		return state
	}
	staleAfter := time.Duration(1<<63 - 1)
	if r.Opt.PollInterval <= staleAfter/3 {
		staleAfter = 3 * r.Opt.PollInterval
	}
	if staleAfter < 30*time.Second {
		staleAfter = 30 * time.Second
	}
	if age > staleAfter {
		state.Status, state.Reason = "degraded", "upstream_poll_stale"
		return state
	}
	state.Ready, state.Status, state.Reason = true, "ready", ""
	return state
}

// Ready reports whether backfill completed and upstream polling remains healthy.
func (r *Runner) Ready() bool { return r.Readiness(r.Now().UTC()).Ready }

// ingest reads [from,to) page by page and processes it; returns the new candidates.
func (r *Runner) ingest(ctx context.Context, from, to time.Time, maxPages int) ([]*model.Candidate, error) {
	var cursor *sources.Cursor
	created := []*model.Candidate{}
	for page := 0; maxPages <= 0 || page < maxPages; page++ {
		docs, next, err := r.Gateway.Page(ctx, from, to, cursor)
		if err != nil {
			r.C.GatewayErrors.Add(1)
			return created, err
		}
		r.C.Pages.Add(1)
		for _, d := range docs {
			obs, ok := r.Res.Observe(d)
			if !ok {
				r.C.Unparseable.Add(1)
				continue
			}
			created = append(created, r.Eng.Process(obs)...)
			r.mu.Lock()
			if obs.Time.After(r.cursorAt) {
				r.cursorAt = obs.Time
			}
			r.mu.Unlock()
		}
		if next == nil {
			return created, nil
		}
		cursor = next
	}
	return created, errors.New("page limit reached")
}

// Backfill rebuilds state over the look-back window (no emission of stale candidates).
func (r *Runner) Backfill(ctx context.Context) ([]*model.Candidate, error) {
	now := r.Now().UTC()
	to := now.Add(-r.Opt.Lag)
	from := to.Add(-r.Opt.Backfill)
	// Feedback first so that historical suppressions apply in time order.
	if err := r.RefreshFeedback(ctx); err != nil {
		r.Log.Warn("feedback.unavailable_at_start", "error", errText(err))
	}
	start := time.Now()
	// Day-sized slices keep each search bounded.
	created := []*model.Candidate{}
	for sliceFrom := from; sliceFrom.Before(to); sliceFrom = sliceFrom.Add(24 * time.Hour) {
		sliceTo := sliceFrom.Add(24 * time.Hour)
		if sliceTo.After(to) {
			sliceTo = to
		}
		c, err := r.ingest(ctx, sliceFrom, sliceTo, 0)
		created = append(created, c...)
		if err != nil {
			r.mu.Lock()
			r.lastPollErr = "upstream_backfill_failed"
			r.mu.Unlock()
			return created, err
		}
	}
	r.mu.Lock()
	r.lastTo, r.backfilled, r.ready = to, true, true
	r.lastPoll, r.lastPollErr = r.Now().UTC(), ""
	r.mu.Unlock()
	r.attachAlerts()
	r.Log.Info("backfill.completed", "from", from, "to", to, "observations", r.Eng.Observations,
		"candidates", len(created), "duration_ms", time.Since(start).Milliseconds())
	return created, nil
}

// Poll reads new alerts since the last window (with overlap; ids dedupe).
func (r *Runner) Poll(ctx context.Context) ([]*model.Candidate, error) {
	r.mu.RLock()
	from := r.lastTo.Add(-r.Opt.Overlap)
	r.mu.RUnlock()
	to := r.Now().UTC().Add(-r.Opt.Lag)
	if !to.After(from) {
		return nil, nil
	}
	r.C.Polls.Add(1)
	created, err := r.ingest(ctx, from, to, r.Opt.MaxPagesPerPoll)
	if err != nil {
		r.mu.Lock()
		r.lastPollErr = "upstream_poll_failed"
		r.mu.Unlock()
		return created, err
	}
	r.mu.Lock()
	r.lastTo, r.lastPoll, r.lastPollErr = to, r.Now().UTC(), ""
	r.mu.Unlock()
	return created, nil
}

// RefreshFeedback pulls the B89 alert feed, recomputes suppressions/proposals and dedup.
func (r *Runner) RefreshFeedback(ctx context.Context) error {
	now := r.Now().UTC()
	alerts, truncated, err := r.API.Alerts(ctx, now.Add(-r.Opt.FeedbackLookback))
	if err != nil {
		r.C.APIErrors.Add(1)
		return err
	}
	fb := feedback.Evaluate(alerts, r.Res.Canonical, r.Opt.Feedback, now)
	r.Eng.SetSuppressor(fb)
	since := now.Add(-r.Opt.Backfill)
	recent := make([]model.B89Alert, 0, len(alerts))
	for _, a := range alerts {
		if !a.OccurredAt.Before(since) && !strings.HasPrefix(a.RuleID, risk.CorrelatorRulePrefix) {
			recent = append(recent, a)
		}
	}
	dedup := risk.DedupAlerts(recent, r.Res.Canonical, r.Eng.P.GroupGap, r.Eng.P.GroupMaxSpan)
	r.mu.Lock()
	r.fb, r.alerts, r.truncated, r.dedup, r.lastFeedback = fb, alerts, truncated, dedup, now
	r.mu.Unlock()
	r.attachAlerts()
	return nil
}

func (r *Runner) attachAlerts() {
	r.mu.RLock()
	alerts := r.alerts
	r.mu.RUnlock()
	if len(alerts) > 0 {
		r.Eng.AttachAlerts(alerts)
	}
}

// AuditFeedback records feedback decisions (idempotent on the API side).
func (r *Runner) AuditFeedback(ctx context.Context) {
	if !r.Opt.Audit {
		return
	}
	r.mu.RLock()
	props := append([]feedback.Proposal(nil), r.fb.Proposals...)
	r.mu.RUnlock()
	for _, p := range props {
		actions := []string{"risk.feedback.proposed"}
		switch p.Suppression {
		case feedback.SuppressionActive:
			actions = append(actions, "risk.suppression.applied")
		case feedback.SuppressionExpired:
			actions = append(actions, "risk.suppression.applied", "risk.suppression.expired")
		}
		for _, action := range actions {
			mark := action + "|" + p.ID
			r.mu.RLock()
			done := r.audited[mark]
			r.mu.RUnlock()
			if done {
				continue
			}
			req := sources.AuditRequest{
				Action: action, ResourceID: p.ID, Outcome: "succeeded", Reason: p.Reason, RuleID: p.RuleID,
				Metadata: map[string]any{
					"kind": p.Kind, "falsePositives": p.FalsePos, "truePositives": p.TruePos,
					"ratio": p.Ratio, "protected": p.Protected, "thresholdAt": p.ThresholdAt.UTC().Format(time.RFC3339),
					"evidenceAlerts": len(p.EvidenceIDs),
				},
			}
			if p.EntityKey != "*" {
				req.EntityKey = p.EntityKey
			}
			if !p.ExpiresAt.IsZero() {
				req.Metadata["expiresAt"] = p.ExpiresAt.UTC().Format(time.RFC3339)
			}
			recorded, err := r.API.Audit(ctx, req)
			if err != nil {
				r.C.APIErrors.Add(1)
				r.Log.Warn("audit.failed", "action", action, "resource", p.ID, "error", errText(err))
				continue
			}
			if recorded {
				r.C.AuditRecorded.Add(1)
			}
			r.mu.Lock()
			r.audited[mark] = true
			r.mu.Unlock()
		}
	}
}

// Emit materializes eligible candidates as B89 alerts through the API.
func (r *Runner) Emit(ctx context.Context, cands []*model.Candidate) {
	now := r.Now().UTC()
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].LastSeen.Before(cands[j].LastSeen) })
	for _, c := range cands {
		snap, ok := r.Eng.Candidate(c.ID)
		if !ok || snap.Status != model.CandidateProposed && snap.Status != model.CandidateFailed {
			continue
		}
		cur := &snap
		if !r.Opt.Emit {
			continue
		}
		if now.Sub(cur.LastSeen) > r.Opt.EmitMaxAge {
			r.C.EmitSkipped.Add(1)
			r.Eng.UpdateCandidate(c.ID, func(x *model.Candidate) { x.StatusDetail = "stale: not emitted (older than emit max age)" })
			continue
		}
		if !r.takeEmitSlot(now) {
			r.C.EmitSkipped.Add(1)
			r.Eng.UpdateCandidate(c.ID, func(x *model.Candidate) { x.StatusDetail = "rate limited: will retry" })
			continue
		}
		keys := []string{cur.Entity.Key()}
		for _, k := range cur.RelatedKeys {
			if len(keys) >= 8 {
				break
			}
			if strings.HasPrefix(k, "user:") || strings.HasPrefix(k, "ip:") || strings.HasPrefix(k, "host:") || strings.HasPrefix(k, "cloud:") {
				keys = append(keys, k)
			}
		}
		resp, err := r.API.CreateCandidate(ctx, sources.CandidateRequest{
			IdempotencyKey: cur.IdempotencyKey, PatternID: cur.PatternID, Kind: cur.Kind,
			Title: cur.Title, Summary: cur.Summary, Priority: cur.Priority, Score: cur.Score,
			RiskScore: cur.RiskScore, Signal: cur.Signal, PrimaryEntityKey: cur.Entity.Key(),
			EntityKeys: keys, RelatedAlertIDs: cur.B89AlertIDs, OccurredAt: cur.LastSeen,
			FirstSeen: cur.FirstSeen, MemberCount: cur.MemberCount, Stages: cur.Stages,
			Sources: cur.Sources, Tactics: cur.Tactics,
		})
		if err != nil {
			r.C.EmitErrors.Add(1)
			r.Log.Warn("candidate.emit_failed", "candidate", c.ID, "error", errText(err))
			r.Eng.UpdateCandidate(c.ID, func(x *model.Candidate) { x.Status, x.StatusDetail = model.CandidateFailed, errText(err) })
			continue
		}
		r.C.Emitted.Add(1)
		r.Log.Info("candidate.emitted", "candidate", c.ID, "alert", resp.AlertID, "created", resp.Created, "priority", cur.Priority, "pattern", cur.PatternID)
		r.Eng.UpdateCandidate(c.ID, func(x *model.Candidate) {
			x.Status, x.AlertID, x.StatusDetail = model.CandidateEmitted, resp.AlertID, ""
		})
	}
}

func (r *Runner) takeEmitSlot(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Opt.EmitMaxPerHour <= 0 {
		return false
	}
	kept := r.emitTimes[:0]
	for _, t := range r.emitTimes {
		if now.Sub(t) < time.Hour {
			kept = append(kept, t)
		}
	}
	r.emitTimes = kept
	if len(r.emitTimes) >= r.Opt.EmitMaxPerHour {
		return false
	}
	r.emitTimes = append(r.emitTimes, now)
	return true
}

// Run executes backfill and the loops until ctx is cancelled.
func (r *Runner) Run(ctx context.Context) {
	for {
		created, err := r.Backfill(ctx)
		if err == nil {
			r.Emit(ctx, created)
			r.AuditFeedback(ctx)
			break
		}
		r.Log.Error("backfill.failed", "error", errText(err))
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
	poll := time.NewTicker(r.Opt.PollInterval)
	fbTick := time.NewTicker(r.Opt.FeedbackInterval)
	prune := time.NewTicker(10 * time.Minute)
	defer poll.Stop()
	defer fbTick.Stop()
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			created, err := r.Poll(ctx)
			if err != nil {
				r.Log.Warn("poll.failed", "error", errText(err))
			}
			r.attachAlerts()
			r.Emit(ctx, append(created, r.retryable()...))
		case <-fbTick.C:
			if err := r.RefreshFeedback(ctx); err != nil {
				r.Log.Warn("feedback.failed", "error", errText(err))
				continue
			}
			r.AuditFeedback(ctx)
		case <-prune.C:
			r.Eng.Prune(r.Now().UTC())
		}
	}
}

// retryable returns failed/rate-limited candidates still young enough to emit.
func (r *Runner) retryable() []*model.Candidate {
	if !r.Opt.Emit {
		return nil
	}
	now := r.Now().UTC()
	out := []*model.Candidate{}
	for _, c := range r.Eng.Candidates("", 200) {
		if (c.Status == model.CandidateFailed || (c.Status == model.CandidateProposed && c.StatusDetail != "")) && now.Sub(c.LastSeen) <= r.Opt.EmitMaxAge {
			cp := c
			out = append(out, &cp)
		}
	}
	return out
}

// Snapshot is the read model served by the HTTP layer and the replay report.
type Snapshot struct {
	Ready          bool
	Backfilled     bool
	LastTo         time.Time
	CursorAt       time.Time
	LastPoll       time.Time
	LastFeedback   time.Time
	Feedback       feedback.Result
	Dedup          risk.DedupResult
	AlertsTotal    int
	AlertsTrunc    bool
}

// Snapshot copies the runner's derived state.
func (r *Runner) Snapshot() Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return Snapshot{
		Ready: r.readinessLocked(r.Now().UTC()).Ready, Backfilled: r.backfilled, LastTo: r.lastTo, CursorAt: r.cursorAt,
		LastPoll: r.lastPoll, LastFeedback: r.lastFeedback, Feedback: r.fb, Dedup: r.dedup,
		AlertsTotal: len(r.alerts), AlertsTrunc: r.truncated,
	}
}

// Alerts returns the last B89 feed (for the replay report).
func (r *Runner) Alerts() []model.B89Alert {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]model.B89Alert(nil), r.alerts...)
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
