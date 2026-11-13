package engine

import (
	"context"
	"testing"
	"time"

	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/feedback"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/model"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/resolve"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/risk"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/sources"
)

type feedbackTestAPI struct {
	alerts    []model.B89Alert
	truncated bool
	since     time.Time
}

func (a *feedbackTestAPI) Alerts(_ context.Context, since time.Time) ([]model.B89Alert, bool, error) {
	a.since = since
	return a.alerts, a.truncated, nil
}

func (*feedbackTestAPI) CreateCandidate(context.Context, sources.CandidateRequest) (sources.CandidateResponse, error) {
	return sources.CandidateResponse{}, nil
}

func (*feedbackTestAPI) Audit(context.Context, sources.AuditRequest) (bool, error) {
	return false, nil
}

func TestRefreshFeedbackKeepsMetricsButDisablesSuppressionsForTruncatedFeed(t *testing.T) {
	now := time.Date(2026, time.November, 11, 12, 0, 0, 0, time.UTC)
	alerts := make([]model.B89Alert, 0, 3)
	for index := 0; index < 3; index++ {
		at := now.Add(-time.Duration(index+1) * time.Hour)
		alerts = append(alerts, model.B89Alert{
			ID:         []string{"fp-a", "fp-b", "fp-c"}[index],
			RuleID:     "101501",
			Priority:   "P3",
			Verdict:    "false_positive",
			EntityKeys: []string{"ip:192.0.2.200"},
			OccurredAt: at,
			UpdatedAt:  at.Add(10 * time.Minute),
		})
	}
	policy := feedback.DefaultPolicy()
	policy.AutoSuppress = true
	resolver := resolve.New(nil, "")
	engine := risk.NewEngine(risk.DefaultPolicy(), risk.DefaultPatterns(), resolver, nil, 7)
	api := &feedbackTestAPI{alerts: alerts}
	runner := New(Options{Feedback: policy}, engine, resolver, nil, api, nil)
	runner.Now = func() time.Time { return now }

	if err := runner.RefreshFeedback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := runner.Snapshot().Feedback.ActiveCount(now); got != 1 {
		t.Fatalf("complete feed should apply the configured suppression, got %d", got)
	}
	api.truncated = true
	if err := runner.RefreshFeedback(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot := runner.Snapshot()
	proposal := findProposal(snapshot.Feedback.Proposals, "101501")
	if proposal == nil || proposal.Suppression != feedback.SuppressionProposed {
		t.Fatalf("expected the incomplete evidence to remain a reviewable proposal: %+v", snapshot.Feedback.Proposals)
	}
	if snapshot.Feedback.FalsePos != 3 || snapshot.Feedback.Verdicts != 3 {
		t.Fatalf("observed feedback metrics were lost: %+v", snapshot.Feedback)
	}
	if !snapshot.AlertsTrunc {
		t.Fatal("snapshot must retain the incomplete-feed indicator")
	}
	if snapshot.Feedback.ReviewCoverage != nil || snapshot.Feedback.ReviewCoverageStatus != feedback.ReviewCoverageIncomplete {
		t.Fatalf("truncated denominator must not publish review coverage: %+v", snapshot.Feedback)
	}
	if snapshot.Feedback.Suppressed("101501", "ip:192.0.2.200", now) || snapshot.Feedback.ActiveCount(now) != 0 {
		t.Fatal("truncated feedback must not apply or renew automatic suppressions")
	}
}

func TestRefreshFeedbackReportsTheEffectiveFeedWindow(t *testing.T) {
	now := time.Date(2026, time.November, 11, 12, 0, 0, 0, time.UTC)
	lookback := 29 * 24 * time.Hour
	policy := feedback.DefaultPolicy()
	api := &feedbackTestAPI{alerts: []model.B89Alert{{
		ID: "correlator-alert", RuleID: model.CorrelatorRulePrefix + "edge-to-ssh",
		Verdict: "true_positive", OccurredAt: now.Add(-28 * 24 * time.Hour),
	}}}
	resolver := resolve.New(nil, "")
	engine := risk.NewEngine(risk.DefaultPolicy(), risk.DefaultPatterns(), resolver, nil, 7)
	runner := New(Options{Feedback: policy, FeedbackLookback: lookback}, engine, resolver, nil, api, nil)
	runner.Now = func() time.Time { return now }

	if err := runner.RefreshFeedback(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := runner.Snapshot().Feedback
	if !api.since.Equal(now.Add(-lookback)) || got.WindowSeconds != int64(lookback.Seconds()) {
		t.Fatalf("reported feedback window must match fetched feed: since=%s feedback=%+v", api.since, got)
	}
}

func findProposal(proposals []feedback.Proposal, ruleID string) *feedback.Proposal {
	for index := range proposals {
		if proposals[index].RuleID == ruleID && proposals[index].Kind == feedback.KindAllowlist {
			return &proposals[index]
		}
	}
	return nil
}
