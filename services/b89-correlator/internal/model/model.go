// Package model holds the value types shared by the correlator: resolved entities, the
// observations derived from Wazuh alerts, B89 alerts with analyst verdicts and the
// correlated candidates the engine proposes.
package model

import (
	"strings"
	"time"
)

// EntityType is the closed set of entity kinds the correlator scores.
type EntityType string

const (
	EntityUser  EntityType = "user"
	EntityHost  EntityType = "host"
	EntityIP    EntityType = "ip"
	EntityCloud EntityType = "cloud"
)

// ValidEntityType reports whether t is one of the four supported kinds.
func ValidEntityType(t string) bool {
	switch EntityType(t) {
	case EntityUser, EntityHost, EntityIP, EntityCloud:
		return true
	}
	return false
}

// Entity is a canonical (already resolved) entity. Its key ("type:value") is the same
// format B89 uses in soc_alerts.entity_keys for users and IPs.
type Entity struct {
	Type  EntityType `json:"type"`
	Value string     `json:"value"`
}

// Key returns "type:value".
func (e Entity) Key() string { return string(e.Type) + ":" + e.Value }

// ParseKey splits "type:value". ok is false for unknown types or empty values.
func ParseKey(key string) (Entity, bool) {
	i := strings.IndexByte(key, ':')
	if i <= 0 || i == len(key)-1 {
		return Entity{}, false
	}
	t := key[:i]
	if !ValidEntityType(t) {
		return Entity{}, false
	}
	return Entity{Type: EntityType(t), Value: key[i+1:]}, true
}

// Stage is a step of a multi-stage pattern (edge WAF block, SSH brute force, ...).
type Stage string

const (
	StageEdgeWAFBlock     Stage = "edge.waf_block"
	StageEdgeScan         Stage = "edge.scan"
	StageSSHBruteForce    Stage = "ssh.bruteforce"
	StageSSHSuccess       Stage = "ssh.success"
	StageAuthFailure      Stage = "auth.failure"
	StageAuthSuccess      Stage = "auth.success"
	StagePrivilegedChange Stage = "priv.change"
	StageProtectionOff    Stage = "endpoint.protection_off"
	StageEndpointMalware  Stage = "endpoint.malware"
	StageCloudTamper      Stage = "cloud.audit_tamper"
	// StageIdentityChange is a credential/authentication-method change of an account
	// (password reset, MFA registration/removal, login profile change).
	StageIdentityChange Stage = "identity.change"
	// StageNewLocation is derived by the engine: a successful sign-in from a location
	// (country, or exact IP when no geolocation exists) not observed before for the user.
	StageNewLocation Stage = "auth.new_location"
	// StageEndpointActivity is activity attributed to a user on a managed endpoint.
	StageEndpointActivity Stage = "endpoint.activity"
)

// Confidence of an entity attribution. Only exact or canonical identifiers may pivot a
// sequence; derived identifiers (bare names, truncated host names) only add context.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"   // exact provider identifier (UPN, ARN, IP, agent)
	ConfidenceMedium Confidence = "medium" // canonicalized through configuration or structure
	ConfidenceLow    Confidence = "low"    // derived from free text or bare names
)

// Rank orders confidences (low < medium < high).
func (c Confidence) Rank() int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	}
	return 0
}

// Provenance records which field produced an entity and how it was normalized.
type Provenance struct {
	Key        string     `json:"key"`
	Field      string     `json:"field"`
	Method     string     `json:"method"` // exact, alias, domain_default, host_scoped, first_label, derived_ip
	Confidence Confidence `json:"confidence"`
}

// Observation is one Wazuh alert after entity resolution and stage classification.
type Observation struct {
	ProviderTenant string
	SessionRef     string
	ID             string
	// Time is the correlation time: the provider event time when it is present and
	// plausible, otherwise the time Wazuh recorded the alert (IngestedAt).
	Time       time.Time
	IngestedAt time.Time
	// TimeSource is "provider" or "ingest" (which clock produced Time).
	TimeSource string
	// Location is a coarse geolocation (country) of the actor IP when the SIEM enriched it.
	Location string
	// Provenance by entity key. Absent keys are treated as low confidence.
	Provenance map[string]Provenance
	// StageCriteria says, per stage, which evidence satisfied the classification.
	StageCriteria map[Stage]string
	RuleID        string
	Level         int
	Description   string
	Groups        []string
	Tactics       []string
	Source        string
	Entities      []Entity
	Stages        []Stage
}

// B89Alert is the compact projection of a B89 alert the API's internal feed returns.
type B89Alert struct {
	ID       string `json:"id"`
	RuleID   string `json:"ruleId"`
	Title    string `json:"title"`
	Priority string `json:"priority"`
	Status   string `json:"status"`
	Verdict  string `json:"verdict"`
	// ClosureOrigin says who closed the alert (human, ai_analyst, bulk_script, learning_engine,
	// ...). Empty when the API predates SOC learning stage A or the alert is still open.
	ClosureOrigin string    `json:"closureOrigin,omitempty"`
	Signal        string    `json:"signal"`
	EntityKeys    []string  `json:"entityKeys"`
	IncidentID    string    `json:"incidentId"`
	OccurredAt    time.Time `json:"occurredAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// CorrelatorRulePrefix identifies alerts emitted by the risk correlator. Keep this on the
// shared model so feedback can measure adjudication without importing the risk package.
const CorrelatorRulePrefix = "b89-correlator:"

// IsFalsePositive reports a benign/false-positive analyst verdict.
func (a B89Alert) IsFalsePositive() bool {
	return a.Verdict == "false_positive" || a.Verdict == "benign"
}

// IsHumanFalsePositive reports a false-positive/benign verdict closed by a person. Closures by
// the AI analyst, bulk scripts or the learning engine never feed suppression: otherwise a
// pattern could keep itself alive (docs/soc-learning/01-diseno.md §5.2). An unknown origin
// fails closed.
func (a B89Alert) IsHumanFalsePositive() bool {
	return a.IsFalsePositive() && a.ClosureOrigin == "human"
}

// IsTruePositive reports a confirmed verdict.
func (a B89Alert) IsTruePositive() bool { return a.Verdict == "true_positive" }

// StageHit records when a pattern stage was observed and by which rule.
type StageHit struct {
	ProviderTenant string    `json:"providerTenant,omitempty"`
	SessionRef     string    `json:"sessionRef,omitempty"`
	Stage          Stage     `json:"stage"`
	At             time.Time `json:"at"`
	RuleID         string    `json:"ruleId"`
	ObsID          string    `json:"observationId"`
	Source         string    `json:"source"`
	// Criteria is the evidence that satisfied this step (field/value, never raw payload).
	Criteria   string    `json:"criteria,omitempty"`
	IngestedAt time.Time `json:"ingestedAt,omitempty"`
}

// Candidate statuses.
const (
	CandidateProposed   = "proposed"
	CandidateEmitted    = "emitted"
	CandidateSuppressed = "suppressed"
	CandidateFailed     = "emit_failed"
	// CandidateShadow is produced by a rule running in shadow mode: it is measured and
	// reviewable, but never materialized as a B89 alert.
	CandidateShadow = "shadow"
)

// Rule modes.
const (
	ModeActive = "active"
	ModeShadow = "shadow"
)

// Check is one threshold of the rule and whether the evidence reached it.
type Check struct {
	Name     string `json:"name"`
	Required string `json:"required"`
	Observed string `json:"observed"`
	Met      bool   `json:"met"`
}

// ExplainedEntity is an entity of a candidate with its role in the explanation.
type ExplainedEntity struct {
	Key  string `json:"key"`
	Role string `json:"role"` // "pivot" or "related"
}

// Contributor is one rule that added risk to the pivot entity.
type Contributor struct {
	RuleID        string    `json:"ruleId"`
	Description   string    `json:"description"`
	Source        string    `json:"source"`
	Points        float64   `json:"points"`
	At            time.Time `json:"at"`
	ObservationID string    `json:"observationId"`
}

// Explanation is what the investigation view and notifications show: why this candidate
// exists (pattern and stages or threshold), which entities, which evidence and what to do.
type Explanation struct {
	PatternVersion string `json:"patternVersion,omitempty"`
	WindowSeconds  int64  `json:"windowSeconds,omitempty"`
	RequiredStages int    `json:"minStages,omitempty"`
	MinimumSources int    `json:"minSources,omitempty"`

	PatternID              string            `json:"patternId"`
	PatternTitle           string            `json:"patternTitle"`
	Narrative              string            `json:"narrative"`
	Stages                 []StageHit        `json:"stages"`
	Entities               []ExplainedEntity `json:"entities"`
	EvidenceObservationIDs []string          `json:"evidenceObservationIds"`
	TopContributors        []Contributor     `json:"topContributors"`
	ScoreBase              float64           `json:"scoreBase"`
	DiversityMultiplier    float64           `json:"diversityMultiplier"`
	ProgressionBonus       float64           `json:"progressionBonus"`
	NextSteps              []string          `json:"nextSteps"`

	// Checks lists every threshold of the rule with the observed value.
	Checks []Check `json:"checks"`
	// Contradictions is evidence that weakens the correlation (benign verdicts, distinct
	// sessions, out-of-order steps). MissingData lists what could not be verified.
	Contradictions []string `json:"contradictions"`
	MissingData    []string `json:"missingData"`
	// Provenance of the entities that connected the evidence.
	Provenance []Provenance `json:"provenance"`
	// AdditionalStageEvidence is step evidence that arrived after the candidate was opened
	// (late or repeated). Bounded inline; the ledger keeps every member.
	AdditionalStageEvidence []StageHit `json:"additionalStageEvidence"`
	// Lifecycle states the semantics: a candidate is a grouping to investigate, never an
	// incident accepted by the SOC.
	Lifecycle string `json:"lifecycle"`
}

// Candidate is a correlated "risk incident" proposal: one entity, one stage window.
type Candidate struct {
	ID               string      `json:"id"`
	IdempotencyKey   string      `json:"idempotencyKey"`
	Kind             string      `json:"kind"` // "pattern" or "threshold"
	PatternID        string      `json:"patternId"`
	Title            string      `json:"title"`
	Summary          string      `json:"summary"`
	Entity           Entity      `json:"entity"`
	RelatedKeys      []string    `json:"relatedEntityKeys"`
	Score            int         `json:"score"`
	RiskScore        float64     `json:"riskScore"`
	Priority         string      `json:"priority"`
	Signal           string      `json:"signal"`
	Stages           []StageHit  `json:"stages"`
	MemberCount      int         `json:"memberCount"`
	LinkedAlertCount int         `json:"linkedAlertCount"`
	B89AlertIDs      []string    `json:"b89AlertIds"`
	Sources          []string    `json:"sources"`
	Tactics          []string    `json:"tactics"`
	FirstSeen        time.Time   `json:"firstSeen"`
	LastSeen         time.Time   `json:"lastSeen"`
	CreatedAt        time.Time   `json:"createdAt"`
	Status           string      `json:"status"`
	Mode             string      `json:"mode"`
	Revision         int         `json:"revision"`
	UpdatedAt        time.Time   `json:"updatedAt"`
	AlertID          string      `json:"alertId,omitempty"`
	StatusDetail     string      `json:"statusDetail,omitempty"`
	Explanation      Explanation `json:"explanation"`
}
