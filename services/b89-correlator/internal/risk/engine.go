package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/model"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/resolve"
)

// CorrelatorRulePrefix prefixes the rule id of every alert the correlator creates in B89.
const CorrelatorRulePrefix = model.CorrelatorRulePrefix

// Suppressor answers whether a rule+entity pair is under a temporary suppression at t.
type Suppressor interface {
	Suppressed(ruleID, entityKey string, at time.Time) bool
}

type noSuppression struct{}

func (noSuppression) Suppressed(string, string, time.Time) bool { return false }

type episode struct {
	start time.Time
	cand  *model.Candidate
}

// CandidateLifecycle is attached to every explanation so no consumer reads a candidate as
// an incident: the SOC accepts incidents; the correlator only proposes groupings.
const CandidateLifecycle = "candidate: agrupación propuesta para investigar; no es un incidente aceptado por el SOC y no reemplaza las alertas originales"

// maxKnownLocations bounds the per-user location baseline.
const maxKnownLocations = 32

// locationBaseline is how long a sign-in location remains "known" for a user.
const locationBaseline = 30 * 24 * time.Hour

// CoverageFunc returns human-readable gaps (sources without complete coverage) for the
// evidence window of a candidate. It must not call back into the engine.
type CoverageFunc func(sources []string, from, to time.Time) []string

// Engine is the stateful correlator core. All methods are safe for concurrent use.
type Engine struct {
	pendingObservations map[*model.Candidate][]string
	mu                  sync.RWMutex
	P                   Policy
	Patterns            []Pattern
	Resolver            *resolve.Resolver
	Criticality         func(model.Entity) string
	supp                Suppressor
	coverage            CoverageFunc
	GroupMinLevel       int

	states       map[string]*EntityState
	related      map[string]map[string]time.Time
	history      map[string]stageHistory
	episodes     map[string]*episode
	patternCands map[string][]*model.Candidate   // pattern|entity -> candidates (episode lookup)
	stageObs     map[string]map[string]bool      // candidate -> observation ids cited as stage evidence
	locations    map[string]map[string]time.Time // user key -> location -> last seen
	prov         map[string]model.Provenance     // entity key -> strongest attribution seen
	open         map[string][]*model.Candidate   // entity key -> candidates still accepting members
	candidates   []*model.Candidate
	byID         map[string]*model.Candidate
	members      *memberLedger
	grouper      *Grouper
	seen         map[string]time.Time // observation ids (dedup of overlapping reads)

	Clock              time.Time
	Observations       int
	Duplicates         int
	DuplicatesBySource map[string]int
	OutOfOrder         int
	SuppressedObs      int
	CandidatesOpened   int
	CandidatesUpdated  int
	ShadowCandidates   int
	BySource           map[string]int
	ByStage            map[string]int
	horizon            time.Duration
}

// NewEngine builds an engine. crit may be nil (every entity is "medium").
func NewEngine(p Policy, patterns []Pattern, r *resolve.Resolver, crit func(model.Entity) string, groupMinLevel int) *Engine {
	if crit == nil {
		crit = func(model.Entity) string { return "" }
	}
	h := p.Window
	for _, pt := range patterns {
		if pt.Window > h {
			h = pt.Window
		}
	}
	return &Engine{
		pendingObservations: map[*model.Candidate][]string{},
		members:             newMemberLedger(),
		P:                   p, Patterns: patterns, Resolver: r, Criticality: crit, supp: noSuppression{},
		GroupMinLevel: groupMinLevel,
		states:        map[string]*EntityState{}, related: map[string]map[string]time.Time{},
		history: map[string]stageHistory{}, episodes: map[string]*episode{},
		patternCands: map[string][]*model.Candidate{}, stageObs: map[string]map[string]bool{},
		locations: map[string]map[string]time.Time{}, prov: map[string]model.Provenance{},
		open: map[string][]*model.Candidate{},
		byID: map[string]*model.Candidate{}, grouper: NewGrouper(p.GroupGap, p.GroupMaxSpan),
		seen: map[string]time.Time{}, BySource: map[string]int{}, ByStage: map[string]int{},
		DuplicatesBySource: map[string]int{},
		horizon:            h,
	}
}

// SetCoverage installs the source-coverage lookup used to state missing data.
func (e *Engine) SetCoverage(f CoverageFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.coverage = f
}

// pivotEligible reports whether an entity attribution is strong enough to connect the
// steps of a sequence. Observations built without provenance (legacy fixtures) are exact.
func pivotEligible(o model.Observation, key string) bool {
	if o.Provenance == nil {
		return true
	}
	pv, ok := o.Provenance[key]
	return ok && pv.Confidence.Rank() >= PivotMinConfidence.Rank()
}

// observeLocation derives auth.new_location for a user: a successful sign-in from a
// location of the same kind (country, else exact IP) absent from the user's baseline. The
// first location ever seen is never "new": there is no baseline to differ from.
func (e *Engine) observeLocation(key string, o model.Observation) (model.StageHit, bool) {
	loc, label := "", ""
	if o.Location != "" {
		loc, label = "country:"+o.Location, "país «"+o.Location+"»"
	} else {
		for _, ent := range o.Entities {
			if ent.Type != model.EntityIP {
				continue
			}
			if pv, ok := o.Provenance[ent.Key()]; o.Provenance != nil && (!ok || pv.Method != "exact") {
				continue
			}
			loc, label = "ip:"+ent.Value, "IP "+ent.Value
			break
		}
	}
	if loc == "" {
		return model.StageHit{}, false
	}
	kind := loc[:strings.IndexByte(loc, ':')+1]
	known := e.locations[key]
	if known == nil {
		known = map[string]time.Time{}
		e.locations[key] = known
	}
	previous, since := []string{}, time.Time{}
	for k, t := range known {
		if strings.HasPrefix(k, kind) && k != loc && o.Time.Sub(t) <= locationBaseline {
			previous = append(previous, strings.TrimPrefix(k, kind))
			if since.IsZero() || t.Before(since) {
				since = t
			}
		}
	}
	_, seenBefore := known[loc]
	if o.Time.After(known[loc]) {
		known[loc] = o.Time
	}
	if len(known) > maxKnownLocations {
		oldest, at := "", time.Time{}
		for k, t := range known {
			if oldest == "" || t.Before(at) {
				oldest, at = k, t
			}
		}
		delete(known, oldest)
	}
	if seenBefore || len(previous) == 0 {
		return model.StageHit{}, false
	}
	sort.Strings(previous)
	if len(previous) > 3 {
		previous = previous[:3]
	}
	return model.StageHit{
		ProviderTenant: o.ProviderTenant, SessionRef: o.SessionRef, Stage: model.StageNewLocation,
		At: o.Time, RuleID: o.RuleID, ObsID: o.ID, Source: o.Source, IngestedAt: o.IngestedAt,
		Criteria: fmt.Sprintf("inicio de sesión exitoso desde %s, no observado antes para el usuario; ubicaciones previas observadas por el correlador desde %s: %s",
			label, since.UTC().Format("2006-01-02 15:04Z"), strings.Join(previous, ", ")),
	}, true
}

// SetSuppressor replaces the suppression source (feedback loop).
func (e *Engine) SetSuppressor(s Suppressor) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s == nil {
		s = noSuppression{}
	}
	e.supp = s
}

func candidateID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "rc_" + hex.EncodeToString(sum[:12])
}

// Process ingests one observation and returns the candidates it created.
func (e *Engine) Process(o model.Observation) []*model.Candidate {
	created, _ := e.ProcessStatus(o)
	return created
}

// ProcessStatus is Process that also reports whether the observation was a duplicate
// (already ingested through an overlapping or replayed read).
func (e *Engine) ProcessStatus(o model.Observation) ([]*model.Candidate, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if o.ID != "" {
		if _, dup := e.seen[o.ID]; dup {
			e.Duplicates++
			e.DuplicatesBySource[o.Source]++
			return nil, true
		}
		e.seen[o.ID] = o.Time
	}
	e.applyMerges()
	if o.Time.Before(e.Clock) {
		e.OutOfOrder++
	}
	if o.Time.After(e.Clock) {
		e.Clock = o.Time
	}
	for key, pv := range o.Provenance {
		if prev, ok := e.prov[key]; !ok || pv.Confidence.Rank() > prev.Confidence.Rank() {
			e.prov[key] = pv
		}
	}
	e.Observations++
	e.BySource[o.Source]++
	for _, s := range o.Stages {
		e.ByStage[string(s)]++
	}

	keys := make([]string, 0, len(o.Entities))
	for _, ent := range o.Entities {
		keys = append(keys, ent.Key())
	}
	if o.Level >= e.GroupMinLevel {
		e.grouper.Add(PivotOf(keys, o.RuleID), o.RuleID, o.Time)
	}

	created := []*model.Candidate{}
	for _, ent := range o.Entities {
		key := ent.Key()
		st := e.states[key]
		if st == nil {
			st = newState(ent, e.Criticality(ent))
			e.states[key] = st
		}
		suppressed := e.supp.Suppressed(o.RuleID, key, o.Time)
		if suppressed {
			e.SuppressedObs++
		}
		st.apply(o, e.P, suppressed)
		rel := e.related[key]
		if rel == nil {
			rel = map[string]time.Time{}
			e.related[key] = rel
		}
		for _, other := range keys {
			if other != key {
				rel[other] = o.Time
			}
		}
		if len(rel) > 32 {
			trimRelated(rel, 32)
		}
		// Open candidates of this entity absorb the observation (grouping / dedup).
		for _, c := range e.open[key] {
			// Delayed observations must belong to this episode, not merely be older
			// than its upper bounds. Otherwise an unrelated historical event can
			// inflate a current case and contaminate downstream investigation.
			if !o.Time.Before(c.FirstSeen) && o.Time.Sub(c.LastSeen) <= e.P.GroupGap && o.Time.Sub(c.FirstSeen) <= e.P.GroupMaxSpan {
				c.MemberCount++
				if o.ID != "" {
					e.pendingObservations[c] = append(e.pendingObservations[c], o.ID)
				}
				if !suppressed {
					c.Sources = unionStrings(c.Sources, []string{o.Source})
					c.Tactics = unionStrings(c.Tactics, o.Tactics)
				}
				if o.ID != "" && len(c.Explanation.EvidenceObservationIDs) < 50 && !contains(c.Explanation.EvidenceObservationIDs, o.ID) {
					c.Explanation.EvidenceObservationIDs = append(c.Explanation.EvidenceObservationIDs, o.ID)
				}
				if o.Time.After(c.LastSeen) {
					c.LastSeen = o.Time
				}
			}
		}
		if !suppressed {
			hist := e.history[key]
			if hist == nil {
				hist = stageHistory{}
				e.history[key] = hist
			}
			stages := o.Stages
			for _, s := range o.Stages {
				criteria := o.StageCriteria[s]
				if criteria == "" {
					criteria = fmt.Sprintf("regla %s (%s) clasificada como %s", o.RuleID, o.Source, s)
				}
				hist.add(model.StageHit{ProviderTenant: o.ProviderTenant, SessionRef: o.SessionRef, Stage: s, At: o.Time, RuleID: o.RuleID, ObsID: o.ID, Source: o.Source, Criteria: criteria, IngestedAt: o.IngestedAt}, e.horizon)
			}
			eligible := pivotEligible(o, key)
			if eligible && ent.Type == model.EntityUser && containsStage(o.Stages, model.StageAuthSuccess) {
				if hit, ok := e.observeLocation(key, o); ok {
					hist.add(hit, e.horizon)
					stages = append(append([]model.Stage{}, o.Stages...), model.StageNewLocation)
					e.ByStage[string(model.StageNewLocation)]++
				}
			}
			if len(stages) > 0 && eligible {
				created = append(created, e.evaluatePatterns(st, hist, o, stages)...)
			}
		}
		if c := e.evaluateThreshold(st, o.Time); c != nil {
			created = append(created, c)
		}
	}
	return created, false
}

func containsStage(list []model.Stage, s model.Stage) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func trimRelated(rel map[string]time.Time, keep int) {
	type kv struct {
		k string
		t time.Time
	}
	list := make([]kv, 0, len(rel))
	for k, t := range rel {
		list = append(list, kv{k, t})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].t.After(list[j].t) })
	for _, item := range list[keep:] {
		delete(rel, item.k)
	}
}

// applyMerges folds states of identifiers that the resolver just linked.
func (e *Engine) applyMerges() {
	if e.Resolver == nil {
		return
	}
	for _, m := range e.Resolver.DrainMerges() {
		from := e.states[m.From]
		if from == nil {
			continue
		}
		into := e.states[m.Into]
		if into == nil {
			ent, _ := model.ParseKey(m.Into)
			into = newState(ent, e.Criticality(ent))
			e.states[m.Into] = into
		}
		into.merge(from, e.P)
		delete(e.states, m.From)
		if h := e.history[m.From]; h != nil {
			dst := e.history[m.Into]
			if dst == nil {
				dst = stageHistory{}
				e.history[m.Into] = dst
			}
			for _, hits := range h {
				for _, hit := range hits {
					dst.add(hit, e.horizon)
				}
			}
			delete(e.history, m.From)
		}
		e.open[m.Into] = append(e.open[m.Into], e.open[m.From]...)
		delete(e.open, m.From)
		for _, p := range e.Patterns {
			if list := e.patternCands[p.ID+"|"+m.From]; len(list) > 0 {
				e.patternCands[p.ID+"|"+m.Into] = append(e.patternCands[p.ID+"|"+m.Into], list...)
				delete(e.patternCands, p.ID+"|"+m.From)
			}
		}
		if known := e.locations[m.From]; known != nil {
			dst := e.locations[m.Into]
			if dst == nil {
				dst = map[string]time.Time{}
				e.locations[m.Into] = dst
			}
			for k, t := range known {
				if t.After(dst[k]) {
					dst[k] = t
				}
			}
			delete(e.locations, m.From)
		}
	}
}

func (e *Engine) evaluatePatterns(st *EntityState, hist stageHistory, o model.Observation, stages []model.Stage) []*model.Candidate {
	out := []*model.Candidate{}
	for _, p := range e.Patterns {
		if !p.pivots(st.Entity.Type) {
			continue
		}
		touches := false
		for _, s := range stages {
			if p.uses(s) {
				touches = true
			}
		}
		if !touches {
			continue
		}
		// A late observation can complete a chain whose terminal step was already
		// processed. Evaluate at its own time and at each later step inside the window.
		for _, at := range p.anchors(hist, o.Time) {
			hits, complete := p.Match(hist, at)
			if len(hits) < p.MinStages {
				continue
			}
			if c := e.applyMatch(st, p, hits, complete); c != nil {
				out = append(out, c)
			}
		}
	}
	return out
}

// maxAnchors bounds re-evaluation work per observation and pattern.
const maxAnchors = 16

// anchors returns the evaluation times for an observation at `at`: `at` itself and the
// distinct times of this pattern's steps later than `at` but within the window.
func (p Pattern) anchors(h stageHistory, at time.Time) []time.Time {
	set := map[time.Time]bool{at: true}
	for _, s := range p.Stages {
		for _, hit := range h[s] {
			if hit.At.After(at) && hit.At.Sub(at) <= p.Window {
				set[hit.At] = true
			}
		}
	}
	out := make([]time.Time, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	if len(out) > maxAnchors {
		out = out[:maxAnchors]
	}
	return out
}

func chainSpan(hits []model.StageHit) (time.Time, time.Time) {
	first, last := hits[0].At, hits[0].At
	for _, h := range hits[1:] {
		if h.At.Before(first) {
			first = h.At
		}
		if h.At.After(last) {
			last = h.At
		}
	}
	return first, last
}

// applyMatch creates a candidate for a new episode, or updates the candidate of the same
// episode with evidence that arrived later. A partial candidate is escalated by a separate
// complete candidate (different priority/idempotency key); a complete one absorbs updates.
func (e *Engine) applyMatch(st *EntityState, p Pattern, hits []model.StageHit, complete bool) *model.Candidate {
	key := st.Entity.Key()
	markKey := p.ID + "|" + key
	first, last := chainSpan(hits)
	list := e.patternCands[markKey]
	for i := len(list) - 1; i >= 0; i-- {
		c := list[i]
		cFirst, cLast := chainSpan(c.Stages)
		lo, hi := first, last
		if cFirst.Before(lo) {
			lo = cFirst
		}
		if cLast.After(hi) {
			hi = cLast
		}
		if hi.Sub(lo) > p.Window {
			continue // a different episode
		}
		if len(c.Stages) == len(p.Stages) || !complete {
			e.enrich(c, hits)
			return nil
		}
		break // partial episode escalated by a complete chain
	}
	variant, priority := "partial", p.PartialPriority
	if complete {
		priority, variant = p.Priority, "complete"
	}
	if st.Criticality == "critical" || st.Criticality == "high" {
		priority = bump(priority)
	}
	if e.supp.Suppressed(CorrelatorRulePrefix+p.ID, key, last) {
		return nil
	}
	idem := fmt.Sprintf("b89-correlator|pattern|%s|%s|%s|%d", p.ID, variant, key, hits[0].At.Unix())
	c := e.newCandidate(st, last, idem, "pattern", p.ID, priority, p.Signal)
	c.Stages = hits
	c.FirstSeen = first
	names := make([]string, len(hits))
	for i, h := range hits {
		names[i] = fmt.Sprintf("%s (regla %s, %s)", h.Stage, h.RuleID, h.At.UTC().Format("2006-01-02 15:04Z"))
	}
	c.Title = "B89 Riesgo: " + p.Title
	c.Explanation.PatternTitle = p.Title
	c.Explanation.PatternVersion = p.Fingerprint()
	c.Explanation.WindowSeconds = int64(p.Window / time.Second)
	c.Explanation.RequiredStages = p.MinStages
	c.Explanation.MinimumSources = p.MinSources
	c.Explanation.Stages = hits
	stageEvidence := []string{}
	for _, h := range hits {
		if h.ObsID != "" {
			stageEvidence = append(stageEvidence, h.ObsID)
		}
	}
	c.Explanation.EvidenceObservationIDs = mergeIDs(stageEvidence, c.Explanation.EvidenceObservationIDs, 20)
	order, separator := "sin exigir orden temporal", "; "
	if p.Ordered {
		order, separator = "en orden temporal no decreciente", " → "
	}
	// Keep the limitation near the start so bounded notification/MCP projections
	// retain it. Matching timestamps and entities do not establish causality.
	c.Explanation.Narrative = fmt.Sprintf("Correlación temporal; no demuestra causalidad ni compromiso. %s. Se observaron %d de %d etapas %s sobre la misma entidad (%s) dentro de %s: %s. Riesgo %.1f (base %.1f x diversidad %.2f + progresión %.1f).",
		p.Title, len(hits), len(p.Stages), order, st.Entity.Type, p.Window, strings.Join(names, separator), c.RiskScore,
		c.Explanation.ScoreBase, c.Explanation.DiversityMultiplier, c.Explanation.ProgressionBonus)
	c.Summary = fmt.Sprintf("Patrón %s (%s, %d/%d etapas) sobre %s: %s. Riesgo %.1f.",
		p.ID, variant, len(hits), len(p.Stages), st.Entity.Type, strings.Join(names, separator), c.RiskScore)
	e.explainPattern(c, p, hits)
	if p.IsShadow() {
		c.Mode, c.Status = model.ModeShadow, model.CandidateShadow
		c.StatusDetail = "regla en modo sombra: se mide y revisa, no se materializa como alerta B89"
	}
	registered := e.register(st, c)
	if registered == c {
		e.patternCands[markKey] = append(e.patternCands[markKey], c)
		obs := map[string]bool{}
		for _, h := range hits {
			if h.ObsID != "" {
				obs[h.ObsID] = true
			}
		}
		e.stageObs[c.ID] = obs
		if c.Mode == model.ModeShadow {
			e.ShadowCandidates++
		}
	}
	return registered
}

// maxAdditionalEvidence bounds the late/extra step evidence kept inline on a candidate.
// The full membership remains in the ledger.
const maxAdditionalEvidence = 20

// enrich records step evidence that satisfies an existing episode (late or repeated
// arrivals). It never rewrites the explained chain; it adds and revises.
func (e *Engine) enrich(c *model.Candidate, hits []model.StageHit) {
	seen := e.stageObs[c.ID]
	if seen == nil {
		seen = map[string]bool{}
		e.stageObs[c.ID] = seen
	}
	added := false
	for _, h := range hits {
		if h.ObsID == "" || seen[h.ObsID] {
			continue
		}
		seen[h.ObsID] = true
		added = true
		e.pendingObservations[c] = append(e.pendingObservations[c], h.ObsID)
		if len(c.Explanation.AdditionalStageEvidence) < maxAdditionalEvidence {
			c.Explanation.AdditionalStageEvidence = append(c.Explanation.AdditionalStageEvidence, h)
		}
		if h.At.Before(c.FirstSeen) {
			c.FirstSeen = h.At
		}
		if h.At.After(c.LastSeen) {
			c.LastSeen = h.At
		}
	}
	if added {
		c.Revision++
		c.UpdatedAt = e.Clock
		e.CandidatesUpdated++
		if _, exists := e.pendingObservations[c]; !exists {
			e.pendingObservations[c] = nil
		}
	}
}

// explainPattern fills the thresholds, contradictions, missing data and provenance an
// analyst needs to validate the correlation quickly.
func (e *Engine) explainPattern(c *model.Candidate, p Pattern, hits []model.StageHit) {
	x := &c.Explanation
	sources, rules, sessions := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, h := range hits {
		if h.Source != "" && h.Source != "unknown" {
			sources[h.Source] = true
		}
		rules[h.RuleID] = true
		if h.SessionRef != "" {
			sessions[h.SessionRef] = true
		}
	}
	first, last := chainSpan(hits)
	x.Checks = append(x.Checks,
		model.Check{Name: "etapas", Required: fmt.Sprintf(">= %d de %d", p.MinStages, len(p.Stages)), Observed: fmt.Sprintf("%d", len(hits)), Met: len(hits) >= p.MinStages},
		model.Check{Name: "ventana", Required: "<= " + p.Window.String(), Observed: last.Sub(first).String(), Met: last.Sub(first) <= p.Window},
	)
	if p.MinSources > 1 {
		x.Checks = append(x.Checks, model.Check{Name: "fuentes distintas", Required: fmt.Sprintf(">= %d", p.MinSources), Observed: fmt.Sprintf("%d", len(sources)), Met: len(sources) >= p.MinSources})
	}
	if p.MinDistinctRules > 1 {
		x.Checks = append(x.Checks, model.Check{Name: "reglas distintas", Required: fmt.Sprintf(">= %d", p.MinDistinctRules), Observed: fmt.Sprintf("%d", len(rules)), Met: len(rules) >= p.MinDistinctRules})
	}
	if p.Ordered {
		ordered := true
		for i := 1; i < len(hits); i++ {
			if hits[i].At.Before(hits[i-1].At) {
				ordered = false
			}
		}
		x.Checks = append(x.Checks, model.Check{Name: "orden temporal", Required: "no decreciente", Observed: map[bool]string{true: "cumplido", false: "no cumplido"}[ordered], Met: ordered})
	}
	pivot := e.prov[c.Entity.Key()]
	if pivot.Confidence == "" {
		pivot = model.Provenance{Key: c.Entity.Key(), Method: "exact", Confidence: model.ConfidenceHigh}
	}
	x.Checks = append(x.Checks, model.Check{Name: "confianza del pivote", Required: ">= " + string(PivotMinConfidence), Observed: string(pivot.Confidence), Met: pivot.Confidence.Rank() >= PivotMinConfidence.Rank()})
	if pivot.Confidence != model.ConfidenceHigh {
		x.Contradictions = append(x.Contradictions, fmt.Sprintf("La entidad pivote se normalizó por %s (campo %s); confirmar que todas las etapas corresponden a la misma identidad.", pivot.Method, fieldLabel(pivot.Field)))
	}
	if len(sessions) > 1 {
		x.Contradictions = append(x.Contradictions, fmt.Sprintf("Las etapas pertenecen a %d sesiones distintas del proveedor; la secuencia no está ligada a una sola sesión.", len(sessions)))
	}
	present := map[model.Stage]bool{}
	for _, h := range hits {
		present[h.Stage] = true
		if !h.IngestedAt.IsZero() && h.IngestedAt.Equal(h.At) && h.Source != "" {
			x.MissingData = appendUnique(x.MissingData, fmt.Sprintf("La etapa %s usa la hora de ingesta: el proveedor no informó hora del evento.", h.Stage))
		}
		if h.Stage == model.StageNewLocation && strings.Contains(h.Criteria, "desde IP ") {
			x.MissingData = appendUnique(x.MissingData, "Sin geolocalización del acceso: la ubicación nueva se basa en la IP exacta (puede variar por red móvil o VPN).")
		}
	}
	for _, s := range p.Stages {
		if !present[s] {
			x.MissingData = append(x.MissingData, fmt.Sprintf("Etapa no observada en la ventana: %s.", s))
		}
	}
	e.explainCommon(c)
}

// explainCommon adds the provenance of connecting entities and source coverage gaps.
func (e *Engine) explainCommon(c *model.Candidate) {
	x := &c.Explanation
	for _, ent := range x.Entities {
		if pv, ok := e.prov[ent.Key]; ok {
			x.Provenance = append(x.Provenance, pv)
		}
	}
	if e.coverage != nil {
		for _, gap := range e.coverage(c.Sources, c.FirstSeen, c.LastSeen) {
			x.MissingData = appendUnique(x.MissingData, gap)
		}
	}
}

func fieldLabel(field string) string {
	if field == "" {
		return "no informado"
	}
	return field
}

func appendUnique(list []string, v string) []string {
	if contains(list, v) {
		return list
	}
	return append(list, v)
}

func (e *Engine) evaluateThreshold(st *EntityState, at time.Time) *model.Candidate {
	key := st.Entity.Key()
	eff := st.Effective(at, e.P).Effective
	ep := e.episodes[key]
	if ep != nil {
		if eff < e.P.Threshold/2 {
			delete(e.episodes, key)
		}
		return nil
	}
	if eff < e.P.Threshold {
		return nil
	}
	e.episodes[key] = &episode{start: at}
	if e.supp.Suppressed(CorrelatorRulePrefix+"threshold", key, at) {
		return nil
	}
	priority := "P3"
	if eff >= 2*e.P.Threshold {
		priority = "P2"
	}
	if st.Criticality == "critical" || st.Criticality == "high" {
		priority = bump(priority)
	}
	idem := fmt.Sprintf("b89-correlator|threshold|%s|%d", key, at.Unix())
	c := e.newCandidate(st, at, idem, "threshold", "threshold", priority, signalFromTactics(st.TacticsAt(at, e.P)))
	c.FirstSeen = st.FirstSeen
	if at.Sub(c.FirstSeen) > e.P.Window {
		c.FirstSeen = at.Add(-e.P.Window)
	}
	top := []string{}
	for i, ctr := range st.Contributors {
		if i == 5 {
			break
		}
		top = append(top, fmt.Sprintf("regla %s (%s, +%.1f)", ctr.RuleID, ctr.Source, ctr.Points))
	}
	b := st.Effective(at, e.P)
	c.Title = fmt.Sprintf("B89 Riesgo: %s supera el umbral de riesgo", entityNoun(st.Entity.Type))
	c.Summary = fmt.Sprintf("Riesgo %.1f ≥ umbral %.0f (base %.1f × diversidad %.2f + progresión %.1f) con %d fuentes y tácticas %s. Aportes recientes: %s.",
		b.Effective, e.P.Threshold, b.Base, b.Diversity, b.Progression, len(st.SourcesAt(at, e.P)),
		strings.Join(st.TacticsAt(at, e.P), ", "), strings.Join(top, "; "))
	c.Explanation.PatternTitle = "Umbral de riesgo por entidad"
	c.Explanation.Narrative = c.Summary
	c.Explanation.WindowSeconds = int64(e.P.Window / time.Second)
	c.Explanation.Checks = append(c.Explanation.Checks,
		model.Check{Name: "riesgo efectivo", Required: fmt.Sprintf(">= %.0f", e.P.Threshold), Observed: fmt.Sprintf("%.1f", b.Effective), Met: b.Effective >= e.P.Threshold},
		model.Check{Name: "fuentes distintas", Required: "informativo", Observed: fmt.Sprintf("%d", len(c.Sources)), Met: true},
	)
	if len(c.Sources) < 2 {
		c.Explanation.Contradictions = append(c.Explanation.Contradictions, "Todo el riesgo proviene de una sola fuente; no hay corroboración independiente.")
	}
	if pv, ok := e.prov[key]; ok && pv.Confidence == model.ConfidenceLow {
		c.Explanation.Contradictions = append(c.Explanation.Contradictions, fmt.Sprintf("La entidad se atribuyó con confianza baja (%s, campo %s): puede agrupar identidades distintas.", pv.Method, fieldLabel(pv.Field)))
	}
	e.explainCommon(c)
	e.episodes[key].cand = c
	return e.register(st, c)
}

func entityNoun(t model.EntityType) string {
	switch t {
	case model.EntityUser:
		return "Usuario"
	case model.EntityHost:
		return "Equipo"
	case model.EntityIP:
		return "IP"
	}
	return "Recurso cloud"
}

func (e *Engine) newCandidate(st *EntityState, at time.Time, idem, kind, patternID, priority, signal string) *model.Candidate {
	b := st.Effective(at, e.P)
	floor := map[string]float64{"P1": 85, "P2": 65, "P3": 45, "P4": 25}[priority]
	score := int(math.Round(math.Max(floor, math.Min(b.Effective, 100))))
	if score > 100 {
		score = 100
	}
	related := []string{}
	for k := range e.related[st.Entity.Key()] {
		related = append(related, k)
	}
	sort.Strings(related)
	if len(related) > 10 {
		related = related[:10]
	}
	entities := []model.ExplainedEntity{{Key: st.Entity.Key(), Role: "pivot"}}
	for _, k := range related {
		entities = append(entities, model.ExplainedEntity{Key: k, Role: "related"})
	}
	top := []model.Contributor{}
	evidence := []string{}
	for _, ctr := range st.Contributors {
		if ctr.Suppressed || ctr.Points <= 0 {
			continue
		}
		if len(top) < 5 {
			top = append(top, model.Contributor{RuleID: ctr.RuleID, Description: ctr.Description, Source: ctr.Source, Points: ctr.Points, At: ctr.At, ObservationID: ctr.ObsID})
		}
		if len(evidence) < 20 && ctr.ObsID != "" {
			evidence = append(evidence, ctr.ObsID)
		}
	}
	expl := model.Explanation{
		PatternID: patternID, Entities: entities, TopContributors: top, EvidenceObservationIDs: evidence,
		ScoreBase: b.Base, DiversityMultiplier: b.Diversity, ProgressionBonus: b.Progression,
		NextSteps: nextSteps(patternID), Stages: []model.StageHit{},
		Checks: []model.Check{}, Contradictions: []string{}, MissingData: []string{},
		Provenance: []model.Provenance{}, AdditionalStageEvidence: []model.StageHit{},
		Lifecycle: CandidateLifecycle,
	}
	return &model.Candidate{
		Explanation: expl,
		ID:          candidateID(idem), IdempotencyKey: idem, Kind: kind, PatternID: patternID,
		Entity: st.Entity, RelatedKeys: related, Score: score, RiskScore: b.Effective,
		Priority: priority, Signal: signal, MemberCount: 1, Sources: st.SourcesAt(at, e.P),
		Tactics: st.TacticsAt(at, e.P), LastSeen: at, CreatedAt: at, Status: model.CandidateProposed,
		B89AlertIDs: []string{}, Mode: model.ModeActive, Revision: 1, UpdatedAt: at,
	}
}

func (e *Engine) register(st *EntityState, c *model.Candidate) *model.Candidate {
	if existing, ok := e.byID[c.ID]; ok {
		return existing
	}
	if alertID := e.members.emitted[c.ID]; alertID != "" {
		c.AlertID, c.Status = alertID, model.CandidateEmitted
	}
	e.candidates = append(e.candidates, c)
	e.byID[c.ID] = c
	e.CandidatesOpened++
	e.pendingObservations[c] = append(e.pendingObservations[c], c.Explanation.EvidenceObservationIDs...)
	for _, hit := range c.Stages {
		if hit.ObsID != "" {
			e.pendingObservations[c] = append(e.pendingObservations[c], hit.ObsID)
		}
	}
	for _, ctr := range st.Contributors {
		if !ctr.Suppressed && ctr.ObsID != "" && !ctr.At.Before(c.FirstSeen) && !ctr.At.After(c.LastSeen) {
			e.pendingObservations[c] = append(e.pendingObservations[c], ctr.ObsID)
		}
	}
	key := st.Entity.Key()
	e.open[key] = append(e.open[key], c)
	st.CandidateIDs = append(st.CandidateIDs, c.ID)
	return c
}

func bump(p string) string {
	switch p {
	case "P4":
		return "P3"
	case "P3":
		return "P2"
	case "P2":
		return "P1"
	}
	return p
}

func signalFromTactics(tactics []string) string {
	best, idx := "other", -1
	m := map[string]string{
		"credential-access": "credential_access", "initial-access": "initial_access",
		"persistence": "persistence", "privilege-escalation": "privilege_escalation",
		"defense-evasion": "defense_evasion", "collection": "collection", "exfiltration": "exfiltration",
	}
	for _, t := range tactics {
		if s, ok := m[t]; ok && resolve.TacticIndex(t) > idx {
			best, idx = s, resolve.TacticIndex(t)
		}
	}
	return best
}

// AttachAlerts links B89 alerts to the candidates of their entities (same stage window).
func (e *Engine) AttachAlerts(alerts []model.B89Alert) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	links := make(map[*model.Candidate][]string)
	benign := make(map[*model.Candidate]map[string]bool)
	for _, a := range alerts {
		if a.ID == "" || strings.HasPrefix(a.RuleID, CorrelatorRulePrefix) {
			continue
		}
		for _, k := range a.EntityKeys {
			key := k
			if e.Resolver != nil {
				key = e.Resolver.Canonical(k)
			}
			for _, c := range e.open[key] {
				if a.OccurredAt.Before(c.FirstSeen.Add(-e.P.GroupGap)) || a.OccurredAt.After(c.LastSeen.Add(e.P.GroupGap)) {
					continue
				}
				links[c] = append(links[c], a.ID)
				if a.IsFalsePositive() {
					if benign[c] == nil {
						benign[c] = map[string]bool{}
					}
					benign[c][a.ID] = true
				}
			}
		}
	}
	for c, ids := range benign {
		line := fmt.Sprintf("%d alertas vinculadas tienen veredicto de analista benigno o falso positivo.", len(ids))
		kept := []string{}
		for _, v := range c.Explanation.Contradictions {
			if !strings.HasSuffix(v, "tienen veredicto de analista benigno o falso positivo.") {
				kept = append(kept, v)
			}
		}
		c.Explanation.Contradictions = append(kept, line)
	}
	for c, ids := range links {
		all, err := e.members.merge(c.ID, ids)
		if err != nil {
			return err
		}
		c.B89AlertIDs = append([]string{}, all[:min(50, len(all))]...)
		if c.LinkedAlertCount != len(all) && e.members.dir != "" {
			snapshot := *c
			snapshot.LinkedAlertCount = len(all)
			if err := e.members.store(c.ID+".snapshot", &snapshot); err != nil {
				return err
			}
		}
		c.LinkedAlertCount = len(all)
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Copy on update keeps previously returned candidate summaries immutable.
func unionStrings(existing, incoming []string) []string {
	out := append([]string{}, existing...)
	for _, value := range incoming {
		if value != "" && !contains(out, value) {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

// UpdateCandidate mutates a candidate under the lock (emission results).
func (e *Engine) UpdateCandidate(id string, fn func(*model.Candidate)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c := e.byID[id]; c != nil {
		fn(c)
		if _, exists := e.pendingObservations[c]; !exists {
			e.pendingObservations[c] = nil
		}
	}
}

// Candidate returns a copy of one candidate.
func (e *Engine) Candidate(id string) (model.Candidate, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	c := e.byID[id]
	if c == nil {
		return model.Candidate{}, false
	}
	cp := *c
	cp.Stages = append([]model.StageHit{}, c.Stages...)
	cp.B89AlertIDs = append([]string{}, c.B89AlertIDs...)
	return cp, true
}

// Candidates returns copies, newest first. status filters when non-empty.
func (e *Engine) Candidates(status string, limit int) []model.Candidate {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := []model.Candidate{}
	for i := len(e.candidates) - 1; i >= 0; i-- {
		c := e.candidates[i]
		if status != "" && c.Status != status {
			continue
		}
		cp := *c
		cp.Stages = append([]model.StageHit{}, c.Stages...)
		cp.B89AlertIDs = append([]string{}, c.B89AlertIDs...)
		out = append(out, cp)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// EntitySummary is the list view of an entity.
type EntitySummary struct {
	Key          string    `json:"key"`
	Type         string    `json:"type"`
	Value        string    `json:"value"`
	Score        float64   `json:"score"`
	Breakdown    Breakdown `json:"breakdown"`
	Peak         float64   `json:"peak"`
	PeakAt       time.Time `json:"peakAt"`
	FirstSeen    time.Time `json:"firstSeen"`
	LastSeen     time.Time `json:"lastSeen"`
	Observations int       `json:"observations"`
	Suppressed   int       `json:"suppressedObservations"`
	Sources      []string  `json:"sources"`
	Tactics      []string  `json:"tactics"`
	Criticality  string    `json:"criticality"`
	CandidateIDs []string  `json:"candidateIds"`
}

// EntityDetail adds contributors, timeline, aliases and related entities.
type EntityDetail struct {
	EntitySummary
	Contributors []Contribution  `json:"contributors"`
	Timeline     []TimelinePoint `json:"timeline"`
	Aliases      []string        `json:"aliases"`
	Related      []string        `json:"related"`
}

func (e *Engine) summary(key string, st *EntityState, at time.Time) EntitySummary {
	b := st.Effective(at, e.P)
	crit := st.Criticality
	if crit == "" {
		crit = "medium"
	}
	return EntitySummary{
		Key: key, Type: string(st.Entity.Type), Value: st.Entity.Value, Score: b.Effective,
		Breakdown: b, Peak: round2(st.Peak), PeakAt: st.PeakAt, FirstSeen: st.FirstSeen,
		LastSeen: st.LastSeen, Observations: st.Observations, Suppressed: st.Suppressed,
		Sources: st.SourcesAt(at, e.P), Tactics: st.TacticsAt(at, e.P), Criticality: crit,
		CandidateIDs: append([]string(nil), st.CandidateIDs...),
	}
}

// Top returns the n riskiest entities at time `at` (optionally of one type).
func (e *Engine) Top(n int, typ string, at time.Time) []EntitySummary {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]EntitySummary, 0, len(e.states))
	for key, st := range e.states {
		if typ != "" && string(st.Entity.Type) != typ {
			continue
		}
		s := e.summary(key, st, at)
		if s.Score < 0.01 && n > 0 {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score == out[j].Score {
			return out[i].Key < out[j].Key
		}
		return out[i].Score > out[j].Score
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// Keys lists every tracked entity key of a type (used by the API to resolve opaque refs).
func (e *Engine) Keys(typ string) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := []string{}
	for key, st := range e.states {
		if typ == "" || string(st.Entity.Type) == typ {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// Detail returns the full view of one entity (aliases resolve to the canonical entity).
func (e *Engine) Detail(key string, at time.Time) (EntityDetail, bool) {
	if e.Resolver != nil {
		key = e.Resolver.Canonical(key)
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	st := e.states[key]
	if st == nil {
		return EntityDetail{}, false
	}
	related := []string{}
	for k := range e.related[key] {
		related = append(related, k)
	}
	sort.Strings(related)
	aliases := []string{}
	if e.Resolver != nil {
		aliases = e.Resolver.Aliases(key)
	}
	timeline := append([]TimelinePoint(nil), st.Timeline...)
	// Close the timeline at `at` with the current decayed score.
	if b := st.Effective(at, e.P); len(timeline) == 0 || timeline[len(timeline)-1].At.Before(at.Truncate(e.P.TimelineBucket)) {
		timeline = append(timeline, TimelinePoint{At: at.Truncate(e.P.TimelineBucket), Score: b.Effective})
	}
	return EntityDetail{
		EntitySummary: e.summary(key, st, at),
		Contributors:  append([]Contribution(nil), st.Contributors...),
		Timeline:      timeline,
		Aliases:       aliases,
		Related:       related,
	}, true
}

// Stats is a consistent copy of the engine counters.
type Stats struct {
	Observations       int
	Duplicates         int
	DuplicatesBySource map[string]int
	OutOfOrder         int
	Suppressed         int
	CandidatesOpened   int
	CandidatesUpdated  int
	ShadowCandidates   int
	BySource           map[string]int
	ByStage            map[string]int
}

// Stats copies the counters under the lock.
func (e *Engine) Stats() Stats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	st := Stats{Observations: e.Observations, Duplicates: e.Duplicates, Suppressed: e.SuppressedObs,
		OutOfOrder: e.OutOfOrder, CandidatesOpened: e.CandidatesOpened, CandidatesUpdated: e.CandidatesUpdated,
		ShadowCandidates: e.ShadowCandidates, DuplicatesBySource: map[string]int{}, BySource: map[string]int{}, ByStage: map[string]int{}}
	for k, v := range e.DuplicatesBySource {
		st.DuplicatesBySource[k] = v
	}
	for k, v := range e.BySource {
		st.BySource[k] = v
	}
	for k, v := range e.ByStage {
		st.ByStage[k] = v
	}
	return st
}

// GroupStats reports the grouping of Wazuh alerts at or above GroupMinLevel.
func (e *Engine) GroupStats() (items, groups int, reduction float64) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.grouper.Items, e.grouper.Groups, e.grouper.Reduction()
}

// EntityCounts counts tracked entities by type.
func (e *Engine) EntityCounts() map[string]int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := map[string]int{}
	for _, st := range e.states {
		out[string(st.Entity.Type)]++
	}
	return out
}

// Prune drops cold entities, closed candidate windows and old dedup ids.
func (e *Engine) Prune(at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for key, st := range e.states {
		if at.Sub(st.LastSeen) > e.P.PruneAfter && st.Effective(at, e.P).Effective < 0.5 {
			delete(e.states, key)
			delete(e.history, key)
			delete(e.related, key)
			delete(e.episodes, key)
		}
	}
	for key, list := range e.open {
		kept := list[:0]
		for _, c := range list {
			if at.Sub(c.LastSeen) <= e.P.GroupMaxSpan {
				kept = append(kept, c)
			}
		}
		if len(kept) == 0 {
			delete(e.open, key)
		} else {
			e.open[key] = kept
		}
	}
	for id, t := range e.seen {
		if at.Sub(t) > e.horizon+time.Hour {
			delete(e.seen, id)
		}
	}
	// Episodes outside every pattern window can no longer absorb late evidence.
	for key, list := range e.patternCands {
		kept := list[:0]
		for _, c := range list {
			if at.Sub(c.LastSeen) <= e.horizon {
				kept = append(kept, c)
			} else {
				delete(e.stageObs, c.ID)
			}
		}
		if len(kept) == 0 {
			delete(e.patternCands, key)
		} else {
			e.patternCands[key] = kept
		}
	}
	for key, known := range e.locations {
		for loc, t := range known {
			if at.Sub(t) > locationBaseline {
				delete(known, loc)
			}
		}
		if len(known) == 0 {
			delete(e.locations, key)
		}
	}
	for key := range e.prov {
		if e.states[key] == nil {
			delete(e.prov, key)
		}
	}
	// Candidate history is bounded: keep the most recent 5000.
	if len(e.candidates) > 5000 {
		for _, c := range e.candidates[:len(e.candidates)-5000] {
			delete(e.byID, c.ID)
			delete(e.stageObs, c.ID)
			delete(e.members.memory, c.ID)
			if e.members.dir == "" {
				delete(e.members.byAlert, c.AlertID)
				delete(e.members.emitted, c.ID)
			}
			delete(e.members.memory, c.ID+".obs")
		}
		e.candidates = append([]*model.Candidate(nil), e.candidates[len(e.candidates)-5000:]...)
	}
}

func mergeIDs(first, second []string, limit int) []string {
	out := []string{}
	for _, list := range [][]string{first, second} {
		for _, id := range list {
			if len(out) < limit && !contains(out, id) {
				out = append(out, id)
			}
		}
	}
	return out
}

// nextSteps is the investigation checklist shown with each candidate.
func nextSteps(patternID string) []string {
	switch patternID {
	case "edge-to-ssh":
		return []string{
			"Confirmar en Cloudflare los bloqueos WAF y las rutas atacadas por la IP.",
			"Revisar en el nodo los intentos SSH y si hubo algun acceso exitoso desde la IP.",
			"Proponer bloqueo de la IP en el borde y en el grupo de seguridad (B89 Respond, con aprobacion).",
		}
	case "credential-to-privilege":
		return []string{
			"Validar con la persona si reconoce los inicios de sesion y el cambio privilegiado.",
			"Revisar en CloudTrail/Entra que permisos se otorgaron y a quien; revertir si no esta autorizado.",
			"Revocar sesiones y rotar credenciales del usuario si el acceso no es legitimo.",
		}
	case "ssh-bruteforce-then-access":
		return []string{
			"Revisar la sesion SSH aceptada (usuario, hora, comandos) en el host.",
			"Aislar el host o bloquear la IP si el acceso no es legitimo (con aprobacion).",
		}
	case "endpoint-protection-and-malware":
		return []string{
			"Verificar en GravityZone quien desactivo la proteccion y el estado de la deteccion.",
			"Reactivar la proteccion y aislar el equipo si la infeccion sigue activa (con aprobacion).",
		}
	case "access-then-audit-tamper":
		return []string{
			"Restaurar de inmediato la auditoria afectada (CloudTrail/GuardDuty).",
			"Revisar las acciones del usuario durante la ventana sin auditoria y revocar sus sesiones.",
		}
	}
	return []string{
		"Revisar los aportes principales y la linea de tiempo de la entidad.",
		"Agrupar en un incidente si las alertas relacionadas comparten causa; registrar el veredicto para el ciclo de feedback.",
	}
}
