// Package resolve turns raw Wazuh alert documents (as served by the B89 wazuh-gateway) into
// observations with canonical entities, and keeps the alias graph that links identifiers of
// the same host (agent name, private IP, EC2 instance id, Bitdefender endpoint) and of the
// same person (UPN/e-mail, AWS SSO role session, IAM user via configured aliases).
//
// Resolution rules (documented in the tests):
//   - users: lower-cased UPN/e-mail; SSO sessions "assumed-role/<role>/<email>" resolve to the
//     e-mail; IAM users "user/<name>" resolve to the e-mail when the name is one, otherwise to
//     "iam:<account>/<name>" unless an explicit alias maps them; "DOMAIN\name" maps to
//     name@<default domain> when one is configured; local Linux accounts are scoped to their
//     host ("local:<host>/<name>"); attacker-chosen names of failed SSH logins are ignored.
//   - hosts: first DNS label, lower-cased. Identifiers seen together in one alert are merged
//     (union-find). Only private/CGNAT IPs alias a host: a public IP may be NAT shared.
//   - ip: canonical textual form (netip); private IPs that alias a host resolve to the host.
//   - cloud: AWS ARNs (roles, resources), S3 buckets, security groups, Cloudflare zones.
package resolve

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/model"
)

// Doc is a decoded Wazuh alert `_source`.
type Doc = map[string]any

// Resolver is safe for concurrent use.
type Resolver struct {
	mu            sync.Mutex
	parent        map[string]string // union-find over entity keys (hosts and private IPs)
	rank          map[string]int
	userAliases   map[string]string // raw (lower) -> canonical user value
	defaultDomain string
	merges        []Merge
}

// Merge reports that `From` became an alias of `Into` (the engine merges state).
type Merge struct{ From, Into string }

// New builds a resolver. aliases maps raw identifiers (e.g. "iam:061098277310/ci-deploy" or
// "jdoe") to a canonical user value (e.g. "svc-ci@b89.io").
func New(aliases map[string]string, defaultDomain string) *Resolver {
	r := &Resolver{
		parent:        map[string]string{},
		rank:          map[string]int{},
		userAliases:   map[string]string{},
		defaultDomain: strings.ToLower(strings.TrimSpace(defaultDomain)),
	}
	for k, v := range aliases {
		r.userAliases[strings.ToLower(strings.TrimSpace(k))] = strings.ToLower(strings.TrimSpace(v))
	}
	return r
}

// DrainMerges returns and clears alias merges observed since the last call.
func (r *Resolver) DrainMerges() []Merge {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.merges
	r.merges = nil
	return out
}

// typeRank decides which identifier names the merged host: agent/endpoint names beat
// instance ids, which beat IPs.
func typeRank(key string) int {
	switch {
	case strings.HasPrefix(key, "host:i-"):
		return 2
	case strings.HasPrefix(key, "host:"):
		return 3
	case strings.HasPrefix(key, "ip:"):
		return 1
	}
	return 0
}

func (r *Resolver) find(k string) string {
	p, ok := r.parent[k]
	if !ok {
		return k
	}
	if p == k {
		return k
	}
	root := r.find(p)
	r.parent[k] = root
	return root
}

func (r *Resolver) union(a, b string) {
	ra, rb := r.find(a), r.find(b)
	if ra == rb {
		r.parent[a], r.parent[b] = ra, ra
		return
	}
	// The more descriptive identifier becomes the root (stable display name).
	into, from := ra, rb
	if typeRank(rb) > typeRank(ra) || (typeRank(rb) == typeRank(ra) && rb < ra) {
		into, from = rb, ra
	}
	r.parent[from] = into
	if _, ok := r.parent[into]; !ok {
		r.parent[into] = into
	}
	r.merges = append(r.merges, Merge{From: from, Into: into})
}

// Canonical resolves an entity key through the alias graph.
func (r *Resolver) Canonical(key string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.find(key)
}

// Aliases lists every key that resolves to canonical (including itself).
func (r *Resolver) Aliases(canonical string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []string{}
	for k := range r.parent {
		if r.find(k) == canonical && k != canonical {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------------------------
// Field access helpers

func get(doc Doc, path string) any {
	var cur any = doc
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		// Wazuh flattens some keys with dots (e.g. "data.aws.source_ip" can be nested or not).
		cur, ok = m[part]
		if !ok {
			return nil
		}
	}
	return cur
}

func str(doc Doc, path string) string {
	switch v := get(doc, path).(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

func strs(doc Doc, path string) []string {
	switch v := get(doc, path).(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v != "" {
			return []string{v}
		}
	}
	return nil
}

func truthy(doc Doc, path string) bool {
	switch v := get(doc, path).(type) {
	case bool:
		return v
	case string:
		l := strings.ToLower(v)
		return l == "true" || l == "yes" || l == "1"
	case float64:
		return v != 0
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// Normalizers

var (
	emailRe       = regexp.MustCompile(`^[a-z0-9._%+\-']+@[a-z0-9.\-]+\.[a-z]{2,}$`)
	instanceRe    = regexp.MustCompile(`\bi-[0-9a-f]{8,17}\b`)
	ec2HostRe     = regexp.MustCompile(`^ip-(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})$`)
	junkUsers     = map[string]bool{"": true, "-": true, "n/a": true, "unknown": true, "system": true, "local service": true, "network service": true, "anonymous logon": true, "(unknown user)": true}
	cgnat         = netip.MustParsePrefix("100.64.0.0/10")
	privilegedAWS = map[string]bool{
		"AttachUserPolicy": true, "AttachRolePolicy": true, "AttachGroupPolicy": true,
		"PutUserPolicy": true, "PutRolePolicy": true, "PutGroupPolicy": true,
		"CreateAccessKey": true, "CreateUser": true, "CreateLoginProfile": true,
		"UpdateLoginProfile": true, "AddUserToGroup": true, "UpdateAssumeRolePolicy": true,
		"CreatePolicyVersion": true, "SetDefaultPolicyVersion": true, "CreateRole": true,
		"DeactivateMFADevice": true, "DeleteRolePermissionsBoundary": true,
		"DeleteUserPermissionsBoundary": true, "PassRole": true, "AssumeRoot": true,
	}
	tamperAWS = map[string]bool{
		"StopLogging": true, "DeleteTrail": true, "UpdateTrail": true, "PutEventSelectors": true,
		"DeleteDetector": true, "DisableSecurityHub": true, "DeleteFlowLogs": true,
		"DeleteConfigurationRecorder": true, "StopConfigurationRecorder": true,
	}
)

// NormalizeIP returns the canonical form of an IP, or "" when it is not one.
func NormalizeIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		raw = raw[1 : len(raw)-1]
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return ""
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() || addr.IsLoopback() {
		return ""
	}
	return addr.String()
}

// IsInternalIP reports private, link-local or CGNAT addresses (eligible as host aliases).
func IsInternalIP(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return addr.IsPrivate() || addr.IsLinkLocalUnicast() || cgnat.Contains(addr)
}

// NormalizeHost returns the first DNS label of a host name, lower-cased.
func NormalizeHost(raw string) string {
	h := strings.ToLower(strings.TrimSpace(raw))
	if h == "" || h == "-" || h == "localhost" {
		return ""
	}
	if NormalizeIP(h) != "" {
		return ""
	}
	if m := instanceRe.FindString(h); m != "" && m == h {
		return m
	}
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	if strings.ContainsAny(h, " /\\") {
		return ""
	}
	return h
}

// NormalizeUser resolves a raw principal to a canonical user value, or "".
func (r *Resolver) NormalizeUser(raw string) string {
	u, _, _ := r.normalizeUser(raw)
	return u
}

// normalizeUser also reports how the value was obtained. Exact provider identifiers
// (UPN/e-mail, ARN structure) and explicitly configured aliases are high confidence; a
// default-domain completion is medium; a bare name is low and never pivots a sequence.
func (r *Resolver) normalizeUser(raw string) (string, string, model.Confidence) {
	u := strings.ToLower(strings.TrimSpace(raw))
	if junkUsers[u] || strings.HasSuffix(u, "$") {
		return "", "", ""
	}
	if alias, ok := r.userAliases[u]; ok {
		return alias, "alias", model.ConfidenceHigh
	}
	if strings.HasPrefix(u, "arn:aws:") {
		return r.userFromARN(u), "exact", model.ConfidenceHigh
	}
	if i := strings.IndexByte(u, '\\'); i > 0 && i < len(u)-1 {
		name := u[i+1:]
		if alias, ok := r.userAliases[name]; ok {
			return alias, "alias", model.ConfidenceHigh
		}
		if r.defaultDomain != "" {
			return name + "@" + r.defaultDomain, "domain_default", model.ConfidenceMedium
		}
		return name, "bare_name", model.ConfidenceLow
	}
	if emailRe.MatchString(u) {
		return u, "exact", model.ConfidenceHigh
	}
	if strings.ContainsAny(u, " \t") || len(u) > 128 {
		return "", "", ""
	}
	return u, "bare_name", model.ConfidenceLow
}

func (r *Resolver) userFromARN(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return ""
	}
	account, resource := parts[4], parts[5]
	switch {
	case resource == "root":
		return "aws-root:" + account
	case strings.HasPrefix(resource, "assumed-role/"):
		seg := strings.Split(resource, "/")
		if len(seg) >= 3 {
			session := seg[len(seg)-1]
			if emailRe.MatchString(session) {
				return session
			}
			key := "iam:" + account + "/" + seg[1] + "/" + session
			if alias, ok := r.userAliases[key]; ok {
				return alias
			}
			return key
		}
	case strings.HasPrefix(resource, "user/"):
		name := resource[strings.LastIndexByte(resource, '/')+1:]
		if emailRe.MatchString(name) {
			return name
		}
		key := "iam:" + account + "/" + name
		if alias, ok := r.userAliases[key]; ok {
			return alias
		}
		if alias, ok := r.userAliases[name]; ok {
			return alias
		}
		return key
	}
	return ""
}

// roleFromARN extracts the IAM role ARN of an assumed-role session as a cloud resource.
func roleFromARN(arn string) string {
	arn = strings.ToLower(arn)
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || !strings.HasPrefix(parts[5], "assumed-role/") {
		return ""
	}
	seg := strings.Split(parts[5], "/")
	if len(seg) < 2 {
		return ""
	}
	return "arn:aws:iam::" + parts[4] + ":role/" + seg[1]
}

// ---------------------------------------------------------------------------------------------
// Observation building

var tacticOrder = []string{
	"reconnaissance", "resource-development", "initial-access", "execution", "persistence",
	"privilege-escalation", "defense-evasion", "credential-access", "discovery",
	"lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
}

// TacticIndex returns the kill-chain position of a normalized tactic, or -1.
func TacticIndex(t string) int {
	for i, v := range tacticOrder {
		if v == t {
			return i
		}
	}
	return -1
}

func normalizeTactic(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	t = strings.ReplaceAll(t, " ", "-")
	t = strings.ReplaceAll(t, "_", "-")
	if t == "command-and-control" || TacticIndex(t) >= 0 {
		return t
	}
	return ""
}

func hasAny(set map[string]bool, values ...string) bool {
	for _, v := range values {
		if set[v] {
			return true
		}
	}
	return false
}

// SourceOf names the telemetry source of a document (vendor, then rule groups, then decoder).
func SourceOf(doc Doc, groups map[string]bool) string {
	if v := strings.ToLower(str(doc, "data.b89.vendor")); v != "" {
		return v
	}
	switch {
	case groups["office365"]:
		return "m365"
	case groups["amazon"] || groups["aws"] || str(doc, "data.aws.eventSource") != "":
		return "aws"
	case groups["cloudflare"]:
		return "cloudflare"
	case groups["bitdefender"]:
		return "bitdefender"
	case groups["sshd"]:
		return "linux-ssh"
	case groups["windows"] || str(doc, "data.win.system.eventID") != "":
		return "windows"
	case groups["web"] || groups["accesslog"] || groups["nginx"]:
		return "web"
	case groups["syscheck"]:
		return "fim"
	}
	if d := strings.ToLower(str(doc, "decoder.name")); d != "" {
		return d
	}
	return "wazuh"
}

// Observe converts one Wazuh alert into an observation. ok is false when the document has
// no usable timestamp or rule.
func (r *Resolver) Observe(doc Doc) (model.Observation, bool) {
	ts := str(doc, "timestamp")
	if ts == "" {
		ts = str(doc, "@timestamp")
	}
	at, err := parseTime(ts)
	if err != nil {
		return model.Observation{}, false
	}
	ruleID := str(doc, "rule.id")
	if ruleID == "" {
		return model.Observation{}, false
	}
	level := 0
	if lv, ok := get(doc, "rule.level").(float64); ok {
		level = int(lv)
	}
	groupList := strs(doc, "rule.groups")
	groups := map[string]bool{}
	for _, g := range groupList {
		groups[strings.ToLower(g)] = true
	}
	tactics := []string{}
	seenTactic := map[string]bool{}
	for _, t := range strs(doc, "rule.mitre.tactic") {
		if n := normalizeTactic(t); n != "" && !seenTactic[n] {
			seenTactic[n] = true
			tactics = append(tactics, n)
		}
	}
	obs := model.Observation{
		ID:          str(doc, "id"),
		Time:        at,
		RuleID:      ruleID,
		Level:       level,
		Description: str(doc, "rule.description"),
		Groups:      groupList,
		Tactics:     tactics,
		Source:      SourceOf(doc, groups),
		IngestedAt:  at,
		TimeSource:  "ingest",
		Location:    strings.ToLower(str(doc, "GeoLocation.country_name")),
		Provenance:  map[string]model.Provenance{},
	}
	// Tenant and session provenance are taken only from provider-owned identifiers.
	if organization := str(doc, "data.office365.OrganizationId"); organizationID.MatchString(organization) {
		obs.ProviderTenant = "m365:" + strings.ToLower(organization)
		if session := str(doc, "data.office365.SessionId"); organizationID.MatchString(session) {
			obs.SessionRef = fmt.Sprintf("%x", sha256.Sum256([]byte(obs.ProviderTenant+"/"+strings.ToLower(session))))
		}
	}
	if obs.ID == "" {
		obs.ID = ruleID + "@" + at.UTC().Format(time.RFC3339Nano)
	}
	// Sequences are evaluated on provider event time. A provider clock in the future of
	// ingestion, or older than the late-arrival bound, is not trusted.
	for _, field := range providerTimeFields {
		raw := str(doc, field)
		if raw == "" {
			continue
		}
		if pt, err := parseTime(raw); err == nil && !pt.After(at.Add(maxProviderSkew)) && !pt.Before(at.Add(-MaxLateArrival)) {
			obs.Time, obs.TimeSource = pt, "provider"
		}
		break
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	ents := map[string]model.Entity{}
	addWith := func(e model.Entity, field, method string, confidence model.Confidence) {
		if e.Value == "" {
			return
		}
		ents[e.Key()] = e
		if prev, ok := obs.Provenance[e.Key()]; ok && prev.Confidence.Rank() >= confidence.Rank() {
			return
		}
		obs.Provenance[e.Key()] = model.Provenance{Key: e.Key(), Field: field, Method: method, Confidence: confidence}
	}
	add := func(e model.Entity) { addWith(e, "", "exact", model.ConfidenceHigh) }
	// hostProvenance: an FQDN truncated to its first label may collide across domains.
	hostProvenance := func(raw string) (string, model.Confidence) {
		if NormalizeHost(raw) != strings.ToLower(strings.TrimSpace(raw)) {
			return "first_label", model.ConfidenceMedium
		}
		return "exact", model.ConfidenceHigh
	}
	hostField, hostRaw := "", ""

	// --- hosts: every identifier of the reporting/affected machine, merged together.
	hostIDs := []string{}
	addHost := func(field, raw string) {
		if h := NormalizeHost(raw); h != "" {
			if hostField == "" {
				hostField, hostRaw = field, raw
			}
			hostIDs = append(hostIDs, "host:"+h)
			if m := ec2HostRe.FindStringSubmatch(h); m != nil {
				hostIDs = append(hostIDs, "ip:"+m[1]+"."+m[2]+"."+m[3]+"."+m[4])
			}
		}
	}
	addHostIP := func(raw string) {
		if ip := NormalizeIP(raw); ip != "" && IsInternalIP(ip) {
			hostIDs = append(hostIDs, "ip:"+ip)
		}
	}
	agentID := str(doc, "agent.id")
	agentName := str(doc, "agent.name")
	vendor := obs.Source
	isProvider := vendor == "cloudflare" || vendor == "aws" || vendor == "m365" || vendor == "snyk" || vendor == "bitdefender"
	// The manager (agent 000) is only the collector for provider events: it is not the
	// affected host there, so it is not attached to them.
	if agentName != "" && !(isProvider && (agentID == "000" || agentID == "")) {
		addHost("agent.name", agentName)
		addHostIP(str(doc, "agent.ip"))
	}
	if h := str(doc, "predecoder.hostname"); h != "" && !isProvider {
		addHost("predecoder.hostname", h)
	}
	if bd := str(doc, "data.bitdefender.endpoint.name"); bd != "" {
		// A Bitdefender endpoint is its own host group (name, FQDN, IP).
		group := []string{}
		if h := NormalizeHost(bd); h != "" {
			group = append(group, "host:"+h)
		}
		if h := NormalizeHost(str(doc, "data.bitdefender.endpoint.fqdn")); h != "" {
			group = append(group, "host:"+h)
		}
		if ip := NormalizeIP(str(doc, "data.bitdefender.endpoint.ip")); ip != "" && IsInternalIP(ip) {
			group = append(group, "ip:"+ip)
		}
		r.link(group)
		if len(group) > 0 {
			method, confidence := hostProvenance(bd)
			addWith(entityOf(r.find(group[0])), "data.bitdefender.endpoint.name", method, confidence)
		}
	}
	if comp := str(doc, "data.win.system.computer"); comp != "" {
		addHost("data.win.system.computer", comp)
	}
	for _, field := range []string{"data.aws.instance_id", "data.aws.instanceId", "data.aws.resource.instanceDetails.instanceId"} {
		if id := strings.ToLower(str(doc, field)); instanceRe.MatchString(id) {
			if hostField == "" {
				hostField, hostRaw = field, instanceRe.FindString(id)
			}
			hostIDs = append(hostIDs, "host:"+instanceRe.FindString(id))
		}
	}
	r.link(hostIDs)
	if len(hostIDs) > 0 {
		method, confidence := "host_alias", model.ConfidenceMedium // only agent.ip seen
		if hostField != "" {
			method, confidence = hostProvenance(hostRaw)
		}
		addWith(entityOf(r.find(hostIDs[0])), hostField, method, confidence)
	}

	// --- users
	failedSSH := groups["sshd"] && (groups["authentication_failed"] || groups["invalid_login"] || groups["authentication_failures"])
	hostForLocal := ""
	if len(hostIDs) > 0 {
		hostForLocal = strings.TrimPrefix(r.find(hostIDs[0]), "host:")
	}
	for _, field := range []string{
		"data.office365.UserId", "data.aws.principal_arn", "data.aws.userIdentity.arn",
		"data.aws.principal", "data.aws.userIdentity.userName", "data.cloudflare.audit.actor_email",
		"data.win.eventdata.targetUserName", "data.win.eventdata.subjectUserName",
		"data.srcuser", "data.dstuser", "data.user",
	} {
		raw := str(doc, field)
		if raw == "" {
			continue
		}
		if failedSSH && (field == "data.srcuser" || field == "data.dstuser" || field == "data.user") {
			continue // attacker-chosen names of failed logins are not identities
		}
		if field == "data.aws.principal" && str(doc, "data.aws.principal_arn") != "" {
			continue
		}
		if field == "data.win.eventdata.subjectUserName" && str(doc, "data.win.eventdata.targetUserName") != "" {
			continue
		}
		u, method, confidence := r.normalizeUser(raw)
		if u == "" {
			continue
		}
		local := (field == "data.srcuser" || field == "data.dstuser" || field == "data.user") && !strings.Contains(u, "@")
		if local {
			if _, aliased := r.userAliases[strings.ToLower(raw)]; !aliased {
				if hostForLocal == "" {
					continue
				}
				u = "local:" + hostForLocal + "/" + u
				method, confidence = "host_scoped", model.ConfidenceMedium
			}
		}
		addWith(model.Entity{Type: model.EntityUser, Value: u}, field, method, confidence)
		if strings.HasPrefix(strings.ToLower(raw), "arn:aws:") {
			if role := roleFromARN(raw); role != "" {
				add(model.Entity{Type: model.EntityCloud, Value: role})
			}
		}
	}

	// --- source IPs (actors). A private IP known as a host resolves to that host.
	for _, field := range []string{
		"data.srcip", "data.aws.source_ip", "data.aws.sourceIPAddress", "data.office365.ClientIP",
		"data.office365.ActorIpAddress", "data.cloudflare.firewall.client_ip",
		"data.cloudflare.http.client_ip", "data.cloudflare.dns.client_ip",
		"data.cloudflare.audit.actor_ip", "data.win.eventdata.ipAddress", "data.src_ip",
	} {
		ip := NormalizeIP(stripPort(str(doc, field)))
		if ip == "" {
			continue
		}
		key := r.find("ip:" + ip)
		if key == "ip:"+ip {
			addWith(entityOf(key), field, "exact", model.ConfidenceHigh)
		} else {
			// A private IP aliasing a host: the host is inferred from co-occurrence.
			addWith(entityOf(key), field, "host_alias", model.ConfidenceMedium)
		}
	}

	// --- cloud resources
	if zone := strings.ToLower(str(doc, "data.cloudflare.zone_name")); zone != "" {
		add(model.Entity{Type: model.EntityCloud, Value: "cloudflare:zone/" + zone})
	}
	if project := strings.ToLower(str(doc, "data.snyk.project.name")); project != "" {
		add(model.Entity{Type: model.EntityCloud, Value: "snyk:project/" + project})
	}
	if params := str(doc, "data.aws.request_parameters"); params != "" {
		for _, re := range []*regexp.Regexp{bucketRe, sgRe} {
			if m := re.FindStringSubmatch(params); m != nil {
				add(model.Entity{Type: model.EntityCloud, Value: m[1]})
			}
		}
	}
	for _, arn := range strs(doc, "data.aws.resources") {
		if strings.HasPrefix(strings.ToLower(arn), "arn:aws:") {
			add(model.Entity{Type: model.EntityCloud, Value: strings.ToLower(arn)})
		}
	}

	keys := make([]string, 0, len(ents))
	for k := range ents {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		obs.Entities = append(obs.Entities, ents[k])
	}
	obs.Stages, obs.StageCriteria = classify(doc, groups, obs)
	return obs, true
}

// MaxLateArrival bounds how old a provider event time may be relative to ingestion.
const MaxLateArrival = 7 * 24 * time.Hour

const maxProviderSkew = 5 * time.Minute

var providerTimeFields = []string{
	"data.b89.event_time", "data.office365.CreationTime", "data.aws.eventTime", "data.aws.event_time",
	"data.win.system.systemTime",
}

// Heartbeat is a collector heartbeat read from the alert stream (b89_collector.py).
type Heartbeat struct {
	Vendor      string
	Outcome     string
	FinishedAt  time.Time
	LagSeconds  *float64
	Position    string
	ItemsRead   int
	CursorMoved bool
}

// ParseHeartbeat recognizes a collector heartbeat. Heartbeats are coverage evidence, never
// observations: they carry no entity and must not add risk.
func ParseHeartbeat(doc Doc) (Heartbeat, bool) {
	if str(doc, "data.b89.event_type") != "source_heartbeat" {
		return Heartbeat{}, false
	}
	hb := Heartbeat{
		Vendor:      strings.ToLower(str(doc, "data.b89.vendor")),
		Outcome:     str(doc, "data.b89.heartbeat.outcome"),
		Position:    str(doc, "data.b89.heartbeat.cursor_position"),
		CursorMoved: truthy(doc, "data.b89.heartbeat.cursor_advanced"),
	}
	if hb.Vendor == "" {
		return Heartbeat{}, false
	}
	if t, err := parseTime(str(doc, "data.b89.heartbeat.finished_at")); err == nil {
		hb.FinishedAt = t
	}
	if v, ok := get(doc, "data.b89.heartbeat.provider_lag_seconds").(float64); ok && v >= 0 {
		hb.LagSeconds = &v
	}
	if v, ok := get(doc, "data.b89.heartbeat.items_fetched").(float64); ok && v >= 0 {
		hb.ItemsRead = int(v)
	}
	return hb, true
}

var (
	organizationID = regexp.MustCompile(`(?i)^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	bucketRe       = regexp.MustCompile(`"bucketName"\s*:\s*"([a-z0-9.\-]{3,63})"`)
	sgRe           = regexp.MustCompile(`"groupId"\s*:\s*"(sg-[0-9a-f]{8,17})"`)
)

func (r *Resolver) link(keys []string) {
	for i := 1; i < len(keys); i++ {
		r.union(keys[0], keys[i])
	}
	if len(keys) == 1 {
		if _, ok := r.parent[keys[0]]; !ok {
			r.parent[keys[0]] = keys[0]
		}
	}
}

func entityOf(key string) model.Entity {
	e, _ := model.ParseKey(key)
	return e
}

func stripPort(v string) string {
	if endpoint, err := netip.ParseAddrPort(strings.TrimSpace(v)); err == nil {
		return endpoint.Addr().String()
	}
	return v
}

func parseTime(v string) (time.Time, error) {
	// Zone-less timestamps (Office 365 CreationTime) are UTC by provider contract.
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000-0700", "2006-01-02T15:04:05.000Z0700", "2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, &time.ParseError{Value: v}
}

var (
	// identityO365 are account credential / authentication-method changes in Entra/M365.
	identityO365 = map[string]bool{
		"Reset user password.": true, "Change user password.": true, "Set force change user password.": true,
		"User registered security info": true, "User deleted security info": true,
		"User changed default security info": true, "Admin registered security info": true,
		"Admin deleted security info": true, "Disable Strong Authentication.": true,
		"Update StsRefreshTokenValidFrom Timestamp.": true,
	}
	identityAWS = map[string]bool{
		"UpdateLoginProfile": true, "CreateLoginProfile": true, "DeactivateMFADevice": true,
		"DeleteVirtualMFADevice": true, "EnableMFADevice": true, "ResyncMFADevice": true,
		"ChangePassword": true, "ResetServiceSpecificCredential": true,
	}
	endpointSources = map[string]bool{"windows": true, "bitdefender": true, "linux-ssh": true, "sysmon": true}
)

// classify maps the alert to the multi-stage pattern vocabulary and records, per stage, the
// field/value that satisfied it (shown to the analyst; never raw payload).
func classify(doc Doc, groups map[string]bool, obs model.Observation) ([]model.Stage, map[model.Stage]string) {
	out := []model.Stage{}
	criteria := map[model.Stage]string{}
	addStage := func(s model.Stage, why string) {
		if _, ok := criteria[s]; ok {
			return
		}
		criteria[s] = why
		out = append(out, s)
	}
	action := strings.ToLower(str(doc, "data.cloudflare.firewall.action"))
	if obs.Source == "cloudflare" && (action == "block" || action == "drop" || action == "managed_challenge" || action == "challenge" || action == "jschallenge") {
		addStage(model.StageEdgeWAFBlock, "data.cloudflare.firewall.action="+action)
	}
	if obs.Source == "cloudflare" && obs.RuleID == "101740" {
		addStage(model.StageEdgeScan, "regla 101740 (pico de ataques WAF)") // WAF attack surge = scanning at the edge
	}
	webScan := (groups["web"] || groups["accesslog"] || groups["nginx"] || groups["apache"]) &&
		(groups["attack"] || groups["recon"] || groups["web_scan"] || groups["invalid_access"] || groups["sql_injection"] || groups["multiple_web_errors"])
	if webScan || hasAny(groups, "web_scan", "scan", "recon") {
		addStage(model.StageEdgeScan, "rule.groups de escaneo web/recon")
	}
	if groups["sshd"] && (groups["authentication_failed"] || groups["invalid_login"] || groups["authentication_failures"] || groups["brute_force"]) {
		addStage(model.StageSSHBruteForce, "rule.groups sshd + fallo de autenticación")
	}
	if groups["sshd"] && groups["authentication_success"] {
		addStage(model.StageSSHSuccess, "rule.groups sshd + authentication_success")
	}
	consoleLogin := strings.ToLower(str(doc, "data.aws.console_login"))
	op := str(doc, "data.office365.Operation")
	switch {
	case op == "UserLoginFailed":
		addStage(model.StageAuthFailure, "data.office365.Operation=UserLoginFailed")
	case consoleLogin == "failure":
		addStage(model.StageAuthFailure, "data.aws.console_login=failure")
	case hasAny(groups, "authentication_failed", "authentication_failures", "win_authentication_failed", "invalid_login"):
		addStage(model.StageAuthFailure, "rule.groups de fallo de autenticación")
	}
	switch {
	case op == "UserLoggedIn":
		addStage(model.StageAuthSuccess, "data.office365.Operation=UserLoggedIn")
	case consoleLogin == "success":
		addStage(model.StageAuthSuccess, "data.aws.console_login=success")
	case groups["authentication_success"]:
		addStage(model.StageAuthSuccess, "rule.groups authentication_success")
	}
	eventName := str(doc, "data.aws.event_name")
	if eventName == "" {
		eventName = str(doc, "data.aws.eventName")
	}
	switch {
	case privilegedAWS[eventName]:
		addStage(model.StagePrivilegedChange, "data.aws.eventName="+eventName)
	case op == "Add member to role." || op == "Add member to group.":
		addStage(model.StagePrivilegedChange, "data.office365.Operation="+op)
	case hasAny(groups, "b89_privilege_escalation", "group_changed", "adduser", "sudo_privilege"):
		addStage(model.StagePrivilegedChange, "rule.groups de cambio privilegiado")
	}
	for _, t := range obs.Tactics {
		if t == "privilege-escalation" && (obs.Source == "aws" || obs.Source == "m365" || obs.Source == "entra") {
			addStage(model.StagePrivilegedChange, "rule.mitre.tactic=privilege-escalation en "+obs.Source)
		}
	}
	switch {
	case identityO365[op]:
		addStage(model.StageIdentityChange, "data.office365.Operation="+op)
	case identityAWS[eventName]:
		addStage(model.StageIdentityChange, "data.aws.eventName="+eventName)
	case groups["b89_identity_change"]:
		addStage(model.StageIdentityChange, "rule.groups b89_identity_change")
	}
	if tamperAWS[eventName] {
		addStage(model.StageCloudTamper, "data.aws.eventName="+eventName)
	}
	if truthy(doc, "data.bitdefender.endpoint.antimalware_disabled") {
		addStage(model.StageProtectionOff, "data.bitdefender.endpoint.antimalware_disabled=true")
	} else if truthy(doc, "data.bitdefender.endpoint.atc_disabled") {
		addStage(model.StageProtectionOff, "data.bitdefender.endpoint.atc_disabled=true")
	}
	switch {
	case truthy(doc, "data.bitdefender.endpoint.infected"):
		addStage(model.StageEndpointMalware, "data.bitdefender.endpoint.infected=true")
	case truthy(doc, "data.bitdefender.endpoint.detection"):
		addStage(model.StageEndpointMalware, "data.bitdefender.endpoint.detection=true")
	case hasAny(groups, "malware", "virus", "virustotal"):
		addStage(model.StageEndpointMalware, "rule.groups de malware")
	}
	// Endpoint activity requires both a user and a managed host on the same event from an
	// endpoint source; failed logons are attempts, not activity of the account.
	if endpointSources[obs.Source] {
		_, failed := criteria[model.StageAuthFailure]
		_, brute := criteria[model.StageSSHBruteForce]
		hasUser, hasHost := false, false
		for _, e := range obs.Entities {
			hasUser = hasUser || e.Type == model.EntityUser
			hasHost = hasHost || e.Type == model.EntityHost
		}
		if hasUser && hasHost && !failed && !brute {
			addStage(model.StageEndpointActivity, "usuario y equipo gestionado en el mismo evento ("+obs.Source+", regla "+obs.RuleID+")")
		}
	}
	return out, criteria
}
