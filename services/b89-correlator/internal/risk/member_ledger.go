package risk

import (
	"encoding/json"
	"errors"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/model"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var candidateKey = regexp.MustCompile("^rc_[0-9a-f]{24}$")

// A ledger belongs to one correlator. The engine mutex serializes updates. Each
// snapshot is immutable until a complete replacement is durably installed.
type memberLedger struct {
	dir     string
	memory  map[string][]string
	byAlert map[string]string
	emitted map[string]string
}

func newMemberLedger() *memberLedger {
	return &memberLedger{memory: make(map[string][]string), byAlert: make(map[string]string), emitted: make(map[string]string)}
}

func (e *Engine) EnableMemberLedger(dir string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.candidates) > 0 {
		return errors.New("configure candidate membership before ingestion")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	ledger := newMemberLedger()
	ledger.dir = dir
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		id, snapshot := strings.CutSuffix(entry.Name(), ".snapshot.json")
		if !snapshot || !candidateKey.MatchString(id) {
			continue
		}
		c, _, err := ledger.snapshot(id)
		if err != nil {
			return err
		}
		if c.AlertID != "" {
			if other := ledger.byAlert[c.AlertID]; other != "" && other != id {
				return errors.New("conflicting archived candidate alert IDs")
			}
			ledger.byAlert[c.AlertID], ledger.emitted[id] = id, c.AlertID
		}
	}
	e.members = ledger
	return nil
}

func (m *memberLedger) read(id string) ([]string, bool, error) {
	if m.dir == "" {
		ids, ok := m.memory[id]
		return ids, ok, nil
	}
	raw, err := os.ReadFile(filepath.Join(m.dir, id+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil {
		return nil, false, err
	}
	if ids == nil {
		return nil, false, errors.New("invalid candidate membership")
	}
	return ids, true, nil
}

func (m *memberLedger) merge(id string, links []string) ([]string, error) {
	ids, _, err := m.read(id)
	if err != nil {
		return nil, err
	}
	original := len(ids)
	seen := make(map[string]bool, len(ids))
	for _, v := range ids {
		seen[v] = true
	}
	for _, v := range links {
		if !seen[v] {
			ids = append(ids, v)
			seen[v] = true
		}
	}
	if len(ids) == original {
		return ids, nil
	}
	if m.dir == "" {
		m.memory[id] = ids
		return ids, nil
	}
	return ids, m.store(id, ids)
}
func (m *memberLedger) store(id string, value any) error {
	tmp, err := os.CreateTemp(m.dir, ".members-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	err = json.NewEncoder(tmp).Encode(value)
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(tmp.Name(), filepath.Join(m.dir, id+".json")); err != nil {
		return err
	}
	dir, err := os.Open(m.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return err
	}
	return nil
}

type MemberPage struct {
	Items      []string `json:"items"`
	Total      int      `json:"total"`
	NextOffset *int     `json:"nextOffset"`
}

func (e *Engine) MemberPage(id string, offset, limit int) (MemberPage, bool, error) {
	return e.MemberPageByKind(id, "alerts", offset, limit)
}
func (e *Engine) MemberPageByKind(id, kind string, offset, limit int) (MemberPage, bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if !candidateKey.MatchString(id) {
		return MemberPage{}, false, nil
	}
	if offset < 0 || limit < 1 || limit > 500 {
		return MemberPage{}, false, errors.New("invalid membership page")
	}
	key := id
	if kind == "observations" {
		key += ".obs"
	} else if kind != "alerts" {
		return MemberPage{}, false, errors.New("invalid membership kind")
	}
	ids, found, err := e.members.read(key)
	if err == nil && !found && e.byID[id] == nil {
		archived, exists, readErr := e.members.snapshot(id)
		if readErr != nil || !exists {
			return MemberPage{}, false, readErr
		}
		if kind == "observations" || archived.LinkedAlertCount != 0 || len(archived.B89AlertIDs) > 0 {
			return MemberPage{}, false, errors.New("archived membership file missing")
		}
	}
	if err != nil {
		return MemberPage{}, false, err
	}
	start := min(offset, len(ids))
	end := start + min(len(ids)-start, limit)
	page := MemberPage{Items: append([]string{}, ids[start:end]...), Total: len(ids)}
	if end < len(ids) {
		page.NextOffset = &end
	}
	return page, true, nil
}

// FlushMembers persists updates before the upstream page cursor advances.
func (e *Engine) FlushMembers() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for c, refs := range e.pendingObservations {
		id := c.ID
		if _, err := e.members.merge(id+".obs", refs); err != nil {
			return err
		}
		if e.members.dir != "" {
			if err := e.members.store(id+".snapshot", c); err != nil {
				return err
			}
		}
		delete(e.pendingObservations, c)
	}
	return nil
}

func (e *Engine) ArchivedCandidate(id string) (model.Candidate, bool, error) {
	if c, ok := e.Candidate(id); ok {
		return c, true, nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.members.snapshot(id)
}

func (m *memberLedger) snapshot(id string) (model.Candidate, bool, error) {
	if m.dir == "" || !candidateKey.MatchString(id) {
		return model.Candidate{}, false, nil
	}
	raw, err := os.ReadFile(filepath.Join(m.dir, id+".snapshot.json"))
	if errors.Is(err, os.ErrNotExist) {
		return model.Candidate{}, false, nil
	}
	if err != nil {
		return model.Candidate{}, false, err
	}
	var c model.Candidate
	if err := json.Unmarshal(raw, &c); err != nil {
		return model.Candidate{}, false, err
	}
	if c.ID != id {
		return model.Candidate{}, false, errors.New("candidate snapshot ID mismatch")
	}
	return c, true, nil
}

// RecordEmission atomically stores the API result before reporting successful emission.
// Failed writes remain queued for the next membership flush.
func (e *Engine) RecordEmission(id, alertID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	c := e.byID[id]
	if c == nil || alertID == "" {
		return errors.New("missing emission identity")
	}
	if other := e.members.byAlert[alertID]; other != "" && other != id {
		return errors.New("alert already linked to another candidate")
	}
	if c.AlertID != "" && c.AlertID != alertID {
		return errors.New("candidate already linked to another alert")
	}
	c.Status, c.AlertID, c.StatusDetail = model.CandidateEmitted, alertID, ""
	e.members.byAlert[alertID], e.members.emitted[id] = id, alertID
	if e.members.dir != "" {
		if err := e.members.store(id+".snapshot", c); err != nil {
			if _, queued := e.pendingObservations[c]; !queued {
				e.pendingObservations[c] = nil
			}
			return err
		}
	}
	return nil
}

func (e *Engine) CandidateByAlert(alertID string) (model.Candidate, bool, error) {
	e.mu.RLock()
	id, found := e.members.byAlert[alertID]
	e.mu.RUnlock()
	if !found {
		return model.Candidate{}, false, nil
	}
	return e.ArchivedCandidate(id)
}
