package evaluation

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Require an explicit prediction from each run. encoding/json otherwise turns an
// absent or null boolean into false, indistinguishable from a completed negative.
func (e *Example) UnmarshalJSON(data []byte) error {
	type fields Example
	var row struct {
		fields
		Baseline  *bool `json:"baselineDetected"`
		Candidate *bool `json:"candidateDetected"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&row); err != nil {
		return err
	}
	if row.Baseline == nil || row.Candidate == nil {
		return fmt.Errorf("example %q requires explicit baselineDetected and candidateDetected predictions", row.ID)
	}
	*e = Example(row.fields)
	e.BaselineDetected = *row.Baseline
	e.CandidateDetected = *row.Candidate
	return nil
}
