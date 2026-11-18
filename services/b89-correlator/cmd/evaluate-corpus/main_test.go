package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/evaluation"
)

func writeCorpus(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "corpus.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func corpusJSON(candidateDetected bool, priority string) string {
	return `{"schemaVersion":"b89-correlator-eval/v1","corpusId":"test-corpus","sourceSnapshotSha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","annotationProtocol":"test-v1","baselineVersion":"base-v1","candidateVersion":"candidate-v2","evaluationStart":"2026-01-01T00:00:00Z","evaluationEnd":"2026-02-01T00:00:00Z","families":[{"id":"auth","eligibleSourceEvents":100,"examples":[{"id":"p1","occurredAt":"2026-01-02T00:00:00Z","label":"ambiguous","baselineDetected":true,"candidateDetected":` + boolString(candidateDetected) + `,"baselinePriority":"` + priority + `"}]}]}`
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func TestRunWritesInsufficientReportAndReturnsNonzero(t *testing.T) {
	input := writeCorpus(t, corpusJSON(true, "P1"))
	output := filepath.Join(t.TempDir(), "report.json")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-input", input, "-output", output}, &stdout, &stderr); code != 4 {
		t.Fatalf("exit code %d, stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("unexpected stdout %s", stdout.String())
	}
	report, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(report), `"schemaVersion": "b89-correlator-eval/v1"`) ||
		!strings.Contains(string(report), `"ambiguousExamplesExcluded": 1`) {
		t.Fatalf("report missing evaluated fields: %s", report)
	}
	if !strings.Contains(stderr.String(), "insufficient evidence") {
		t.Fatalf("missing insufficient-evidence message: %s", stderr.String())
	}
}

func TestRunPassesOnlyWithSufficientEvidenceAndNoRegressions(t *testing.T) {
	corpus := evaluation.Corpus{
		SchemaVersion: evaluation.SchemaVersion, CorpusID: "test-corpus",
		SourceSnapshotSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		AnnotationProtocol:   "test-v1", BaselineVersion: "base-v1", CandidateVersion: "candidate-v2",
		EvaluationStart: "2026-01-01T00:00:00Z", EvaluationEnd: "2026-02-01T00:00:00Z",
		Families: []evaluation.Family{{ID: "auth", EligibleSourceEvents: 1000}},
	}
	for i := 0; i < evaluation.MinPositiveExamples; i++ {
		corpus.Families[0].Examples = append(corpus.Families[0].Examples, evaluation.Example{
			ID: "tp-" + strconv.Itoa(i), OccurredAt: "2026-01-02T00:00:00Z", Label: "positive",
			BaselineDetected: true, CandidateDetected: true, BaselinePriority: "P2",
		})
	}
	for i := 0; i < evaluation.MinLabeled-evaluation.MinPositiveExamples; i++ {
		corpus.Families[0].Examples = append(corpus.Families[0].Examples, evaluation.Example{
			ID: "negative-" + strconv.Itoa(i), OccurredAt: "2026-01-03T00:00:00Z", Label: "negative",
			BaselineDetected: i < evaluation.MinNegativeExamples, CandidateDetected: false, BaselinePriority: "P3",
		})
	}
	encoded, err := json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	input := writeCorpus(t, string(encoded))
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-input", input}, &stdout, &stderr); code != 0 {
		t.Fatalf("sufficient corpus should pass, exit=%d stderr=%s", code, stderr.String())
	}
	var report evaluation.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if !report.SufficientEvidence || !report.GuardrailsPassed {
		t.Fatalf("report does not satisfy evidence and guardrail gates: %+v", report)
	}
	if code := run([]string{"-input", input, "-require-fp-reduction"}, &stdout, &stderr); code != 0 {
		t.Fatalf("expected significant paired reduction, exit=%d", code)
	}
	if report.OverallBaseline.ConfusionMatrix.FalsePositive != evaluation.MinNegativeExamples || report.Overall.ConfusionMatrix.FalsePositive != 0 {
		t.Fatal("comparison omits baseline or candidate false positives")
	}
	// A global reduction can coincide with a new false alert in a particular source.
	last := &corpus.Families[0].Examples[len(corpus.Families[0].Examples)-1]
	last.Source, last.CandidateDetected = "cloudflare", true
	encoded, err = json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	mixed := writeCorpus(t, string(encoded))
	if code := run([]string{"-input", mixed, "-require-fp-reduction"}, &stdout, &stderr); code != 0 {
		t.Fatalf("overall decrease should still pass: %d", code)
	}
	if code := run([]string{"-input", mixed, "-require-fp-reduction", "-require-no-slice-fp-increase"}, &stdout, &stderr); code != 6 ||
		!strings.Contains(stderr.String(), `source "cloudflare": observed false positives increased from 0 to 1`) {
		t.Fatalf("expected source regression: exit=%d stderr=%s", code, stderr.String())
	}
	for i := range corpus.Families[0].Examples {
		row := &corpus.Families[0].Examples[i]
		if row.Label == "negative" {
			row.CandidateDetected = true
		}
	}
	encoded, err = json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"-input", writeCorpus(t, string(encoded)), "-require-fp-reduction"}, &stdout, &stderr); code != 5 {
		t.Fatalf("significant increase in false positives should fail the reduction gate, exit=%d", code)
	}
}

func TestRunWritesGuardrailReportAndReturnsNonzero(t *testing.T) {
	input := writeCorpus(t, corpusJSON(false, "P1"))
	output := filepath.Join(t.TempDir(), "report.json")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-input", input, "-output", output}, &stdout, &stderr); code != 3 {
		t.Fatalf("exit code %d, stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatalf("metrics must be written even when guardrail fails: %v", err)
	}
	if !strings.Contains(stderr.String(), "guardrail violations found") {
		t.Fatalf("missing guardrail message: %s", stderr.String())
	}
}

func TestRunRejectsMissingInputAndMalformedCorpus(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("missing input exit code = %d", code)
	}
	input := writeCorpus(t, `{}`)
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"-input", input}, &stdout, &stderr); code != 2 {
		t.Fatalf("malformed corpus exit code = %d", code)
	}
}

func TestIncompleteReplayCannotBeScoredAsNegative(t *testing.T) {
	for _, field := range []string{"baselineDetected", "candidateDetected"} {
		for _, replacement := range []string{"", `"` + field + `":null,`} {
			valid := corpusJSON(true, "P1")
			incomplete := strings.Replace(valid, `"`+field+`":true,`, replacement, 1)
			var stdout, stderr bytes.Buffer
			code := run([]string{"-input", writeCorpus(t, incomplete)}, &stdout, &stderr)
			if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "requires explicit") {
				t.Fatalf("field %s, replacement %q: exit=%d, stderr=%s", field, replacement, code, stderr.String())
			}
		}
	}
}
