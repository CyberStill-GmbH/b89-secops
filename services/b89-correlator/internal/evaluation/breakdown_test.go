package evaluation

import "testing"

func TestBreakdownBySourceAndPriorityCountsDuplicatesSeparately(t *testing.T) {
	corpus := baseCorpus()
	examples := corpus.Families[0].Examples
	examples[1].Source = "m365"
	examples[2].Source = "m365"
	examples[3].Source = "windows"
	examples = append(examples,
		Example{ID: "dup-fire", OccurredAt: "2026-01-14T10:00:00Z", Label: "positive", BaselineDetected: true, CandidateDetected: true, BaselinePriority: "P2", Source: "m365", CandidateDuplicate: true},
	)
	corpus.Families[0].Examples = examples
	report, err := Evaluate(corpus)
	if err != nil {
		t.Fatal(err)
	}
	if report.CandidateDuplicates != 1 {
		t.Fatalf("duplicates = %d", report.CandidateDuplicates)
	}
	sources := map[string]SliceReport{}
	for _, s := range report.BySource {
		sources[s.Key] = s
	}
	m365 := sources["m365"]
	if m365.AdjudicatedExamples != 3 || m365.CandidateDuplicates != 1 || m365.Candidate.ConfusionMatrix.TruePositive != 2 {
		t.Fatalf("m365 slice = %+v", m365)
	}
	if sources["windows"].AdjudicatedExamples != 1 {
		t.Fatalf("windows slice = %+v", sources["windows"])
	}
	priorities := map[string]SliceReport{}
	for _, s := range report.ByPriority {
		priorities[s.Key] = s
	}
	if priorities["P2"].AdjudicatedExamples != 2 || priorities["P3"].Baseline.ConfusionMatrix.FalsePositive != 1 {
		t.Fatalf("priority slices = %+v", report.ByPriority)
	}
}

func TestDuplicateWithoutCandidateDetectionIsRejected(t *testing.T) {
	corpus := baseCorpus()
	corpus.Families[0].Examples[3].CandidateDuplicate = true
	if _, err := Evaluate(corpus); err == nil {
		t.Fatal("a duplicate must be a candidate detection")
	}
}

func TestDuplicateCoverageIsMeasuredWithinEachHoldoutSlice(t *testing.T) {
	corpus := baseCorpus()
	duplicate, unique := true, false
	rows := corpus.Families[0].Examples
	rows[1].Source = "identity"
	rows[1].BaselineDuplicate = &duplicate
	rows[1].CandidateDuplicate = true
	rows[2].Source = "windows"
	corpus.Families = append(corpus.Families, Family{ID: "overlap", Examples: []Example{rows[1]}})
	report, err := Evaluate(corpus)
	if err != nil {
		t.Fatal(err)
	}
	check := func(scope string, d DuplicateMetrics, detections, annotated, candidate, baseline int) {
		t.Helper()
		if d.BaselineDetections != detections || d.BaselineDuplicateAnnotations != annotated || d.CandidateDuplicates != candidate {
			t.Fatalf("%s duplicate coverage = %+v", scope, d)
		}
		if baseline == -1 {
			if d.BaselineDuplicates != nil {
				t.Fatalf("%s partial annotations produced a total", scope)
			}
		} else if d.BaselineDuplicates == nil || *d.BaselineDuplicates != baseline {
			t.Fatalf("%s baseline duplicates = %v, want %d", scope, d.BaselineDuplicates, baseline)
		}
	}
	check("overall", report.DuplicateMetrics, 2, 1, 1, -1)
	check("family", report.Families[0].DuplicateMetrics, 2, 1, 1, -1)
	check("shared family", report.Families[1].DuplicateMetrics, 1, 1, 1, 1)
	for _, slice := range append(report.BySource, report.ByPriority...) {
		switch slice.Key {
		case "identity", "P2":
			check(slice.Key, slice.DuplicateMetrics, 1, 1, 1, 1)
		case "windows", "P3":
			check(slice.Key, slice.DuplicateMetrics, 1, 0, 0, -1)
		case "unspecified", "P4":
			check(slice.Key, slice.DuplicateMetrics, 0, 0, 0, 0)
		default:
			t.Fatalf("unexpected slice: %s", slice.Key)
		}
	}
	rows[2].BaselineDuplicate = &unique
	report, err = Evaluate(corpus)
	if err != nil {
		t.Fatal(err)
	}
	check("complete", report.DuplicateMetrics, 2, 2, 1, 1)
	corpus.Families[1].Examples[0].BaselineDuplicate = &unique
	if _, err = Evaluate(corpus); err == nil {
		t.Fatal("conflicting cross-family annotations accepted")
	}
}

func TestBaselineDuplicateRequiresDetection(t *testing.T) {
	corpus := baseCorpus()
	duplicate := true
	corpus.Families[0].Examples[3].BaselineDuplicate = &duplicate
	if _, err := Evaluate(corpus); err == nil {
		t.Fatal("baseline duplicate without a detection accepted")
	}
}
