package finding

import "testing"

func TestFingerprintIgnoresVolatileFields(t *testing.T) {
	base := Finding{
		Producer: "scan", Provider: "github", Title: "t",
		Severity: "high", Confidence: "high",
		Subject: Subject{Kind: "job", ID: "x"}, Evidence: []string{"e1"},
	}
	fp := Fingerprint(base)

	volatile := base
	volatile.FindingID = "F-009"
	volatile.MatchedAt = "2026-01-01T00:00:00Z"
	volatile.AINotes = &AINotes{Text: "added later"}
	volatile.Fingerprint = "stale"
	if got := Fingerprint(volatile); got != fp {
		t.Fatalf("volatile fields changed fingerprint: %s != %s", got, fp)
	}

	changed := base
	changed.Evidence = []string{"e1", "e2"}
	if got := Fingerprint(changed); got == fp {
		t.Fatal("a content change must change the fingerprint")
	}
}

func TestFingerprintLength(t *testing.T) {
	if fp := Fingerprint(Finding{Title: "x"}); len(fp) != 16 {
		t.Fatalf("want 16 hex chars, got %d (%q)", len(fp), fp)
	}
}

func TestRankUnknownSortsBelowKnown(t *testing.T) {
	if SeverityRank("bogus") != 0 || ConfidenceRank("bogus") != 0 {
		t.Fatal("unknown level must rank 0 so any threshold filters it out")
	}
	if SeverityRank("critical") <= SeverityRank("info") {
		t.Fatal("critical must outrank info")
	}
}
