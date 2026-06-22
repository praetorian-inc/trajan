package report

import (
	"testing"

	"github.com/praetorian-inc/trajan/internal/finding"
)

func mk(sev, conf, ruleID, subjID string) finding.Finding {
	return finding.Finding{
		Severity:   sev,
		Confidence: conf,
		Rule:       &finding.Rule{ID: ruleID},
		Subject:    finding.Subject{ID: subjID},
	}
}

func TestFilterAndOrderSeverityThresholdAndOrdering(t *testing.T) {
	in := []finding.Finding{
		mk("low", "high", "r2", "b"),
		mk("critical", "high", "r1", "a"),
		mk("high", "low", "r1", "z"),
		mk("info", "low", "r0", "a"), // below min-severity → dropped
	}
	got := filterAndOrder(in, Options{MinSeverity: "low", MinConfidence: "low"})

	if len(got) != 3 {
		t.Fatalf("info should be dropped; want 3, got %d", len(got))
	}
	wantSev := []string{"critical", "high", "low"}
	for i, w := range wantSev {
		if got[i].Severity != w {
			t.Errorf("pos %d: want severity %s, got %s", i, w, got[i].Severity)
		}
	}
	wantID := []string{"F-001", "F-002", "F-003"}
	for i, w := range wantID {
		if got[i].FindingID != w {
			t.Errorf("pos %d: want id %s, got %s", i, w, got[i].FindingID)
		}
	}
}

func TestFilterAndOrderConfidenceThreshold(t *testing.T) {
	in := []finding.Finding{
		mk("critical", "low", "r1", "a"), // dropped at min-confidence=medium
		mk("critical", "high", "r2", "a"),
	}
	got := filterAndOrder(in, Options{MinSeverity: "info", MinConfidence: "medium"})
	if len(got) != 1 || got[0].Confidence != "high" {
		t.Fatalf("min-confidence=medium should keep only the high-confidence finding, got %+v", got)
	}
}

func TestFilterAndOrderTieBreaksByRuleThenSubject(t *testing.T) {
	in := []finding.Finding{
		mk("high", "high", "r1", "z"),
		mk("high", "high", "r1", "a"), // same sev+rule → subject id breaks the tie
		mk("high", "high", "r0", "m"),
	}
	got := filterAndOrder(in, Options{})
	wantRuleSubj := [][2]string{{"r0", "m"}, {"r1", "a"}, {"r1", "z"}}
	for i, w := range wantRuleSubj {
		if got[i].Rule.ID != w[0] || got[i].Subject.ID != w[1] {
			t.Errorf("pos %d: want %v, got (%s,%s)", i, w, got[i].Rule.ID, got[i].Subject.ID)
		}
	}
}
