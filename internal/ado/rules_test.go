package ado

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine/detect"
)

// detect carries rule.Graph unparsed, so a typo'd target survives loading and then
// silently attaches nothing when the graph phase indexes rule -> target.
func TestEveryEmbeddedRuleHasAParsableGraphTarget(t *testing.T) {
	rules, err := detect.LoadRules("ado", nil)
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("no rules loaded")
	}
	var bad []string
	for _, r := range rules {
		if _, err := ParseTarget(r.Graph); err != nil {
			bad = append(bad, r.ID+": "+err.Error())
		}
	}
	if len(bad) > 0 {
		t.Errorf("rule(s) with an unusable graph target:\n%s", strings.Join(bad, "\n"))
	}
}

// The attacher resolves through SubjectDirs, so a subject kind absent from it cannot
// attach however well-formed its target is.
func TestEveryRuleSubjectNamesANormalizeDirectory(t *testing.T) {
	rules, err := detect.LoadRules("ado", nil)
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	var bad []string
	for _, r := range rules {
		if _, ok := adoScanProvider.SubjectDirs[r.Subject]; !ok {
			bad = append(bad, r.ID+": subject "+r.Subject)
		}
	}
	if len(bad) > 0 {
		t.Errorf("rule subject(s) with no record directory:\n%s", strings.Join(bad, "\n"))
	}
}
