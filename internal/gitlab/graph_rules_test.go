package gitlab

import (
	"slices"
	"strings"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine/detect"
	"github.com/praetorian-inc/trajan/internal/graph"
)

func TestEveryEmbeddedRuleHasAParsableGraphTarget(t *testing.T) {
	rules, err := detect.LoadRules("gitlab", nil)
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("no rules loaded")
	}
	var bad []string
	for _, r := range rules {
		if _, err := graph.ParseTarget(GraphProvider(), r.Graph); err != nil {
			bad = append(bad, r.ID+": "+err.Error())
		}
	}
	if len(bad) > 0 {
		t.Errorf("rule(s) with an unusable graph target:\n%s", strings.Join(bad, "\n"))
	}
}

func TestEveryChainJoinHasAnAnchor(t *testing.T) {
	rules, err := detect.LoadRules("gitlab", nil)
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	anchored := make([]string, 0, len(chainAnchors))
	for _, ca := range chainAnchors {
		anchored = append(anchored, ca.file)
	}
	var bad []string
	for _, r := range rules {
		if r.ChainOf == nil || r.ChainOf.Join == "" {
			continue
		}
		if !slices.Contains(anchored, r.ChainOf.Join) {
			bad = append(bad, r.ID+": join "+r.ChainOf.Join)
		}
	}
	if len(bad) > 0 {
		t.Errorf("chain rule(s) whose join has no anchor:\n%s", strings.Join(bad, "\n"))
	}
}

func TestEveryRuleSubjectNamesANormalizeDirectory(t *testing.T) {
	rules, err := detect.LoadRules("gitlab", nil)
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	var bad []string
	for _, r := range rules {
		if r.SubjectKind() == "chain" {
			continue
		}
		if _, ok := gitlabScanProvider.SubjectDirs[r.SubjectKind()]; !ok {
			bad = append(bad, r.ID+": subject "+r.SubjectKind())
		}
	}
	if len(bad) > 0 {
		t.Errorf("rule(s) whose subject names no normalize directory:\n%s", strings.Join(bad, "\n"))
	}
}

func TestEveryTargetedLabelHasARecordSource(t *testing.T) {
	rules, err := detect.LoadRules("gitlab", nil)
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	emitted := make([]NodeLabel, 0, len(dirLabels))
	for _, l := range dirLabels {
		emitted = append(emitted, l)
	}
	var bad []string
	for _, r := range rules {
		target, err := graph.ParseTarget(GraphProvider(), r.Graph)
		if err != nil {
			continue
		}
		if !slices.Contains(emitted, NodeLabel(target.Label)) {
			bad = append(bad, r.ID+": "+target.Label)
		}
	}
	if len(bad) > 0 {
		t.Errorf("rule(s) targeting a label no record emits:\n%s", strings.Join(bad, "\n"))
	}
}
