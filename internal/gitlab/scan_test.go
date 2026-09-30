package gitlab

import (
	"slices"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine/detect"
)

func TestHierarchyRulesKeepGroupAndInstanceSubjects(t *testing.T) {
	rules, err := detect.LoadRules("gitlab", nil)
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	want := map[string]int{}
	for _, r := range rules {
		if slices.Contains(gitlabScanProvider.HierarchyKinds, r.SubjectKind()) {
			want[r.SubjectKind()]++
		}
	}
	for _, kind := range gitlabScanProvider.HierarchyKinds {
		if want[kind] == 0 {
			t.Fatalf("the gitlab corpus has no %q-subject rule to filter for", kind)
		}
	}

	// HierarchyRules mutates its input via slices.DeleteFunc, so clone first.
	hierarchy := detect.HierarchyRules(slices.Clone(rules), gitlabScanProvider.HierarchyKinds)
	got := map[string]int{}
	for _, r := range hierarchy {
		got[r.SubjectKind()]++
	}
	if len(hierarchy) >= len(rules) {
		t.Errorf("hierarchy set (%d) should be a strict subset of the full set (%d)", len(hierarchy), len(rules))
	}
	for kind, n := range want {
		if got[kind] != n {
			t.Errorf("kept %d %q-subject rules, want %d", got[kind], kind, n)
		}
	}
	for kind := range got {
		if !slices.Contains(gitlabScanProvider.HierarchyKinds, kind) {
			t.Errorf("hierarchy set leaked a %q-subject rule", kind)
		}
	}
}
