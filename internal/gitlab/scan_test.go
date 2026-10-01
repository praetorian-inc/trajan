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

func TestProjectIsReadFromTheRecordNotSplitOutOfTheID(t *testing.T) {
	job := map[string]any{"_id": "grp/api:build:image", "project": "grp/api"}
	if got := gitlabRepo(job); got != "grp/api" {
		t.Errorf("gitlabRepo = %q, want grp/api; a colon in the job name is not a separator", got)
	}
	if got := jobProject(job); got != "grp/api" {
		t.Errorf("jobProject = %q, want grp/api", got)
	}
	if got := gitlabRepo(map[string]any{"_id": "instance"}); got != "" {
		t.Errorf("gitlabRepo(instance subject) = %q, want empty", got)
	}
}

func TestProtectedVarTupleIDCarriesTheProject(t *testing.T) {
	c := &correlator{}
	var tuples []map[string]any
	v := map[string]any{"key": "DEPLOY_TOKEN", "protected": true, "environment_scope": "*"}
	for _, proj := range []string{"grp/a", "grp/b"} {
		p := map[string]any{
			"_id":                proj,
			"members":            []any{map[string]any{"access_level": int64(30)}},
			"protected_branches": []any{map[string]any{"pattern": "main"}},
		}
		c.emitVarTuples(&tuples, p, v, "instance", nil)
	}
	if len(tuples) != 2 {
		t.Fatalf("emitted %d tuples, want one per project", len(tuples))
	}
	if tuples[0]["_id"] == tuples[1]["_id"] {
		t.Fatalf("both projects produced _id %q; one finding file overwrites the other", tuples[0]["_id"])
	}
}
