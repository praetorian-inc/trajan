package detect

import (
	"slices"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func TestScopeRulesPartitionsTheCorpus(t *testing.T) {
	cases := []struct {
		subtree string
		kinds   []string
	}{
		{"github", []string{"org"}},
		{"gitlab", []string{"group", "instance"}},
		{"ado", []string{"org", "project"}},
	}
	for _, tc := range cases {
		t.Run(tc.subtree, func(t *testing.T) {
			rules, err := LoadRules(tc.subtree, nil)
			if err != nil {
				t.Fatalf("LoadRules: %v", err)
			}
			if got := ScopeRules(slices.Clone(rules), tc.kinds, engine.RuleScopeAll); len(got) != len(rules) {
				t.Fatalf("RuleScopeAll kept %d of %d rules", len(got), len(rules))
			}

			hierarchy := ScopeRules(slices.Clone(rules), tc.kinds, engine.RuleScopeHierarchy)
			repository := ScopeRules(slices.Clone(rules), tc.kinds, engine.RuleScopeRepository)
			if len(hierarchy) == 0 || len(repository) == 0 {
				t.Fatalf("hierarchy=%d repository=%d: neither half may be empty", len(hierarchy), len(repository))
			}
			if len(hierarchy)+len(repository) != len(rules) {
				t.Errorf("hierarchy (%d) + repository (%d) != corpus (%d)", len(hierarchy), len(repository), len(rules))
			}

			half := map[string]string{}
			for _, r := range hierarchy {
				if !slices.Contains(tc.kinds, r.SubjectKind()) {
					t.Errorf("hierarchy half holds %s with subject kind %q", r.ID, r.SubjectKind())
				}
				half[r.ID] = "hierarchy"
			}
			for _, r := range repository {
				if slices.Contains(tc.kinds, r.SubjectKind()) {
					t.Errorf("repository half holds %s with subject kind %q", r.ID, r.SubjectKind())
				}
				if prev, dup := half[r.ID]; dup {
					t.Errorf("%s is in both the %s half and the repository half", r.ID, prev)
				}
				half[r.ID] = "repository"
			}
			for _, r := range rules {
				if _, ok := half[r.ID]; !ok {
					t.Errorf("%s (subject %q) fell out of both halves", r.ID, r.SubjectKind())
				}
			}
		})
	}
}
