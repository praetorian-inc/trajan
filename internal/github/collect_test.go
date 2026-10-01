package github

import (
	"slices"
	"testing"
)

func TestDropAmbiguousBranchSlugsGuardsTheComposedTransform(t *testing.T) {
	cases := []struct {
		name     string
		branches []string
		kept     []string
		errs     int
	}{
		{"slug collision drops the later ref", []string{"feat/a", "feat__a"}, []string{"feat/a"}, 1},
		{"distinct folds are both kept", []string{"feat+a", "feat,a"}, []string{"feat+a", "feat,a"}, 0},
		{"refs-prefixed duplicate of a plain ref", []string{"main", "refs/heads/main"}, []string{"main"}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kept, errs := dropAmbiguousBranchSlugs("r", tc.branches)
			if !slices.Equal(kept, tc.kept) {
				t.Errorf("kept %v, want %v", kept, tc.kept)
			}
			if len(errs) != tc.errs {
				t.Errorf("reported %d collisions (%v), want %d", len(errs), errs, tc.errs)
			}
		})
	}
}
