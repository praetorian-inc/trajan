package gitlab

import (
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// Pull mirroring is a project-detail attribute (mirror==true + import_url), not a
// /remote_mirrors entry. The firing range's pull-only cat-14 fixtures have an
// empty remote_mirrors surface, so a normalizer that keyed off it emitted no
// pull_mirror record and the whole cat-14 mirror.* fold surface went missing.
// Fixture inputs below are the ground-truth cat-14-v05/v07 scenarios.
func TestPullMirrorRec(t *testing.T) {
	writeEnv := func(t *testing.T, prior engine.PriorPhase, rel string, data any) {
		t.Helper()
		if err := engine.WriteJSON(prior.Abs(rel), map[string]any{"data": data}); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	protectedMain := []any{map[string]any{"name": "main"}}

	cases := []struct {
		name        string
		fp          string
		detail      map[string]any
		protected   []any
		projectVars []any
		want        map[string]any
	}{
		{
			// cat-14-v05: mirror confined to protected branches, default branch
			// protected, one protected project variable.
			name: "protected-only reaches protected var",
			fp:   "trajan-fr-group/trjfx/c14/cat-14-v05",
			detail: map[string]any{
				"default_branch":                 "main",
				"mirror":                         true,
				"import_url":                     "https://github.com/octocat/Hello-World.git",
				"mirror_trigger_builds":          true,
				"only_mirror_protected_branches": true,
				"ci_push_repository_for_job_token_allowed": false,
			},
			protected:   protectedMain,
			projectVars: []any{map[string]any{"key": "PROD_DEPLOY_SECRET", "protected": true}},
			want: map[string]any{
				"trigger_pipelines":            true,
				"all_branches":                 false,
				"upstream_untrusted_host":      true,
				"protected_default_branch":     true,
				"reaches_protected_variable":   true,
				"reaches_unprotected_variable": false,
				"job_token_push_allowed":       false,
			},
		},
		{
			// cat-14-v07: mirror pulls all branches, one unprotected variable.
			name: "all-branches reaches unprotected var",
			fp:   "trajan-fr-group/trjfx/c14/cat-14-v07",
			detail: map[string]any{
				"default_branch":                 "main",
				"mirror":                         true,
				"import_url":                     "https://github.com/octocat/Hello-World.git",
				"mirror_trigger_builds":          true,
				"only_mirror_protected_branches": false,
				"ci_push_repository_for_job_token_allowed": false,
			},
			protected:   protectedMain,
			projectVars: []any{map[string]any{"key": "API_KEY", "protected": false}},
			want: map[string]any{
				"trigger_pipelines":            true,
				"all_branches":                 true,
				"upstream_untrusted_host":      true,
				"protected_default_branch":     true,
				"reaches_protected_variable":   false,
				"reaches_unprotected_variable": true,
				"job_token_push_allowed":       false,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prior := engine.PriorPhase{RunDir: t.TempDir()}
			writeEnv(t, prior, engine.CollectGLProtectedBranches(c.fp), c.protected)
			writeEnv(t, prior, engine.CollectGLProjectVariables(c.fp), c.projectVars)

			rec := pullMirrorRec(c.detail, prior, c.fp, false)

			if got := rec["url"]; got != c.detail["import_url"] {
				t.Errorf("url = %v, want %v", got, c.detail["import_url"])
			}
			m, ok := rec["mirror"].(map[string]any)
			if !ok {
				t.Fatalf("mirror field missing/wrong type: %T", rec["mirror"])
			}
			for k, want := range c.want {
				if got := m[k]; got != want {
					t.Errorf("mirror.%s = %v, want %v", k, got, want)
				}
			}
			// C1: list field must serialize as [] not null.
			if hdrs, ok := rec["custom_headers"].([]any); !ok || hdrs == nil {
				t.Errorf("custom_headers = %#v, want empty non-nil list", rec["custom_headers"])
			}
		})
	}
}

func TestMirrorUntrustedHost(t *testing.T) {
	cases := []struct {
		importURL, fp string
		want          bool
	}{
		{"https://github.com/octocat/Hello-World.git", "trajan-fr-group/trjfx/c14/cat-14-v05", true},
		{"https://gitlab.com/trajan-fr-group/upstream.git", "trajan-fr-group/trjfx/x", false},
		{"", "trajan-fr-group/x", false},
	}
	for _, c := range cases {
		if got := mirrorUntrustedHost(c.importURL, c.fp); got != c.want {
			t.Errorf("mirrorUntrustedHost(%q,%q) = %v, want %v", c.importURL, c.fp, got, c.want)
		}
	}
}
