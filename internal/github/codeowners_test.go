package github

import (
	"slices"
	"testing"
)

func ownersOf(t *testing.T, content, path string) []string {
	t.Helper()
	return codeownersOwners(codeownersRules(content), path)
}

// GitHub reads CODEOWNERS with gitignore path semantics. Each case below is a
// rule of that syntax, not of this implementation: a leading slash anchors, a
// bare name floats to any depth, a trailing slash owns a subtree, and * stops
// at a separator.
func TestCodeownersPathMatching(t *testing.T) {
	for _, tc := range []struct {
		name, content, path string
		want                []string
	}{
		{"anchored directory owns its subtree", "/.github/workflows/ @team",
			".github/workflows/ci.yml", []string{"@team"}},
		{"anchored directory does not own a sibling", "/.github/workflows/ @team",
			"scripts/build.sh", nil},
		{"anchored file matches exactly", "/README.md @team", "README.md", []string{"@team"}},
		{"anchored file does not float", "/README.md @team", "docs/README.md", nil},
		{"bare name floats to any depth", "docs/ @team", "a/b/docs/x.md", []string{"@team"}},
		{"star stops at a separator", "*.yml @team", "a/b.yml", []string{"@team"}},
		{"star does not cross a separator", "/.github/*.yml @team",
			".github/workflows/ci.yml", nil},
		{"double star crosses separators", "/.github/**/*.yml @team",
			".github/workflows/ci.yml", []string{"@team"}},
		{"directory pattern owns nested content", "/scripts @team",
			"scripts/deep/run.sh", []string{"@team"}},
		// GitHub departs from gitignore: a trailing * owns one level, not a subtree.
		{"trailing star owns one level", "docs/* @team",
			"docs/getting-started.md", []string{"@team"}},
		{"trailing star does not own a subtree", "docs/* @team",
			"docs/build-app/troubleshooting.md", nil},
		{"trailing star does not reach workflows", ".github/* @team",
			".github/workflows/ci.yml", nil},
		{"leading double star matches at the root", "**/foo @team", "foo", []string{"@team"}},
		{"inner double star matches an empty span", "a/**/b @team", "a/b", []string{"@team"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ownersOf(t, tc.content, tc.path); !slices.Equal(got, tc.want) {
				t.Errorf("owners(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// Last match wins, and a pattern with no owners un-owns the paths it matches.
// Reading first-match-wins instead would report a catch-all as covering paths a
// later rule deliberately excluded.
func TestCodeownersLastMatchWins(t *testing.T) {
	const content = `
# owners for everything
*            @platform
/vendor/
/scripts/    @release
`
	for path, want := range map[string][]string{
		"README.md":        {"@platform"},
		"scripts/build.sh": {"@release"},
		"vendor/lib.go":    nil,
	} {
		if got := ownersOf(t, content, path); !slices.Equal(got, want) {
			t.Errorf("owners(%q) = %v, want %v", path, got, want)
		}
	}
}

// The portus-labs CODEOWNERS: workflow definitions are owned, but nothing a
// workflow executes is. Reporting covers_ci_execution from the workflow
// directory alone would call that fully covered.
func TestCodeownersCoverageSeparatesWorkflowsFromWhatTheyExecute(t *testing.T) {
	co := parseCodeowners(map[string]any{
		"path": "CODEOWNERS",
		"content": "/.github/workflows/   @portus-labs/platform-team\n" +
			"/README.md            @portus-labs/platform-team\n",
	})
	if !co.Present || !co.CoversWorkflows {
		t.Fatalf("present=%v covers_workflows=%v, want both true", co.Present, co.CoversWorkflows)
	}
	if co.CoversCIExecution {
		t.Error("covers_ci_execution = true, but no executable path outside .github/workflows is owned")
	}
	if slices.Contains(co.UncoveredCIPaths, workflowProbe) {
		t.Errorf("uncovered = %v, must not list the workflow probe it owns", co.UncoveredCIPaths)
	}
	if len(co.UncoveredCIPaths) != len(ciExecutionProbes)-1 {
		t.Errorf("uncovered = %v, want every probe but the workflow one", co.UncoveredCIPaths)
	}

	full := parseCodeowners(map[string]any{"path": ".github/CODEOWNERS", "content": "* @platform\n"})
	if !full.CoversCIExecution || len(full.UncoveredCIPaths) != 0 {
		t.Errorf("catch-all: covers=%v uncovered=%v, want fully covered",
			full.CoversCIExecution, full.UncoveredCIPaths)
	}
}

// A run collected before CODEOWNERS was fetched carries no key at all; a run
// that looked and found nothing carries content: null. Collapsing the two would
// make every historical repository look like an uncovered one.
func TestCodeownersDistinguishesNotCollectedFromAbsent(t *testing.T) {
	if co := parseCodeowners(nil); co != nil {
		t.Errorf("uncollected = %+v, want nil so a rule cannot read it as uncovered", co)
	}
	absent := parseCodeowners(map[string]any{"path": nil, "content": nil})
	if absent == nil || absent.Present {
		t.Fatalf("absent = %+v, want a record with present=false", absent)
	}
	if len(absent.Rules) != 0 {
		t.Errorf("absent rules = %v, want none", absent.Rules)
	}
}
