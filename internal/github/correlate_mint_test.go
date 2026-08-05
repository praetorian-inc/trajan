package github

import (
	"slices"
	"testing"
)

func minterJob(repo, uses string, with map[string]any) map[string]any {
	return map[string]any{
		"_id": repo + "__claude__claude", "repo": repo,
		"workflow_filename": "claude.yml", "job_id": "claude",
		"steps": []any{map[string]any{"step_index": 0, "uses": uses, "with": with}},
	}
}

func mintSlugs(mintable map[string]any) []string {
	out := []string{}
	for _, m := range mintable["mints"].([]map[string]any) {
		out = append(out, mStr(mMap(m, "app"), "slug"))
	}
	slices.Sort(out)
	return out
}

// anthropics/claude-code-action authenticates as its own published App and takes
// no app-id input, so the app-id lookup that resolves the generic minters cannot
// reach it. Its identity is the fixed slug — but only where that App is actually
// installed: without the installation the action uses whatever token the
// workflow handed it, which is not an out-of-band mint.
func TestFixedSlugMinterResolvesOnlyAgainstAnInstalledApp(t *testing.T) {
	claude := map[string]any{"_id": "claude", "app_slug": "claude", "app_id": float64(1236702),
		"repository_selection": "selected",
		"permissions":          map[string]any{"contents": "write"}}
	jobs := []map[string]any{minterJob("portus-cli", "anthropics/claude-code-action@v1", map[string]any{
		"claude_code_oauth_token": "${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}"})}

	installed, repos := deriveAppMintable(jobs, []map[string]any{claude})
	if got := mintSlugs(installed); !slices.Equal(got, []string{"claude"}) {
		t.Errorf("mints = %v, want one resolved to app_slug claude", got)
	}
	if got := repos["claude"]; !slices.Equal(got, []string{"portus-cli"}) {
		t.Errorf("mint repos = %v, want [portus-cli]", got)
	}

	elsewhere, repos := deriveAppMintable(jobs, []map[string]any{
		{"_id": "other", "app_slug": "other", "app_id": float64(1)}})
	if n := elsewhere["minter_count"]; n != 0 {
		t.Errorf("minter_count = %v, want 0 where the claude App is not installed", n)
	}
	if len(repos) != 0 {
		t.Errorf("mint repos = %v, want none", repos)
	}
}

// The generic minters still resolve through their app-id input, and an input
// that is an expression resolves to nothing rather than to an arbitrary app.
func TestAppIDMinterStillResolvesThroughItsInput(t *testing.T) {
	apps := []map[string]any{{"_id": "conf-ci", "app_slug": "conf-ci", "app_id": float64(4242)}}
	literal, repos := deriveAppMintable(
		[]map[string]any{minterJob("conf-ci", "actions/create-github-app-token@v1",
			map[string]any{"app-id": float64(4242)})}, apps)
	if got := mintSlugs(literal); !slices.Equal(got, []string{"conf-ci"}) {
		t.Errorf("mints = %v, want the app the id names", got)
	}
	if got := repos["conf-ci"]; !slices.Equal(got, []string{"conf-ci"}) {
		t.Errorf("mint repos = %v, want [conf-ci]", got)
	}

	expr, repos := deriveAppMintable(
		[]map[string]any{minterJob("conf-ci", "actions/create-github-app-token@v1",
			map[string]any{"app-id": "${{ secrets.APP_ID }}"})}, apps)
	mints := expr["mints"].([]map[string]any)
	// The mint is still recorded — the job does mint a token — but its App is
	// unknown, so the graph has nothing to point the edge at.
	if len(mints) != 1 || mGet(mints[0], "app") != nil {
		t.Errorf("mints = %v, want one row with app: null", mints)
	}
	if len(repos) != 0 {
		t.Errorf("mint repos = %v, want none: an unresolved app has no repository scope", repos)
	}
}

// A "selected" installation's repository list is never collected. Fanning it
// over every repo would invent blast radius; skipping it entirely severed the
// only write capability the flagship chain runs through. The repositories where
// a job actually mints the token are the scope that needs no extra API call.
func TestSelectedInstallationLandsCodeOnlyWhereItMints(t *testing.T) {
	repos := []map[string]any{bareRepo(), {"repo": "other", "default_branch": "main"}}
	app := map[string]any{"_id": "claude", "app_slug": "claude", "app_id": float64(1236702),
		"repository_selection": "selected",
		"permissions":          map[string]any{"contents": "write"}}

	_, coverage := deriveBranchCoverage(repos, nil, map[string][]string{"r": {"main"}, "other": {"main"}})
	_, effective := deriveEffectiveRuleset(coverage, nil, repos)

	byRepo := func(mintRepos map[string][]string) []string {
		out := []string{}
		for _, e := range deriveCapabilityEdges(effective, nil, nil, repos, []map[string]any{app}, mintRepos)["edges"].([]map[string]any) {
			if mStr(e, "principal_kind") == "app" {
				out = append(out, mStr(e, "repo")+":"+mStr(e, "write_via"))
			}
		}
		slices.Sort(out)
		return out
	}

	if got := byRepo(nil); len(got) != 0 {
		t.Errorf("no mint site: app edges = %v, want none", got)
	}
	want := []string{"r:app_token_mint"}
	if got := byRepo(map[string][]string{"claude": {"r"}}); !slices.Equal(got, want) {
		t.Errorf("app edges = %v, want %v — never the repo it does not mint in", got, want)
	}

	// repository_selection "all" IS the repo set, so it still fans over both.
	app["repository_selection"] = "all"
	want = []string{"other:app_installation", "r:app_installation"}
	if got := byRepo(nil); !slices.Equal(got, want) {
		t.Errorf("all-selection app edges = %v, want %v", got, want)
	}
}
