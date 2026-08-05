package github

import (
	"maps"
	"slices"
	"testing"
)

func branchRuleset(id int, ruleTypes []string, always, prOnly []any) map[string]any {
	types := make([]any, len(ruleTypes))
	for i, t := range ruleTypes {
		types[i] = t
	}
	return map[string]any{
		"scope":       "repo",
		"repo":        "r",
		"ruleset_id":  float64(id),
		"enforcement": "active",
		"target":      "branch",
		"conditions": map[string]any{
			"ref_name": map[string]any{"include": []any{"~ALL"}, "exclude": []any{}},
		},
		"rule_types":                      types,
		"requires_pull_request":           slices.Contains(ruleTypes, "pull_request"),
		"required_approving_review_count": float64(2),
		"bypass": map[string]any{
			"any_bypass_present":       len(always)+len(prOnly) > 0,
			"bypass_always":            always,
			"bypass_pull_request_only": prOnly,
		},
	}
}

func teamActor(mode string) []any {
	return []any{map[string]any{"actor_id": float64(99), "actor_type": "Team", "bypass_mode": mode}}
}

func roleActor(id int) []any {
	return []any{map[string]any{"actor_id": float64(id), "actor_type": "RepositoryRole", "bypass_mode": "always"}}
}

func bareRepo() map[string]any {
	return map[string]any{
		"repo": "r", "default_branch": "main",
		"default_branch_protection_present": false,
		"can_approve_pull_request_reviews":  false,
	}
}

func capabilityChain(repo map[string]any, rulesets []map[string]any) (map[string]map[string]any, map[string]any) {
	principals := []map[string]any{
		{"_id": "user__u", "kind": "user", "login": "u", "user_id": float64(7),
			"repo_grants": []any{map[string]any{"repo": "r", "can_push": true, "permission": "write"}}},
		{"_id": "user__a", "kind": "user", "login": "a", "user_id": float64(8),
			"repo_grants": []any{map[string]any{"repo": "r", "can_push": true, "permission": "admin", "is_admin": true}}},
		{"_id": "team__t", "kind": "team", "slug": "t", "team_id": float64(99),
			"members": []any{map[string]any{"login": "u"}}, "repo_grants": []any{}},
	}
	deployKeys := []map[string]any{{"_id": "dk", "repo": "r", "can_push": true, "title": "dk"}}
	apps := []map[string]any{{"_id": "app__x", "app_slug": "x", "app_id": float64(4242),
		"repository_selection": "all", "permissions": map[string]any{"contents": "write"}}}
	repos := []map[string]any{repo}

	_, coverage := deriveBranchCoverage(repos, rulesets, map[string][]string{"r": {"main"}})
	_, effective := deriveEffectiveRuleset(coverage, rulesets, repos)

	byPrincipal := map[string]map[string]any{}
	for _, e := range deriveCapabilityEdges(effective, principals, deployKeys, repos, apps, nil)["edges"].([]map[string]any) {
		byPrincipal[mStr(e, "principal_id")] = e
	}
	return byPrincipal, effective[0]
}

func edgeStrings(t *testing.T, edge map[string]any, key string) []string {
	t.Helper()
	v, ok := edge[key].([]string)
	if !ok {
		t.Fatalf("%s is %T, want []string", key, edge[key])
	}
	return v
}

// The route table is empirically settled against live GitHub; each case states
// what that instance of GitHub actually permits, not what the code computes.
func TestCapabilityRoutes(t *testing.T) {
	cases := []struct {
		name        string
		rulesets    []map[string]any
		open        []string
		circumvents []string
	}{
		{
			name: "no control leaves both routes open",
			open: []string{"direct_push", "pull_request"},
		},
		{
			name:     "update alone locks the ref",
			rulesets: []map[string]any{branchRuleset(1, []string{"update"}, nil, nil)},
			open:     []string{},
		},
		{
			name:     "update with pull request forces the merge through a PR",
			rulesets: []map[string]any{branchRuleset(1, []string{"update", "pull_request"}, nil, nil)},
			open:     []string{"pull_request"},
		},
		{
			name:     "pull request closes direct push only",
			rulesets: []map[string]any{branchRuleset(1, []string{"pull_request"}, nil, nil)},
			open:     []string{"pull_request"},
		},
		{
			name: "bypassing one of two blocking rulesets proves nothing",
			rulesets: []map[string]any{
				branchRuleset(1, []string{"pull_request"}, teamActor("always"), nil),
				branchRuleset(2, []string{"pull_request"}, nil, nil),
			},
			open: []string{"pull_request"},
		},
		{
			name: "bypassing every blocking ruleset reopens direct push",
			rulesets: []map[string]any{
				branchRuleset(1, []string{"pull_request"}, teamActor("always"), nil),
				branchRuleset(2, []string{"pull_request"}, teamActor("always"), nil),
			},
			open:        []string{"direct_push", "pull_request"},
			circumvents: []string{"bypass_always"},
		},
		{
			name: "a bypass on a rule that blocks nothing opens no route",
			rulesets: []map[string]any{
				branchRuleset(1, []string{"pull_request"}, nil, nil),
				branchRuleset(2, []string{"required_signatures"}, teamActor("always"), nil),
			},
			open: []string{"pull_request"},
		},
		{
			name:        "pull-request-mode bypass still has to open a PR",
			rulesets:    []map[string]any{branchRuleset(1, []string{"update", "pull_request"}, nil, teamActor("pull_request"))},
			open:        []string{"pull_request"},
			circumvents: []string{"bypass_pull_request"},
		},
		{
			name:        "a role-named bypass actor leaves the gate unproven",
			rulesets:    []map[string]any{branchRuleset(1, []string{"pull_request"}, []any{map[string]any{"actor_type": "RepositoryRole", "bypass_mode": "always"}}, nil)},
			open:        []string{"pull_request"},
			circumvents: []string{"bypass_unproven"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			edges, _ := capabilityChain(bareRepo(), tc.rulesets)
			edge := edges["user__u"]
			if edge == nil {
				t.Fatal("no edge for user__u")
			}
			if got := edgeStrings(t, edge, "routes_open"); !slices.Equal(got, tc.open) {
				t.Errorf("routes_open = %v, want %v", got, tc.open)
			}
			want := tc.circumvents
			if want == nil {
				want = []string{}
			}
			if got := edgeStrings(t, edge, "circumvents"); !slices.Equal(got, want) {
				t.Errorf("circumvents = %v, want %v", got, want)
			}
		})
	}
}

func TestCapabilityDeployKeyNeverMergesAPullRequest(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rulesets []map[string]any
		open     []string
	}{
		{"unprotected", nil, []string{"direct_push"}},
		{"pull request required", []map[string]any{branchRuleset(1, []string{"pull_request"}, nil, nil)}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			edges, _ := capabilityChain(bareRepo(), tc.rulesets)
			edge := edges["dk"]
			if edge == nil {
				t.Fatal("deploy key edge dropped; write access is a fact even when no route is open")
			}
			if got := edgeStrings(t, edge, "routes_open"); !slices.Equal(got, tc.open) {
				t.Errorf("routes_open = %v, want %v", got, tc.open)
			}
		})
	}
}

func TestBranchCoverageIgnoresTagRulesets(t *testing.T) {
	tagRuleset := branchRuleset(1, []string{"update", "deletion"}, nil, nil)
	tagRuleset["target"] = "tag"

	edges, eff := capabilityChain(bareRepo(), []map[string]any{tagRuleset})
	if got := mGet(eff, "active_ruleset_count"); got != 0 {
		t.Errorf("active_ruleset_count = %v, want 0 — a tag ruleset does not gate a branch", got)
	}
	if got := edgeStrings(t, edges["user__u"], "routes_open"); !slices.Equal(got, []string{"direct_push", "pull_request"}) {
		t.Errorf("routes_open = %v, want both routes open", got)
	}
}

// fr-03-08/main ticks "Do not allow bypassing the above settings";
// conf-shared-actions/main leaves it at GitHub's unchecked default, where a repo
// admin still pushes straight to the branch.
func TestEffectiveGapsFromLegacyProtection(t *testing.T) {
	for _, tc := range []struct {
		name          string
		enforceAdmins bool
		adminOpen     []string
	}{
		{"enforced admins take the PR route like everyone else", true, []string{"pull_request"}},
		{"an unenforced admin pushes directly", false, []string{"direct_push", "pull_request"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := bareRepo()
			repo["default_branch_protection_present"] = true
			repo["default_branch_protection_summary"] = map[string]any{
				"required_reviews": float64(1), "enforce_admins": tc.enforceAdmins, "required_status_checks": true,
				"restrictions_present": false, "lock_branch": false, "required_pull_request_reviews": true,
				"dismiss_stale_reviews": true, "require_code_owner_reviews": true, "require_last_push_approval": true,
			}

			edges, eff := capabilityChain(repo, nil)
			if got, ok := eff["gaps"].([]string); !ok || !slices.Equal(got, []string{"single_approval_required"}) {
				t.Errorf("gaps = %v, want [single_approval_required]", eff["gaps"])
			}
			if n, ok := numericValue(mGet(eff, "effective_required_approving_review_count")); !ok || n != 1 {
				t.Errorf("effective_required_approving_review_count = %v, want 1 — classic protection supplies it",
					mGet(eff, "effective_required_approving_review_count"))
			}
			if got := edgeStrings(t, edges["user__u"], "routes_open"); !slices.Equal(got, []string{"pull_request"}) {
				t.Errorf("routes_open = %v, want [pull_request] — legacy protection requires a PR", got)
			}
			if got := edgeStrings(t, edges["user__a"], "routes_open"); !slices.Equal(got, tc.adminOpen) {
				t.Errorf("admin routes_open = %v, want %v", got, tc.adminOpen)
			}
		})
	}
}

// current_user_can_bypass in 00-collect/rulesets is "always" for the collecting
// org owner on fr-11-01 (only role actor id 5) and fr-11-05 (only actor id 2), so
// a role actor is bypassed by every principal ranked at or above it.
func TestCapabilityRepositoryRoleBypass(t *testing.T) {
	both := []string{"direct_push", "pull_request"}
	for _, tc := range []struct {
		name        string
		actorID     int
		principal   string
		open        []string
		circumvents []string
	}{
		{"an admin bypasses the repo-admin actor", 5, "user__a", both, []string{"admin_can_remove_control", "bypass_always"}},
		{"a writer provably does not", 5, "user__u", []string{"pull_request"}, []string{}},
		{"an admin bypasses a lower-ranked actor", 2, "user__a", both, []string{"admin_can_remove_control", "bypass_always"}},
		{"a writer outranks a triage actor", 2, "user__u", both, []string{"bypass_always"}},
		{"a custom role id names nobody the run can identify", 8123, "user__u", []string{"pull_request"}, []string{"bypass_unproven"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			edges, _ := capabilityChain(bareRepo(), []map[string]any{
				branchRuleset(1, []string{"pull_request"}, roleActor(tc.actorID), nil)})
			edge := edges[tc.principal]
			if got := edgeStrings(t, edge, "routes_open"); !slices.Equal(got, tc.open) {
				t.Errorf("routes_open = %v, want %v", got, tc.open)
			}
			if got := edgeStrings(t, edge, "circumvents"); !slices.Equal(got, tc.circumvents) {
				t.Errorf("circumvents = %v, want %v", got, tc.circumvents)
			}
		})
	}
}

// fr-04-05-org-secrets-scoped-to-all-or-archived-repos is archived, and GitHub
// makes an archived repository read-only for everyone, org owners included.
func TestCapabilityArchivedRepositoryIsReadOnly(t *testing.T) {
	repo := bareRepo()
	repo["archived"] = true

	edges, _ := capabilityChain(repo, nil)
	for _, id := range []string{"user__u", "user__a", "dk"} {
		edge := edges[id]
		if edge == nil {
			t.Fatalf("%s edge dropped; write access is a fact even when no route is open", id)
		}
		if got := edgeStrings(t, edge, "routes_open"); len(got) > 0 {
			t.Errorf("%s routes_open = %v, want none — the repository is archived", id, got)
		}
	}
	if got := edgeStrings(t, edges["user__a"], "circumvents"); !slices.Contains(got, "admin_can_unarchive") {
		t.Errorf("admin circumvents = %v, want admin_can_unarchive — an admin unarchives, then pushes", got)
	}
}

func branchGaps(t *testing.T, effective []map[string]any, branch string) []string {
	t.Helper()
	for _, e := range effective {
		if mStr(e, "branch") == branch {
			g, ok := e["gaps"].([]string)
			if !ok {
				t.Fatalf("gaps on %s is %T, want []string", branch, e["gaps"])
			}
			return g
		}
	}
	t.Fatalf("no effective record for branch %s", branch)
	return nil
}

// Collect fetches classic protection for the default branch only, yet fr-11-02
// configures it on release branches — so on any other ref the run has not looked
// and cannot report the branch as uncontrolled.
func TestNoControlNeedsTheBranchToHaveBeenLookedAt(t *testing.T) {
	_, coverage := deriveBranchCoverage([]map[string]any{bareRepo()}, nil, map[string][]string{"r": {"main", "release/1.0"}})
	_, effective := deriveEffectiveRuleset(coverage, nil, nil)

	if got := branchGaps(t, effective, "main"); !slices.Contains(got, "no_control") {
		t.Errorf("main gaps = %v, want no_control — its protection was fetched and is absent", got)
	}
	got := branchGaps(t, effective, "release/1.0")
	if slices.Contains(got, "no_control") {
		t.Errorf("release/1.0 gaps = %v, must not claim no_control from protection never fetched", got)
	}
	if !slices.Contains(got, "control_visibility_unknown") {
		t.Errorf("release/1.0 gaps = %v, want control_visibility_unknown", got)
	}
}

// fr-11-17 carries an org ruleset scoped to repository_property
// trajan_fixture_tier=gated. Repo properties are not collected, so applying it
// would report protection on every branch in the org.
func TestBranchCoverageNamesUnevaluableOrgRuleset(t *testing.T) {
	rs := branchRuleset(20204716, []string{"pull_request"}, nil, nil)
	rs["scope"] = "org"
	rs["conditions"] = map[string]any{
		"ref_name": map[string]any{"include": []any{"refs/heads/main"}, "exclude": []any{}},
		"repository_property": map[string]any{"include": []any{
			map[string]any{"name": "trajan_fixture_tier", "property_values": []any{"gated"}}}},
	}

	_, coverage := deriveBranchCoverage([]map[string]any{bareRepo()}, []map[string]any{rs}, map[string][]string{"r": {"main"}})
	if got := mGet(coverage[0], "applicable_count"); got != 0 {
		t.Errorf("applicable_count = %v, want 0 — a property condition the run cannot read fails closed", got)
	}
	if got := listOrEmpty(coverage[0], "org_rulesets_unevaluable"); len(got) != 1 || idKey(got[0]) != "20204716" {
		t.Errorf("org_rulesets_unevaluable = %v, want [20204716]", got)
	}
}

// fr-11-08's ruleset has an always-mode Integration bypass actor naming an app
// id, so only that app circumvents the gate; its RepositoryRole actor names a role
// no app installation holds, so it must neither match an app nor leave one unproven.
func TestCapabilityAppInstallationBypassMatchesOnAppID(t *testing.T) {
	app := func(slug string, id int, selection, contents, administration string) map[string]any {
		return map[string]any{
			"_id": slug, "app_slug": slug, "app_id": float64(id),
			"repository_selection": selection,
			"permissions":          map[string]any{"contents": contents, "administration": administration},
		}
	}
	apps := []map[string]any{
		app("fr-app-bypass-actor", 3917874, "all", "write", ""),
		app("fr-app-broad-admin", 3917697, "all", "write", "write"),
		app("fr-app-narrow", 3917842, "all", "read", ""),
		app("conf-gh-bot", 4341547, "selected", "write", ""),
	}
	rulesets := []map[string]any{branchRuleset(1, []string{"pull_request"}, []any{
		map[string]any{"actor_id": float64(3917874), "actor_type": "Integration", "bypass_mode": "always"},
		map[string]any{"actor_id": float64(3), "actor_type": "RepositoryRole", "bypass_mode": "always"},
	}, nil)}

	repos := []map[string]any{bareRepo()}
	_, coverage := deriveBranchCoverage(repos, rulesets, map[string][]string{"r": {"main"}})
	_, effective := deriveEffectiveRuleset(coverage, rulesets, repos)
	byApp := map[string]map[string]any{}
	for _, e := range deriveCapabilityEdges(effective, nil, nil, repos, apps, nil)["edges"].([]map[string]any) {
		byApp[mStr(e, "principal_name")] = e
	}
	if len(byApp) != 2 {
		t.Fatalf("got %d app principals %v, want only the two with repository_selection all and contents write",
			len(byApp), slices.Sorted(maps.Keys(byApp)))
	}

	actor := byApp["fr-app-bypass-actor"]
	if got := edgeStrings(t, actor, "circumvents"); !slices.Contains(got, "bypass_always") {
		t.Errorf("bypass actor circumvents %v, want bypass_always", got)
	}
	if got := edgeStrings(t, actor, "routes_open"); !slices.Contains(got, "direct_push") {
		t.Errorf("bypass actor routes_open %v, want direct_push", got)
	}
	if got := mStr(actor, "write_via"); got != "app_installation" {
		t.Errorf("write_via = %q, want app_installation", got)
	}
	if got := mList(actor, "bypass_actors_matched"); len(got) != 1 {
		t.Errorf("matched %v, want only the Integration actor", got)
	}

	admin := byApp["fr-app-broad-admin"]
	for _, unwanted := range []string{"bypass_always", "bypass_pull_request", "bypass_unproven"} {
		if got := edgeStrings(t, admin, "circumvents"); slices.Contains(got, unwanted) {
			t.Errorf("broad-admin circumvents %v; %q must not come from an actor naming another app or a repository role", got, unwanted)
		}
	}
	// administration: write is the app analog of repo admin — the permission
	// that removes the repo-scope ruleset rather than passing it.
	if got := edgeStrings(t, admin, "circumvents"); !slices.Contains(got, "admin_can_remove_control") {
		t.Errorf("broad-admin circumvents %v, want admin_can_remove_control", got)
	}
	if got := edgeStrings(t, admin, "routes_blocked"); !slices.Contains(got, "direct_push") {
		t.Errorf("broad-admin routes_blocked %v, want direct_push", got)
	}
}

// Oracle is the portus-labs configuration read out of band: shared-workflows/main
// requires one approving review with no bypass actors and the org-wide "Actions can
// approve pull requests" toggle on, so portus-bot merges without a human.
func TestCapabilityApprovalCountSelfSatisfiable(t *testing.T) {
	prRuleset := func(approvals float64) []map[string]any {
		rs := branchRuleset(1, []string{"pull_request"}, nil, nil)
		rs["required_approving_review_count"] = approvals
		return []map[string]any{rs}
	}
	approveRepo := func() map[string]any {
		r := bareRepo()
		r["can_approve_pull_request_reviews"] = true
		r["actions_enabled"] = true
		return r
	}

	cases := []struct {
		name     string
		repo     map[string]any
		rulesets []map[string]any
		want     bool
	}{
		{"one approval an Actions run can cast", approveRepo(), prRuleset(1), true},
		// One repository, one Actions identity, and GitHub refuses a self-review,
		// so the second approval still has to come from a person.
		{"two approvals still cost a human", approveRepo(), prRuleset(2), false},
		{"toggle off means the token's review does not count", bareRepo(), prRuleset(1), false},
		{"no gate to satisfy", approveRepo(), nil, false},
		{
			name:     "Actions disabled leaves no run to cast it",
			repo:     func() map[string]any { r := approveRepo(); r["actions_enabled"] = false; return r }(),
			rulesets: prRuleset(1), want: false,
		},
		{
			name: "a principal the rule never bound has nothing to satisfy",
			repo: approveRepo(),
			rulesets: func() []map[string]any {
				rs := branchRuleset(1, []string{"pull_request"}, teamActor("always"), nil)
				rs["required_approving_review_count"] = float64(1)
				return []map[string]any{rs}
			}(),
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			byPrincipal, _ := capabilityChain(tc.repo, tc.rulesets)
			got := slices.Contains(edgeStrings(t, byPrincipal["user__u"], "circumvents"),
				"approval_count_self_satisfiable")
			if got != tc.want {
				t.Errorf("approval_count_self_satisfiable = %v, want %v (circumvents=%v)",
					got, tc.want, byPrincipal["user__u"]["circumvents"])
			}
		})
	}
}
