package github

import (
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
		{"_id": "team__t", "kind": "team", "slug": "t", "team_id": float64(99),
			"members": []any{map[string]any{"login": "u"}}, "repo_grants": []any{}},
	}
	deployKeys := []map[string]any{{"_id": "dk", "repo": "r", "can_push": true, "title": "dk"}}
	repos := []map[string]any{repo}

	_, coverage := deriveBranchCoverage(repos, rulesets, map[string][]string{"r": {"main"}})
	_, effective := deriveEffectiveRuleset(coverage, rulesets)

	byPrincipal := map[string]map[string]any{}
	for _, e := range deriveCapabilityEdges(effective, principals, deployKeys, repos)["edges"].([]map[string]any) {
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

func TestEffectiveGapsFromLegacyProtection(t *testing.T) {
	repo := bareRepo()
	repo["default_branch_protection_present"] = true
	repo["default_branch_protection_summary"] = map[string]any{
		"required_reviews": float64(1), "enforce_admins": true, "required_status_checks": true,
		"restrictions_present": false, "lock_branch": false, "required_pull_request_reviews": true,
		"dismiss_stale_reviews": true, "require_code_owner_reviews": true, "require_last_push_approval": true,
	}

	edges, eff := capabilityChain(repo, nil)
	if got, ok := eff["gaps"].([]string); !ok || !slices.Equal(got, []string{"single_approval_required"}) {
		t.Errorf("gaps = %v, want [single_approval_required]", eff["gaps"])
	}
	if got := edgeStrings(t, edges["user__u"], "routes_open"); !slices.Equal(got, []string{"pull_request"}) {
		t.Errorf("routes_open = %v, want [pull_request] — legacy protection requires a PR", got)
	}
}
