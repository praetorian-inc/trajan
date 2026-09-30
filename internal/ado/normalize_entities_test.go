package ado

import (
	"fmt"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

const (
	shopWeb      = "11111111-1111-4111-8111-111111111111"
	shopAPI      = "22222222-2222-4222-8222-222222222222"
	shopCheckout = "33333333-3333-4333-8333-333333333333"
	shopAdmin    = "44444444-4444-4444-8444-444444444444"
)

var shopRepoNames = map[string]string{
	shopWeb:      "shop-web",
	shopAPI:      "shop-api",
	shopCheckout: "shop-checkout",
	shopAdmin:    "shop-admin",
}

func scopeEntry(repoID any, ref string) any {
	e := map[string]any{"refName": ref, "matchKind": "Exact"}
	if repoID != nil {
		e["repositoryId"] = repoID
	}
	return e
}

func TestPolicyRepoResolvesScopeToOneRepository(t *testing.T) {
	cases := []struct {
		name  string
		scope []any
		want  string
	}{
		{"one repository", []any{scopeEntry(shopAPI, "refs/heads/main")}, "shop-api"},
		{"two refs of one repository", []any{
			scopeEntry(shopAPI, "refs/heads/main"),
			scopeEntry(shopAPI, "refs/heads/release"),
		}, "shop-api"},
		{"two repositories", []any{
			scopeEntry(shopAPI, "refs/heads/main"),
			scopeEntry(shopWeb, "refs/heads/main"),
		}, ""},
		{"null repositoryId", []any{scopeEntry(nil, "refs/heads/main")}, ""},
		{"null repositoryId beside a named one", []any{
			scopeEntry(shopAPI, "refs/heads/main"),
			scopeEntry(nil, "refs/heads/main"),
		}, ""},
		{"unresolvable repositoryId", []any{
			scopeEntry("11111111-2222-3333-4444-555555555555", "refs/heads/main"),
		}, ""},
		{"unresolvable repositoryId before a named one", []any{
			scopeEntry("11111111-2222-3333-4444-555555555555", "refs/heads/main"),
			scopeEntry(shopAPI, "refs/heads/main"),
		}, ""},
		{"unresolvable repositoryId after a named one", []any{
			scopeEntry(shopAPI, "refs/heads/main"),
			scopeEntry("11111111-2222-3333-4444-555555555555", "refs/heads/main"),
		}, ""},
		{"empty scope", []any{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := policyRepo(tc.scope, shopRepoNames); got != tc.want {
				t.Errorf("policyRepo = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNormalizePoliciesJoinsScopeGUIDToRepositoryName(t *testing.T) {
	dir := t.TempDir()
	cp, prior := engineCP(dir), engine.PriorPhase{RunDir: dir}

	repos := []any{}
	for id, name := range shopRepoNames {
		repos = append(repos, map[string]any{"id": id, "name": name})
	}
	writeCollect(t, dir, engine.CollectADORepos("Shop"), repos)

	const typeID = "55555555-5555-4555-8555-555555555555"
	policies := []any{}
	for i, repoID := range []string{shopWeb, shopAPI, shopCheckout, shopAdmin} {
		policies = append(policies, map[string]any{
			"id":         float64(i + 2),
			"type":       map[string]any{"id": typeID, "displayName": "Minimum number of reviewers"},
			"isEnabled":  true,
			"isBlocking": true,
			"settings":   map[string]any{"scope": []any{scopeEntry(repoID, "refs/heads/main")}},
		})
	}
	writeCollect(t, dir, engine.CollectADOPolicies("Shop"), policies)

	if err := normalizePolicies(prior, cp, "Fabrikam", projectMeta{ID: "p", Name: "Shop"}, normTimer()); err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	for i, want := range []string{"shop-web", "shop-api", "shop-checkout", "shop-admin"} {
		rel := engine.NormalizeADOPolicy("Shop", fmt.Sprintf("cfg-%d", i+2), "Minimum number of reviewers")
		rec := readRec(t, dir, rel)
		if rec["repo"] != want {
			t.Errorf("policy cfg-%d repo = %v, want %q", i+2, rec["repo"], want)
		}
		if got := adoRepo(rec); got != "Shop/"+want {
			t.Errorf("policy cfg-%d attributes to %q, want Shop/%s", i+2, got, want)
		}
		seen[fmt.Sprint(rec["repo"])] = true
	}
	if len(seen) != 4 {
		t.Errorf("the four policies resolved to %d distinct repositories, want 4", len(seen))
	}
}
