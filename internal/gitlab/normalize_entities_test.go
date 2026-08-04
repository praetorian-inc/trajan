package gitlab

import "testing"

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"main", "main", true},
		{"main", "develop", false},
		{"release/*", "release/1.0", true},
		{"release/*", "main", false},
		{"*", "anything", true},
		{"v*", "v1", true},
		{"v*", "x1", false},
		{"*-prod", "app-prod", true},
		{"*-prod", "app-dev", false},
		{"a*b", "aXXb", true},
		{"a*b", "aXX", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.name); got != c.want {
			t.Errorf("globMatch(%q,%q)=%v want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestSecretShapedKey(t *testing.T) {
	secret := []string{"PROD_DEPLOY_KEY", "AWS_SECRET_ACCESS_KEY", "npm_token", "DB_PASSWORD", "API_KEY", "GCP_SA_JSON"}
	for _, k := range secret {
		if !secretShapedKey(k) {
			t.Errorf("secretShapedKey(%q)=false want true", k)
		}
	}
	// Ordinary config keys must not fire — the three unprotected-secret booleans
	// rest on this precision.
	plain := []string{"CI_DEBUG_LEVEL", "ENVIRONMENT", "REGION", "BUILD_NUMBER", "STAGE"}
	for _, k := range plain {
		if secretShapedKey(k) {
			t.Errorf("secretShapedKey(%q)=true want false", k)
		}
	}
}

func TestClassifySelfManaged(t *testing.T) {
	saasShared := map[string]any{
		"runner_type": "instance_type", "is_shared": true,
		"description": "1-blue-2.saas-linux-small-amd64.runners-manager.gitlab.com/default",
	}
	if classifySelfManaged(saasShared) {
		t.Error("gitlab.com SaaS shared runner classified self_managed=true")
	}
	selfHosted := map[string]any{
		"runner_type": "project_type", "is_shared": false, "platform": "linux",
		"description": "ops-k8s-runner-01",
	}
	if !classifySelfManaged(selfHosted) {
		t.Error("operator-run project runner classified self_managed=false")
	}
}

func TestDuoGuardrailUppercaseVerbatim(t *testing.T) {
	duo := map[string]any{"duoSettings": map[string]any{"promptInjectionProtectionLevel": "LOG_ONLY"}}
	if got := duoGuardrail(duo, "instance"); got != "LOG_ONLY" {
		t.Errorf("duoGuardrail=%v want LOG_ONLY (uppercase verbatim, never lowercased)", got)
	}
	group := map[string]any{"group": map[string]any{"aiSettings": map[string]any{"promptInjectionProtectionLevel": "INTERRUPT"}}}
	if got := duoGuardrail(group, "group"); got != "INTERRUPT" {
		t.Errorf("duoGuardrail(group)=%v want INTERRUPT", got)
	}
	if got := duoGuardrail(map[string]any{"_unobserved": float64(403)}, "instance"); got != nil {
		t.Errorf("unobserved duo guardrail=%v want nil", got)
	}
}

func TestRoleNameToLevel(t *testing.T) {
	// GitLab may return the group default_membership_role as either enum or int.
	if roleNameToLevel("developer") != accessDeveloper {
		t.Error("string developer did not map to 30")
	}
	if roleNameToLevel(float64(40)) != accessMaintainer {
		t.Error("numeric 40 did not map to maintainer")
	}
	if levelToRoleName(accessGuest) != "guest" {
		t.Error("10 did not map to guest")
	}
}

func TestJobTokenAllowlistMode(t *testing.T) {
	disabled := jobTokenAllowlist(map[string]any{
		"job_token_scope": map[string]any{"inbound_enabled": false},
	})
	if disabled["mode"] != "disabled" {
		t.Errorf("mode=%v want disabled when inbound scope off", disabled["mode"])
	}
	projScoped := jobTokenAllowlist(map[string]any{
		"job_token_scope":     map[string]any{"inbound_enabled": true},
		"job_token_allowlist": []any{map[string]any{"path_with_namespace": "grp/proj"}},
	})
	if projScoped["mode"] != "project_scoped" {
		t.Errorf("mode=%v want project_scoped", projScoped["mode"])
	}
	if ents := projScoped["entries"].([]any); len(ents) != 1 || ents[0] != "grp/proj" {
		t.Errorf("entries=%v want [grp/proj]", projScoped["entries"])
	}
}

func TestShadowedByPermissive(t *testing.T) {
	// Two rules match "main"; one grants Maintainer (40), one grants Developer
	// (30). The broader rule shadows the tighter one.
	branches := []map[string]any{
		{"pattern": "main", "push_access_levels": []any{int64(40)}},
		{"pattern": "*", "push_access_levels": []any{int64(30)}},
	}
	if !shadowedByPermissive(branches, "push_access_levels") {
		t.Error("expected shadow when a wildcard Developer rule overlaps a Maintainer rule on main")
	}
	// A single consistent rule is not a shadow.
	single := []map[string]any{{"pattern": "main", "push_access_levels": []any{int64(40)}}}
	if shadowedByPermissive(single, "push_access_levels") {
		t.Error("single rule falsely reported as shadowed")
	}
}

func TestNearMissProtectedName(t *testing.T) {
	// Exact match is covered → not a near-miss.
	if nearMissProtected("production", []string{"production"}) {
		t.Error("exact protected name reported as near-miss")
	}
	// prod↔production alias, and review/ suffix are near-misses.
	if !nearMissProtected("prod", []string{"production"}) {
		t.Error("prod vs production alias not detected")
	}
	if !nearMissProtected("production/eu", []string{"production"}) {
		t.Error("production/eu suffix of protected name not detected")
	}
}

// TestGroupBranchProtectionEnum: the cat-03 rule reads default_branch_protection
// as the enum {none,partial,full}, not a raw int/object. A Developer-inclusive
// push grant (or force-push) is partial; a Maintainer-only grant is full.
func TestGroupBranchProtectionEnum(t *testing.T) {
	full := groupBranchProtection(map[string]any{
		"default_branch_protection_defaults": map[string]any{
			"allowed_to_push":  []any{map[string]any{"access_level": int64(40)}},
			"allow_force_push": false,
		},
	})
	if full != "full" {
		t.Errorf("Maintainer-only push = %v want full", full)
	}
	partial := groupBranchProtection(map[string]any{
		"default_branch_protection_defaults": map[string]any{
			"allowed_to_push": []any{map[string]any{"access_level": int64(30)}},
		},
	})
	if partial != "partial" {
		t.Errorf("Developer-inclusive push = %v want partial", partial)
	}
	// Legacy integer form: 0 none, 1 partial, 2 full.
	for in, want := range map[int64]string{0: "none", 1: "partial", 2: "full", 3: "full"} {
		if got := groupBranchProtection(map[string]any{"default_branch_protection": in}); got != want {
			t.Errorf("legacy default_branch_protection=%d => %v want %v", in, got, want)
		}
	}
}

// TestAgentImpersonationNil: cat-15 rules read impersonation == null. An absent
// access_as must serialize as nil, never {} (which never matches == null).
func TestAgentImpersonationNil(t *testing.T) {
	if got := agentImpersonation(map[string]any{}); got != nil {
		t.Errorf("no access_as => %v want nil", got)
	}
	if got := agentImpersonation(map[string]any{"access_as": map[string]any{}}); got != nil {
		t.Errorf("empty access_as => %v want nil", got)
	}
	cfg := map[string]any{"access_as": map[string]any{"ci_job": map[string]any{}}}
	if got := agentImpersonation(cfg); got == nil {
		t.Error("a real access_as block must be surfaced, not nil")
	}
}

// TestAgentEnvFilterUnprotected: a fixed filter name absent from protected
// environments (or protected only with a Developer-inclusive deployer) gates
// nothing; a wildcard name is not counted here (a separate wildcard fold covers it).
func TestAgentEnvFilterUnprotected(t *testing.T) {
	protEnvs := []any{
		map[string]any{"name": "production", "deploy_access_levels": []any{map[string]any{"access_level": int64(40)}}},
	}
	if agentEnvFilterUnprotected([]any{"production"}, protEnvs) {
		t.Error("a Maintainer-protected exact env must not be reported unprotected")
	}
	if !agentEnvFilterUnprotected([]any{"staging"}, protEnvs) {
		t.Error("an env with no protected entry must be reported unprotected")
	}
	devProt := []any{map[string]any{"name": "staging", "deploy_access_levels": []any{map[string]any{"access_level": int64(30)}}}}
	if !agentEnvFilterUnprotected([]any{"staging"}, devProt) {
		t.Error("a Developer-deployable protected env gates nothing")
	}
	if agentEnvFilterUnprotected([]any{"review/*"}, nil) {
		t.Error("a wildcard filter name must not be counted by the fixed-name unprotected check")
	}
}

func TestCloudCredKey(t *testing.T) {
	cloud := []string{"AWS_SECRET_ACCESS_KEY", "AZURE_CLIENT_SECRET", "GCP_SA_KEY", "GOOGLE_APPLICATION_CREDENTIALS", "ARM_CLIENT_SECRET"}
	for _, k := range cloud {
		if !cloudCredKey(k) {
			t.Errorf("cloudCredKey(%q)=false want true", k)
		}
	}
	// Generic secrets that are NOT static cloud creds must not mint a cloud cred.
	for _, k := range []string{"CI_JOB_TOKEN", "DB_PASSWORD", "NPM_TOKEN", "REGION"} {
		if cloudCredKey(k) {
			t.Errorf("cloudCredKey(%q)=true want false (not a cloud key)", k)
		}
	}
}

// TestStaticCloudCredInUnprotectedVariable: static_cloud_cred is the variable
// itself, so in_unprotected_variable is directly derivable from the variable's
// protected flag (not the deferred token-vs-variable leg).
func TestStaticCloudCredInUnprotectedVariable(t *testing.T) {
	unprot := staticCloudCredRec(map[string]any{"key": "AWS_SECRET_ACCESS_KEY", "protected": false}, "project")
	if unprot["in_unprotected_variable"] != true || unprot["kind"] != nil {
		t.Errorf("unprotected cloud var => in_unprotected_variable=%v", unprot["in_unprotected_variable"])
	}
	// cat-11 static_cloud_cred rule reads key_pattern == "cloud" (frozen rule).
	if unprot["key_pattern"] != "cloud" {
		t.Errorf("key_pattern=%v want cloud", unprot["key_pattern"])
	}
	prot := staticCloudCredRec(map[string]any{"key": "AWS_SECRET_ACCESS_KEY", "protected": true}, "project")
	if prot["in_unprotected_variable"] != false {
		t.Error("protected cloud var must set in_unprotected_variable=false")
	}
}

// TestRunnerTargetedBy: a tagged job needs the runner to carry all its tags; an
// untagged job needs run_untagged.
func TestRunnerTargetedBy(t *testing.T) {
	if !runnerTargetedBy([]string{"linux", "deploy"}, false, []any{"deploy"}) {
		t.Error("runner carrying the job's tag must be targetable")
	}
	if runnerTargetedBy([]string{"linux"}, false, []any{"deploy"}) {
		t.Error("runner missing a requested tag must not be targetable")
	}
	if !runnerTargetedBy(nil, true, nil) {
		t.Error("untagged job on a run_untagged runner must be targetable")
	}
	if runnerTargetedBy(nil, false, nil) {
		t.Error("untagged job on a runner that refuses untagged must not be targetable")
	}
}

func TestLevelHelpers(t *testing.T) {
	levels := []any{int64(30), int64(50)}
	if !levelsInclude(levels, accessDeveloper) {
		t.Error("levelsInclude missed 30")
	}
	if levelsInclude(levels, accessMaintainer) {
		t.Error("levelsInclude falsely matched 40")
	}
	if !levelsIncludeAtMost(levels, accessDeveloper) {
		t.Error("levelsIncludeAtMost missed a Developer-level actor")
	}
	if levelsIncludeAtMost([]any{int64(40), int64(50)}, accessDeveloper) {
		t.Error("levelsIncludeAtMost falsely matched a Maintainer-only list")
	}
}
