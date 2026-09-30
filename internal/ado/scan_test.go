package ado

import (
	"slices"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine/detect"
)

func TestADORepoAttributionPerSubjectKind(t *testing.T) {
	cases := []struct {
		kind    string
		subject map[string]any
		want    string
	}{
		{"org", map[string]any{"_id": "Fabrikam", "kind": "Organization"}, ""},
		{"project", map[string]any{"_id": "Fabrikam/Shop", "kind": "Project", "project": "Shop"}, ""},
		{"repo", map[string]any{
			"_id": "Fabrikam/Shop/shop-api", "kind": "Repository",
			"project": "Shop", "name": "shop-api",
		}, "Shop/shop-api"},
		{"repository", map[string]any{
			"_id": "Fabrikam/Shop/shop-web", "kind": "Repository",
			"project": "Shop", "name": "shop-web",
		}, "Shop/shop-web"},
		{"pipeline", map[string]any{
			"_id": "Shop/3", "kind": "Pipeline", "project": "Shop",
			"name": "shop-api-ci",
			"repository": map[string]any{
				"id": "22222222-2222-4222-8222-222222222222", "name": "shop-api", "type": "TfsGit",
			},
		}, "Shop/shop-api"},
		{"stage", map[string]any{
			"_id": "3/deploy", "kind": "Stage", "project": "Shop", "repo": "shop-api",
		}, "Shop/shop-api"},
		{"job", map[string]any{
			"_id": "3/deploy/ship", "kind": "Job", "project": "Shop", "repo": "shop-api",
		}, "Shop/shop-api"},
		{"branch", map[string]any{
			"_id": "Shop/shop-api@main", "kind": "Branch",
			"project": "Shop", "repo": "shop-api", "name": "main",
		}, "Shop/shop-api"},
		{"branch_policy", map[string]any{
			"_id": "Shop/3", "kind": "BranchPolicy", "project": "Shop", "repo": "shop-api",
		}, "Shop/shop-api"},
		{"service_connection", map[string]any{
			"_id": "Shop/7fdc98af", "kind": "ServiceConnection",
			"project": "Shop", "name": "azure-retail-prod",
		}, ""},
		{"variable_group", map[string]any{
			"_id": "Shop/1", "kind": "VariableGroup", "project": "Shop", "name": "shop-prod-secrets",
		}, ""},
		{"secret_variable", map[string]any{
			"_id": "1/PAYMENT_PROVIDER_TOKEN", "kind": "SecretVariable",
			"project": "Shop", "name": "PAYMENT_PROVIDER_TOKEN",
		}, ""},
		{"environment", map[string]any{
			"_id": "Shop/prod", "kind": "Environment", "project": "Shop", "name": "prod",
		}, ""},
		{"feed", map[string]any{"_id": "org/3b30e074", "kind": "ArtifactsFeed", "name": "Fabrikam"}, ""},
		{"key_vault", map[string]any{
			"_id": "Shop/retail-kv", "kind": "KeyVault", "project": "Shop", "name": "retail-kv",
		}, ""},
		{"extension", map[string]any{"_id": "ms.azure-artifacts", "kind": "Extension", "org": "Fabrikam"}, ""},
		{"secure_file", map[string]any{
			"_id": "Shop/sf-1", "kind": "SecureFile", "project": "Shop", "name": "signing.pfx",
		}, ""},
		{"service_hook", map[string]any{
			"_id": "sub-1", "kind": "ServiceHookSubscription", "org": "Fabrikam",
			"project": "66666666-6666-4666-8666-666666666666",
		}, ""},
		{"agent_pool", map[string]any{"_id": "1", "kind": "OrgAgentPool", "name": "Default"}, ""},
		{"queue_time_injection", map[string]any{
			"kind": "QUEUE_TIME_INJECTION", "project": "Shop", "repo": "shop-checkout",
			"pipeline_id": float64(4), "stage": "build", "job": "compile",
		}, "Shop/shop-checkout"},
		{"logging_command_injection", map[string]any{
			"kind": "LOGGING_COMMAND_INJECTION", "project": "Shop", "repo": "shop-admin",
			"pipeline_id": float64(5), "stage": "build", "job": "compile",
		}, "Shop/shop-admin"},
		{"agent_injection", map[string]any{
			"kind": "AGENT_INJECTION", "project": "Shop", "repo": "shop-web",
			"pipeline_id": float64(2), "stage": "review", "job": "agent",
		}, "Shop/shop-web"},
		{"pipeline_poisoning", map[string]any{
			"kind": "PIPELINE_POISONING", "project": "Shop", "repo": "shop-api",
			"pipeline_id": float64(3), "stage": "build", "job": "compile",
		}, "Shop/shop-api"},
		{"reads", map[string]any{
			"kind": "READS", "project": "Shop", "repo": "shop-api",
			"variable_group_id": float64(1), "secret_name": "PAYMENT_PROVIDER_TOKEN",
		}, "Shop/shop-api"},
		{"can_push_to", map[string]any{
			"kind": "CAN_PUSH_TO", "project": "Shop", "repo": "shop-web", "target": "main",
		}, "Shop/shop-web"},
		{"can_merge_via_pr", map[string]any{
			"kind": "CAN_MERGE_VIA_PR", "project": "Shop", "repo": "shop-web", "target": "main",
		}, "Shop/shop-web"},
		{"can_bypass", map[string]any{
			"kind": "CAN_BYPASS", "project": "Shop", "repo": "shop-admin", "target": "Shop/5",
		}, "Shop/shop-admin"},
	}

	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			if _, ok := adoScanProvider.SubjectDirs[tc.kind]; !ok {
				t.Fatalf("%q is not a subject kind the provider serves", tc.kind)
			}
			if got := adoRepo(tc.subject); got != tc.want {
				t.Errorf("adoRepo = %q, want %q", got, tc.want)
			}
		})
	}

	covered := map[string]bool{}
	for _, tc := range cases {
		covered[tc.kind] = true
	}
	for kind := range adoScanProvider.SubjectDirs {
		if !covered[kind] {
			t.Errorf("subject kind %q has no repo-attribution case", kind)
		}
	}
}

func TestADORepoRejectsNonAzureReposPipeline(t *testing.T) {
	for _, repoType := range []string{"GitHub", "Bitbucket", "GitHubEnterprise", "Git", ""} {
		subject := map[string]any{
			"_id": "Shop/9", "kind": "Pipeline", "project": "Shop", "name": "external-ci",
			"repository": map[string]any{"id": "octocat/hello", "name": "hello", "type": repoType},
		}
		if got := adoRepo(subject); got != "" {
			t.Errorf("repository type %q: adoRepo = %q, want empty", repoType, got)
		}
	}
	tfsgit := map[string]any{
		"_id": "Shop/3", "kind": "Pipeline", "project": "Shop", "name": "shop-api-ci",
		"repository": map[string]any{"name": "shop-api", "type": "tfsgit"},
	}
	if got := adoRepo(tfsgit); got != "Shop/shop-api" {
		t.Errorf("lowercase tfsgit: adoRepo = %q, want Shop/shop-api", got)
	}
}

func TestADOHierarchyRulesKeepOrgAndProjectSubjects(t *testing.T) {
	rules, err := detect.LoadRules("ado", nil)
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	want := map[string]int{}
	for _, r := range rules {
		if slices.Contains(adoScanProvider.HierarchyKinds, r.SubjectKind()) {
			want[r.SubjectKind()]++
		}
	}
	for _, kind := range adoScanProvider.HierarchyKinds {
		if want[kind] == 0 {
			t.Fatalf("the ado corpus has no %q-subject rule to filter for", kind)
		}
	}

	// HierarchyRules mutates its input via slices.DeleteFunc, so clone first.
	got := map[string]int{}
	hierarchy := detect.HierarchyRules(slices.Clone(rules), adoScanProvider.HierarchyKinds)
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
		if !slices.Contains(adoScanProvider.HierarchyKinds, kind) {
			t.Errorf("hierarchy set leaked a %q-subject rule", kind)
		}
	}
}
