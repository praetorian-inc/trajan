package engine

import "testing"

func TestGLKey(t *testing.T) {
	cases := map[string]string{
		"trajan-fr-group/trjfx": "trajan-fr-group-trjfx",
		"a_b":                   "a-b",
		"Foo.Bar":               "Foo.Bar",
		"":                      "_",
		"x/y z":                 "x-y-z",
	}
	for in, want := range cases {
		if got := glKey(in); got != want {
			t.Errorf("glKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCollectGLPaths(t *testing.T) {
	cases := map[string]string{
		CollectGLGroup("trajan-fr-group/trjfx"):        "00-collect/group/trajan-fr-group-trjfx.json",
		CollectGLProject("trajan-fr-group/trjfx/proj"): "00-collect/project/trajan-fr-group-trjfx-proj.json",
		CollectGLGroupMembers("g"):                     "00-collect/members/group/g.json",
		CollectGLProjectMembers("g/p"):                 "00-collect/members/project/g-p.json",
		CollectGLRunnerProjects(42):                    "00-collect/runner-projects/42.json",
		CollectGLInstanceRunners():                     "00-collect/runners/instance.json",
		CollectGLCIConfig("g/p", ".gitlab-ci.yml"):     "00-collect/ci-config/g-p/.gitlab-ci.yml",
		CollectGLClusterAgents("g/p"):                  "00-collect/cluster-agents/g-p.json",
		CollectGLExternalStatusChecks("g/p"):           "00-collect/external-status-checks/g-p.json",
		CollectGLPackageProtectionRules("g/p"):         "00-collect/package-protection-rules/g-p.json",
		CollectGLSecureFiles("g/p"):                    "00-collect/secure-files/g-p.json",
		CollectGLTerraformState("g/p"):                 "00-collect/terraform-state/g-p.json",
		CollectGLSecurityPolicies("g/p"):               "00-collect/security-policies/g-p.json",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("path = %q, want %q", got, want)
		}
	}
}
