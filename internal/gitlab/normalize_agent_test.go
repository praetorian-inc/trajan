package gitlab

import (
	"slices"
	"testing"
)

// The agent ci_access config schema is GitLab's documented format
// (https://docs.gitlab.com/user/clusters/agent/ci_cd_workflow): a top-level
// ci_access with projects:/groups: entries, each carrying environments,
// default_namespace, protected_branches_only, and an optional access_as
// impersonation block. The firing-range cat-15 agents come back 403 over the
// SaaS token, so these assert parseAgentConfig against that external schema
// rather than corpus output.

func TestParseAgentConfigCIAccessProjectScope(t *testing.T) {
	cfg := parseAgentConfig([]byte(`
gitops: {}
ci_access:
  projects:
    - id: group/app
      environments:
        - production
        - review/*
      protected_branches_only: true
`))
	envs := entListOrEmpty(cfg["environments"])
	got := make([]string, 0, len(envs))
	for _, e := range envs {
		got = append(got, entStr(e))
	}
	if !slices.Equal(got, []string{"production", "review/*"}) {
		t.Fatalf("environments=%v want [production review/*]", got)
	}
	if cfg["protected_branches_only"] != true {
		t.Errorf("protected_branches_only=%v want true", cfg["protected_branches_only"])
	}
	// No access_as → default (broad) permissions.
	if !agentDefaultPermissions(cfg) {
		t.Error("no access_as block must mean default_permissions=true")
	}
}

func TestParseAgentConfigImpersonationDisablesDefault(t *testing.T) {
	cfg := parseAgentConfig([]byte(`
ci_access:
  projects:
    - id: group/app
      access_as:
        ci_job: {}
`))
	if _, ok := cfg["access_as"]; !ok {
		t.Fatal("access_as not surfaced")
	}
	if agentDefaultPermissions(cfg) {
		t.Error("an access_as impersonation block must set default_permissions=false")
	}
}

func TestParseAgentConfigGroupScope(t *testing.T) {
	// environments/protected_branches_only can live under a groups: entry too; the
	// first-access lookup must reach it.
	cfg := parseAgentConfig([]byte(`
ci_access:
  groups:
    - id: top-group
      environments:
        - "*"
`))
	envs := entListOrEmpty(cfg["environments"])
	if len(envs) != 1 || entStr(envs[0]) != "*" {
		t.Fatalf("environments=%v want [*]", envs)
	}
}

func TestParseAgentConfigMalformedIsEmpty(t *testing.T) {
	if got := parseAgentConfig([]byte("\t: not: yaml:")); len(got) != 0 {
		t.Errorf("malformed config must parse to empty map, got %v", got)
	}
	if got := parseAgentConfig(nil); len(got) != 0 {
		t.Errorf("nil config must be empty map, got %v", got)
	}
}

// The wildcard classifier is what cat-15 keys on to detect a forgeable env
// filter. It must fire on a bare * and on prefix/suffix globs, not on fixed names.
func TestAgentEnvWildcardClassification(t *testing.T) {
	wild := []string{"*", "review/*", "*-preview"}
	for _, s := range wild {
		if !containsWildcard([]any{s}) {
			t.Errorf("%q must classify as wildcard env filter", s)
		}
	}
	fixed := []string{"production", "staging", "review"}
	if containsWildcard(toAnyList(fixed)) {
		t.Error("a filter of only fixed names must not be a wildcard filter")
	}
}

// containsWildcard mirrors the environments_filter_wildcard predicate the agent
// normalizer computes inline (anyStr over strings.Contains "*").
func containsWildcard(envs []any) bool {
	return anyStr(envs, func(s string) bool { return contains(s, "*") })
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func toAnyList(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
