package gitlab

import (
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine/detect"
)

// The oracle is the rule YAML itself (internal/detection-rules/gitlab), loaded
// through the shared engine exactly as scan does — never what scan happens to
// emit. Each case below builds a synthetic positive fact record that satisfies a
// real rule's `where`, confirms it fires once, then flips one required predicate
// to its benign value (the "benign twin") and asserts zero matches. Asserting the
// positive fires first is what makes the silence meaningful: it proves the twin is
// silent because the flipped fact is benign, not because the record never matched.

func glRuleByID(t *testing.T, id string) *detect.Rule {
	t.Helper()
	rules, err := detect.LoadRules("gitlab")
	if err != nil {
		t.Fatalf("LoadRules(gitlab): %v", err)
	}
	for i := range rules {
		if rules[i].ID == id {
			return &rules[i]
		}
	}
	t.Fatalf("rule %q not found among %d gitlab rules", id, len(rules))
	return nil
}

func fireCount(t *testing.T, rule *detect.Rule, subj map[string]any) int {
	t.Helper()
	m := detect.EvaluateRule(rule, []map[string]any{subj}, func(err error) {
		t.Errorf("[%s] unexpected eval error: %v", rule.ID, err)
	})
	return len(m)
}

func chainFireCount(t *testing.T, rule *detect.Rule, item map[string]any, forEach string) int {
	t.Helper()
	data := map[string]any{forEach: []any{item}}
	m := detect.EvaluateChainRule(rule, data, func(err error) {
		t.Errorf("[%s] unexpected chain eval error: %v", rule.ID, err)
	})
	return len(m)
}

func clone(m map[string]any) map[string]any {
	c := make(map[string]any, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

// silenceCase pairs a positive fact record with a set of minimal-flip benign
// twins. Each twin overrides exactly one field of the positive to its benign
// value; the rule must go silent on it.
type silenceCase struct {
	id       string
	positive map[string]any
	twins    map[string]map[string]any // twin name -> field overrides
}

// runSilence exercises one non-chain rule: positive fires exactly once, every
// benign twin fires zero times.
func runSilence(t *testing.T, c silenceCase) {
	t.Helper()
	rule := glRuleByID(t, c.id)
	if n := fireCount(t, rule, c.positive); n != 1 {
		t.Fatalf("[%s] positive twin should fire once, got %d", c.id, n)
	}
	for name, overrides := range c.twins {
		twin := clone(c.positive)
		for k, v := range overrides {
			twin[k] = v
		}
		if n := fireCount(t, rule, twin); n != 0 {
			t.Errorf("[%s] benign twin %q should be silent, got %d matches", c.id, name, n)
		}
	}
}

// One representative rule per category (cat-01..15), covering all 11 non-chain
// subject kinds and the chain kind. Booleans are Go bools; numeric folds use
// float64 to mirror JSON decoding; sets are []any of strings.
func TestGitLabBenignTwinsSilence(t *testing.T) {
	cases := []silenceCase{
		{
			// cat-01 job: deployment-to-untrusted-ref triple.
			id: "cat-01/environment-deploy-untrusted-ref",
			positive: map[string]any{
				"_id":                         "grp/proj:deploy",
				"deploys_environment":         true,
				"env_scoped_secret_reachable": true,
				"runs_on_untrusted_ref":       true,
			},
			twins: map[string]map[string]any{
				"protected ref":      {"runs_on_untrusted_ref": false},
				"no env deploy":      {"deploys_environment": false},
				"secret unreachable": {"env_scoped_secret_reachable": false},
			},
		},
		{
			// cat-02 job: interpolated include ref gated by an any_of (set membership /
			// two booleans).
			id: "cat-02/branch-name-controlled-include",
			positive: map[string]any{
				"_id":                      "grp/proj:build",
				"include_ref_interpolated": true,
				"triggers":                 []any{"merge_request_event"},
			},
			twins: map[string]map[string]any{
				"not interpolated": {"include_ref_interpolated": false},
				"benign any_of": {
					"triggers":                 []any{"push"},
					"reads_cicd_variable":      false,
					"outbound_job_token_broad": false,
				},
			},
		},
		{
			// cat-03 project: scoped-unprotected secret reachable from a dev-pushable ref.
			id: "cat-03/env-scoped-not-protected-secret-untrusted-ref",
			positive: map[string]any{
				"_id":                                    "grp/proj",
				"has_scoped_unprotected_secret_var":      true,
				"has_developer_pushable_unprotected_ref": true,
			},
			twins: map[string]map[string]any{
				"no scoped secret":    {"has_scoped_unprotected_secret_var": false},
				"no dev-pushable ref": {"has_developer_pushable_unprotected_ref": false},
			},
		},
		{
			// cat-04 chain: cross-project job-token push (handled in chain test below).
			id: "cat-04/cross-project-git-push-via-job-token",
		},
		{
			// cat-05 project: developer-creatable protected tag + tag-scoped protected var.
			id: "cat-05/developer-creatable-protected-tag",
			positive: map[string]any{
				"_id":                                  "grp/proj",
				"developer_creatable_protected_tag":    true,
				"protected_var_scoped_to_tag_pipeline": true,
			},
			twins: map[string]map[string]any{
				"tag not dev-creatable": {"developer_creatable_protected_tag": false},
				"no tag-scoped var":     {"protected_var_scoped_to_tag_pipeline": false},
			},
		},
		{
			// cat-06 merge_request: nested dotted-path folds on approval_policy.
			id: "cat-06/approval-policy-broad-bypass",
			positive: map[string]any{
				"_id": "grp/proj!7",
				"approval_policy": map[string]any{
					"enabled":            true,
					"bypass_actor_broad": true,
				},
			},
			twins: map[string]map[string]any{
				"policy disabled": {"approval_policy": map[string]any{"enabled": false, "bypass_actor_broad": true}},
				"narrow bypass":   {"approval_policy": map[string]any{"enabled": true, "bypass_actor_broad": false}},
			},
		},
		{
			// cat-07 environment: bot approver on a 1-approval protected env.
			id: "cat-07/bot-service-account-approver",
			positive: map[string]any{
				"_id":                        "grp/proj/production",
				"name":                       "production",
				"protected":                  true,
				"deploy_approvals_required":  float64(1),
				"approval_rule_bot_approver": true,
			},
			twins: map[string]map[string]any{
				"not protected":   {"protected": false},
				"two approvals":   {"deploy_approvals_required": float64(2)},
				"no bot approver": {"approval_rule_bot_approver": false},
			},
		},
		{
			// cat-08 instance: open creation + shared runners serving higher trust.
			id: "cat-08/any-user-open-creation-shared-runner",
			positive: map[string]any{
				"_id":                           "instance",
				"project_creation_unrestricted": true,
				"can_create_group":              true,
				"shared_runners_enabled":        true,
				"self_managed_shared_runner_serves_higher_trust": true,
			},
			twins: map[string]map[string]any{
				"creation restricted":  {"project_creation_unrestricted": false},
				"no group creation":    {"can_create_group": false},
				"shared runners off":   {"shared_runners_enabled": false},
				"no higher-trust corp": {"self_managed_shared_runner_serves_higher_trust": false},
			},
		},
		{
			// cat-08 runner: != true and any_of gate.
			id: "cat-08/unprotected-trusted-runner-untrusted-branch-jobs",
			positive: map[string]any{
				"_id":                            "runner:42",
				"self_managed":                   true,
				"serves_protected_ref_only_jobs": true,
				"serves_untrusted_ref_jobs":      true,
				"run_untagged":                   true,
				// ref_protected absent → "ref_protected != true" passes (benign twin sets it true).
			},
			twins: map[string]map[string]any{
				"ref protected":     {"ref_protected": true},
				"not self-managed":  {"self_managed": false},
				"no untrusted jobs": {"serves_untrusted_ref_jobs": false},
				"tagged + no match": {"run_untagged": false, "untrusted_ref_job_matches_tags": false},
			},
		},
		{
			// cat-10 job: id_tokens mintable, nested any_of/all_of + string != .
			id: "cat-10/id-tokens-mintable-from-untrusted-ref",
			positive: map[string]any{
				"_id":                   "grp/proj:mint",
				"mints_id_token":        true,
				"runs_on_untrusted_ref": true,
				"protected_ref_gate":    "weak",
			},
			twins: map[string]map[string]any{
				"no minting":              {"mints_id_token": false},
				"strong gate + no fork":   {"protected_ref_gate": "strong", "runs_fork_mr_in_parent": false},
				"protected ref + no fork": {"runs_on_untrusted_ref": false, "runs_fork_mr_in_parent": false},
			},
		},
		{
			// cat-11 credential: string-equality folds on kind + key_pattern.
			id: "cat-11/human-pat-as-cicd-variable",
			positive: map[string]any{
				"_id":                     "credential:pat:GITLAB_TOKEN",
				"kind":                    "personal_access_token",
				"in_unprotected_variable": true,
				"key_pattern":             "pat",
			},
			twins: map[string]map[string]any{
				"not a PAT":          {"kind": "deploy_token"},
				"protected variable": {"in_unprotected_variable": false},
				"non-PAT key":        {"key_pattern": "generic"},
			},
		},
		{
			// cat-12 group: SAML provisioning + developer default role (string ==).
			id: "cat-12/saml-scim-default-membership-role-developer",
			positive: map[string]any{
				"_id":                      "grp",
				"saml_provisioning_active": true,
				"default_membership_role":  "developer",
			},
			twins: map[string]map[string]any{
				"provisioning inactive": {"saml_provisioning_active": false},
				"guest default role":    {"default_membership_role": "guest"},
			},
		},
		{
			// cat-13 job: seven-fold Duo flow with set membership on two fields.
			id: "cat-13/code-review-flow-fork-mr-guardrail-not-interrupt",
			positive: map[string]any{
				"_id":                        "grp/proj:duo",
				"is_duo_flow":                true,
				"duo_flow_context_sources":   []any{"fork_mr"},
				"duo_group_features_enabled": true,
				"duo_guardrail_level":        "LOG_ONLY",
				"runner_tags":                []any{"gitlab-duo"},
				"duo_flow_secrets_in_scope":  true,
				"duo_flow_autonomous_write":  true,
			},
			twins: map[string]map[string]any{
				"guardrail interrupt":  {"duo_guardrail_level": "INTERRUPT"},
				"not a fork-MR source": {"duo_flow_context_sources": []any{"same_project_mr"}},
				"no duo runner tag":    {"runner_tags": []any{"docker"}},
				"no secrets in scope":  {"duo_flow_secrets_in_scope": false},
				"no autonomous write":  {"duo_flow_autonomous_write": false},
			},
		},
		{
			// cat-14 integration: any_of over token_present / non-empty custom_headers.
			id: "cat-14/group-webhook-url-recapture",
			positive: map[string]any{
				"_id":                           "integration:webhook:grp",
				"kind":                          "webhook",
				"url_mutable":                   true,
				"firable_event_trigger":         true,
				"editor_below_credential_trust": true,
				"token_present":                 true,
				"custom_headers":                []any{},
			},
			twins: map[string]map[string]any{
				"not a webhook":    {"kind": "slack"},
				"url locked":       {"url_mutable": false},
				"no firable event": {"firable_event_trigger": false},
				"editor is setter": {"editor_below_credential_trust": false},
				"no creds at all":  {"token_present": false, "custom_headers": []any{}},
			},
		},
		{
			// cat-15 agent: implicit config auth, impersonation == null, dev-reachable.
			id: "cat-15/config-project-implicit-authorization",
			positive: map[string]any{
				"_id":                                "grp/proj/agent",
				"config_path":                        ".gitlab/agents/prod/config.yaml",
				"implicit_config_project":            true,
				"config_project_developer_reachable": true,
				// impersonation absent → "impersonation == null" true; twin sets it non-null.
			},
			twins: map[string]map[string]any{
				"not implicit":      {"implicit_config_project": false},
				"impersonation set": {"impersonation": map[string]any{"user": "svc"}},
				"not dev-reachable": {"config_project_developer_reachable": false},
			},
		},
	}

	for _, c := range cases {
		if c.positive == nil {
			continue // placeholder / chain-handled elsewhere
		}
		t.Run(c.id, func(t *testing.T) { runSilence(t, c) })
	}
}

// Chain rules evaluate rule.ChainOf.Where against each for_each item, a different
// path than the top-level `where` in EvaluateRule; they get their own coverage.
func TestGitLabChainBenignTwinsSilence(t *testing.T) {
	type chainCase struct {
		id       string
		forEach  string
		positive map[string]any
		twins    map[string]map[string]any
	}
	cases := []chainCase{
		{
			// cat-04 chain edges: nested dotted paths on target/source/triggerer.
			id:      "cat-04/cross-project-git-push-via-job-token",
			forEach: "edges",
			positive: map[string]any{
				"target": map[string]any{
					"job_token_push_allowed":               true,
					"job_token_cross_project_push_allowed": true,
					"job_token_allowlist":                  map[string]any{"trusts_source": true},
					"developer_writable_protected_branch":  true,
				},
				"source": map[string]any{
					"job_token_cross_project_use":       "git_push",
					"source_ci_writable_by_lower_trust": true,
				},
				"triggerer": map[string]any{"access_level": float64(30)},
			},
			twins: map[string]map[string]any{
				"push toggle off": {"target": map[string]any{
					"job_token_push_allowed":               false,
					"job_token_cross_project_push_allowed": true,
					"job_token_allowlist":                  map[string]any{"trusts_source": true},
					"developer_writable_protected_branch":  true,
				}},
				"allowlist distrusts source": {"target": map[string]any{
					"job_token_push_allowed":               true,
					"job_token_cross_project_push_allowed": true,
					"job_token_allowlist":                  map[string]any{"trusts_source": false},
					"developer_writable_protected_branch":  true,
				}},
				"reporter triggerer": {"triggerer": map[string]any{"access_level": float64(20)}},
				"source not git_push": {"source": map[string]any{
					"job_token_cross_project_use":       "api",
					"source_ci_writable_by_lower_trust": true,
				}},
			},
		},
		{
			// cat-09 chain: producer/consumer cache-key collision with an == false fold.
			id:      "cat-09/cache-poisoning-cachekeyfiles-collision",
			forEach: "prefix_overlaps",
			positive: map[string]any{
				"producer": map[string]any{
					"cache_separation_enabled":          false,
					"runs_on_untrusted_ref":             true,
					"cache_key_files_attacker_writable": true,
					"cache_policy_writes":               true,
					"cache_paths_executable":            true,
				},
				"consumer": map[string]any{
					"protected_ref_gate":                "strong",
					"cache_key_files_attacker_writable": true,
					"cache_paths_executable":            true,
				},
			},
			twins: map[string]map[string]any{
				"separation enabled": {"producer": map[string]any{
					"cache_separation_enabled":          true,
					"runs_on_untrusted_ref":             true,
					"cache_key_files_attacker_writable": true,
					"cache_policy_writes":               true,
					"cache_paths_executable":            true,
				}},
				"consumer gate weak": {"consumer": map[string]any{
					"protected_ref_gate":                "weak",
					"cache_key_files_attacker_writable": true,
					"cache_paths_executable":            true,
				}},
			},
		},
		{
			// cat-12 chain grants: agent ci_access != [] plus config-less auto-devops project.
			id:      "cat-12/auto-devops-deploy-kubernetes-agent",
			forEach: "grants",
			positive: map[string]any{
				"agent": map[string]any{"ci_access_targets": []any{"grp/proj"}},
				"project": map[string]any{
					"auto_devops_enabled":  true,
					"has_cicd_config":      false,
					"has_reachable_runner": true,
				},
			},
			twins: map[string]map[string]any{
				"no ci_access targets": {"agent": map[string]any{"ci_access_targets": []any{}}},
				"has cicd config": {"project": map[string]any{
					"auto_devops_enabled":  true,
					"has_cicd_config":      true,
					"has_reachable_runner": true,
				}},
				"auto-devops off": {"project": map[string]any{
					"auto_devops_enabled":  false,
					"has_cicd_config":      false,
					"has_reachable_runner": true,
				}},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			rule := glRuleByID(t, c.id)
			if rule.SubjectKind() != "chain" {
				t.Fatalf("%s subject kind = %q, want chain", c.id, rule.SubjectKind())
			}
			if n := chainFireCount(t, rule, c.positive, c.forEach); n != 1 {
				t.Fatalf("[%s] positive chain item should fire once, got %d", c.id, n)
			}
			for name, override := range c.twins {
				twin := clone(c.positive)
				for k, v := range override {
					twin[k] = v
				}
				if n := chainFireCount(t, rule, twin, c.forEach); n != 0 {
					t.Errorf("[%s] benign chain twin %q should be silent, got %d", c.id, name, n)
				}
			}
		})
	}
}

// All 141 gitlab rules must load, and every rule's subject kind must be either
// "chain" or one registered in the scan provider's SubjectDirs — otherwise scan
// would silently load no subjects for it and the rule could never fire.
func TestGitLabRulesLoadAndSubjectsRegistered(t *testing.T) {
	rules, err := detect.LoadRules("gitlab")
	if err != nil {
		t.Fatalf("LoadRules(gitlab): %v", err)
	}
	const want = 141
	if len(rules) != want {
		t.Errorf("loaded %d gitlab rules, want %d", len(rules), want)
	}
	for i := range rules {
		r := &rules[i]
		if r.ID == "" {
			t.Errorf("rule %s has empty id", r.RuleFile)
		}
		if r.Where == nil && r.ChainOf == nil {
			t.Errorf("rule %s (%s) has neither where nor chain_of", r.ID, r.RuleFile)
		}
		kind := r.SubjectKind()
		if kind == "chain" {
			continue
		}
		if _, ok := gitlabScanProvider.SubjectDirs[kind]; !ok {
			t.Errorf("rule %s (%s): subject kind %q is not registered in SubjectDirs", r.ID, r.RuleFile, kind)
		}
	}
}
