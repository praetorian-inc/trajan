package gitlab

import "testing"

// These tests guard the chain-participant field contract: every `<role>.<field>`
// predicate a chain rule reads must be projected onto that role's participant,
// sourced from the underlying job/project/credential record. A dropped field
// resolves to nil under the role prefix and the rule silently never fires. The
// oracle is the frozen rule set (internal/detection-rules/gitlab/**), not what
// the correlator happens to produce; joins are near-empty on live SaaS, so the
// records here are synthetic. requireKeys asserts presence (a projected `false`
// is a real literal; a missing key is the bug).

func requireKeys(t *testing.T, role string, m map[string]any, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			t.Errorf("%s participant missing projected field %q", role, k)
		}
	}
}

// dotenv-flow (cat-09 x3): producer reads produces_dotenv, runs_on_untrusted_ref,
// runs_on_protected_ref, dotenv_content_attacker_influenced,
// dotenv_content_from_untrusted_source; consumer reads consumes_dotenv,
// cross_project_needs, dotenv_inheritance_unnarrowed, inherited_var_in_exec_sink,
// dotenv_key_collides_declared_var, colliding_var_in_exec_sink, runs_on_protected_ref.
func TestDotenvParticipantFields(t *testing.T) {
	c := &correlator{
		jobs: []map[string]any{
			{"_id": "g/p:prod", "produces_dotenv": true, "runs_on_untrusted_ref": true,
				"runs_on_protected_ref": false, "dotenv_content_attacker_influenced": true,
				"dotenv_content_from_untrusted_source": true},
			{"_id": "g/p:cons", "consumes_dotenv": true, "dotenv_inheritance_unnarrowed": true,
				"inherited_var_in_exec_sink": true, "dotenv_key_collides_declared_var": true,
				"colliding_var_in_exec_sink": true, "runs_on_protected_ref": true,
				"cross_project_needs": []any{map[string]any{"project": "g/up"}}},
		},
	}
	e := c.dotenvFlow()["edges"].([]map[string]any)[0]
	requireKeys(t, "dotenv.producer", e["producer"].(map[string]any),
		"produces_dotenv", "runs_on_untrusted_ref", "runs_on_protected_ref",
		"dotenv_content_attacker_influenced", "dotenv_content_from_untrusted_source")
	cons := e["consumer"].(map[string]any)
	requireKeys(t, "dotenv.consumer", cons,
		"consumes_dotenv", "cross_project_needs", "dotenv_inheritance_unnarrowed",
		"inherited_var_in_exec_sink", "dotenv_key_collides_declared_var",
		"colliding_var_in_exec_sink", "runs_on_protected_ref")
	if e["producer"].(map[string]any)["runs_on_protected_ref"] != false {
		t.Error("producer.runs_on_protected_ref must carry the literal false, not be dropped")
	}
	if _, ok := cons["cross_project_needs"].([]any); !ok {
		t.Error("consumer.cross_project_needs must be a list (C1: [] not null)")
	}
}

// cross-project-artifact (cat-09 x1): consumer reads runs_on_protected_ref (plus
// cross_project_needs, executes_fetched_artifact, artifact_integrity_checked,
// artifact_source_ref_mutable); producer reads source_ref_developer_pushable and
// on_consumer_job_token_allowlist.
func TestCrossProjectArtifactParticipantFields(t *testing.T) {
	c := &correlator{
		jobs: []map[string]any{
			{"_id": "g/cons:gen", "runs_on_protected_ref": true, "executes_fetched_artifact": true,
				"artifact_integrity_checked": false, "artifact_source_ref_mutable": true,
				"cross_project_needs": []any{map[string]any{"project": "g/prod", "artifacts": true}}},
		},
		projects: map[string]map[string]any{
			"g/prod": {"_id": "g/prod", "has_developer_pushable_unprotected_ref": true,
				"job_token_allowlist": map[string]any{"mode": "project_scoped", "entries": []any{"g/cons"}}},
		},
	}
	e := c.crossProjectArtifact()["edges"].([]map[string]any)[0]
	requireKeys(t, "xpart.consumer", e["consumer"].(map[string]any),
		"cross_project_needs", "executes_fetched_artifact", "artifact_integrity_checked",
		"artifact_source_ref_mutable", "runs_on_protected_ref")
	prod := e["producer"].(map[string]any)
	requireKeys(t, "xpart.producer", prod, "source_ref_developer_pushable", "on_consumer_job_token_allowlist")
	if prod["source_ref_developer_pushable"] != true {
		t.Errorf("producer.source_ref_developer_pushable=%v want true (developer-pushable ref)", prod["source_ref_developer_pushable"])
	}
	if prod["on_consumer_job_token_allowlist"] != true {
		t.Errorf("producer.on_consumer_job_token_allowlist=%v want true (consumer admitted by allowlist)", prod["on_consumer_job_token_allowlist"])
	}
}

// agent-ci-access (cat-12 auto-devops): project reads auto_devops_enabled,
// has_cicd_config, has_reachable_runner (plus agent.ci_access_targets).
func TestAgentCIAccessProjectFields(t *testing.T) {
	c := &correlator{
		agents: []map[string]any{
			{"_id": "g/p/agent", "ci_access_targets": []any{"g/p"}},
		},
		projects: map[string]map[string]any{
			"g/p": {"_id": "g/p", "auto_devops_enabled": true, "has_cicd_config": false, "has_reachable_runner": true},
		},
	}
	grant := c.agentCIAccess()["grants"].([]map[string]any)[0]
	requireKeys(t, "agentci.agent", grant["agent"].(map[string]any), "ci_access_targets")
	proj := grant["project"].(map[string]any)
	requireKeys(t, "agentci.project", proj, "auto_devops_enabled", "has_cicd_config", "has_reachable_runner")
	if proj["auto_devops_enabled"] != true || proj["has_cicd_config"] != false || proj["has_reachable_runner"] != true {
		t.Errorf("project posture not folded: %v", proj)
	}
}

// cache-keyspace (cat-09 x2) reads under producer./consumer. role prefixes.
// producer: cache_separation_enabled, runs_on_untrusted_ref,
// cache_key_files_attacker_writable, cache_key_static_cross_boundary,
// cache_policy_writes, cache_paths_executable; consumer: protected_ref_gate,
// cache_key_files_attacker_writable, cache_key_static_cross_boundary,
// cache_paths_executable.
func TestCacheKeyspaceParticipantRoles(t *testing.T) {
	c := &correlator{
		jobs: []map[string]any{
			{"_id": "g/p:build", "runs_on_untrusted_ref": true, "protected_ref_gate": "none",
				"cache_policy_writes": true, "cache_paths_executable": true,
				"cache_key_static_cross_boundary": true, "cache_key_files_attacker_writable": true,
				"cache": []any{map[string]any{"key": "deps-v1", "policy": "pull-push"}}},
			{"_id": "g/p:deploy", "runs_on_untrusted_ref": false, "protected_ref_gate": "strong",
				"cache_paths_executable": true, "cache_key_static_cross_boundary": true,
				"cache": []any{map[string]any{"key": "deps-v1", "policy": "pull"}}},
		},
	}
	ov := c.cacheKeyspace()["prefix_overlaps"].([]map[string]any)
	if len(ov) != 1 {
		t.Fatalf("overlaps=%d want 1", len(ov))
	}
	prod := ov[0]["producer"].(map[string]any)
	cons := ov[0]["consumer"].(map[string]any)
	requireKeys(t, "cache.producer", prod, "cache_separation_enabled", "runs_on_untrusted_ref",
		"cache_key_files_attacker_writable", "cache_key_static_cross_boundary",
		"cache_policy_writes", "cache_paths_executable")
	requireKeys(t, "cache.consumer", cons, "protected_ref_gate", "cache_key_files_attacker_writable",
		"cache_key_static_cross_boundary", "cache_paths_executable")
	if prod["runs_on_untrusted_ref"] != true {
		t.Error("producer role must be the untrusted-ref writer")
	}
	if cons["protected_ref_gate"] != "strong" {
		t.Error("consumer role must be the strong-gate participant")
	}
}

// deploy-key-reuse (cat-11 x1): key reads kind, can_push,
// creator_has_target_protected_access; source reads in_unprotected_variable;
// target reads holds_protected_resources.
func TestDeployKeyReuseParticipantRoles(t *testing.T) {
	c := &correlator{
		creds: []map[string]any{
			{"kind": "deploy_key", "deploy_key_fingerprint": "SHA256:abc", "can_push": true,
				"in_unprotected_variable": true, "creator_has_target_protected_access": true,
				"_provenance": []any{map[string]any{"scope": "project:g/low"}}},
			{"kind": "deploy_key", "deploy_key_fingerprint": "SHA256:abc", "can_push": false,
				"_provenance": []any{map[string]any{"scope": "project:g/high"}}},
		},
		projects: map[string]map[string]any{
			"g/high": {"_id": "g/high", "holds_protected_resources": true},
			"g/low":  {"_id": "g/low"},
		},
	}
	rk := c.deployKeyReuse()["reused_keys"].([]map[string]any)
	if len(rk) != 1 {
		t.Fatalf("reused_keys=%d want 1", len(rk))
	}
	key := rk[0]["key"].(map[string]any)
	requireKeys(t, "deploykey.key", key, "kind", "can_push", "creator_has_target_protected_access")
	requireKeys(t, "deploykey.source", rk[0]["source"].(map[string]any), "in_unprotected_variable")
	requireKeys(t, "deploykey.target", rk[0]["target"].(map[string]any), "holds_protected_resources")
	if key["kind"] != "deploy_key" || key["can_push"] != true || key["creator_has_target_protected_access"] != true {
		t.Errorf("key participant values wrong: %v", key)
	}
	if rk[0]["source"].(map[string]any)["in_unprotected_variable"] != true {
		t.Error("source.in_unprotected_variable must aggregate the low-trust instance")
	}
	if rk[0]["target"].(map[string]any)["holds_protected_resources"] != true {
		t.Error("target.holds_protected_resources must aggregate the high-trust instance")
	}
}
