package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// normalizeEntities emits the ten non-job subject records (project, group,
// instance, merge_request, environment, runner, agent, credential, integration,
// plus the instance singleton) from the collected surfaces. Resource-scoped
// facts fold onto their owning subject. Per-item failures are recorded in
// timer.Errors and skipped; only IO / contract violations abort.
func normalizeEntities(ctx context.Context, prior engine.PriorPhase, cp engine.CurrentPhase, org string, projs []projectMeta, timer *engine.PhaseTimer) error {
	if err := normalizeInstance(prior, cp, timer); err != nil {
		return err
	}
	if err := normalizeGroups(ctx, prior, cp, org, projs, timer); err != nil {
		return err
	}
	if err := normalizeRunners(prior, cp, org, projs, timer); err != nil {
		return err
	}
	for _, p := range projs {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, fn := range []func(engine.PriorPhase, engine.CurrentPhase, projectMeta, *engine.PhaseTimer) error{
			normalizeProject, normalizeMergeRequest, normalizeEnvironments,
			normalizeCredentials, normalizeIntegrations,
		} {
			if err := fn(prior, cp, p, timer); err != nil {
				return err
			}
		}
		if err := normalizeAgents(prior, cp, p, projs, timer); err != nil {
			return err
		}
	}
	return nil
}

// ---- project ----

func normalizeProject(prior engine.PriorPhase, cp engine.CurrentPhase, p projectMeta, timer *engine.PhaseTimer) error {
	fp := p.FullPath
	detail := entLoadData(prior, engine.CollectGLProject(fp))
	if detail == nil {
		return nil
	}
	ci := entLoadData(prior, engine.CollectGLCISettings(fp))
	members := entLoadList(prior, engine.CollectGLProjectMembers(fp))
	vars := entLoadList(prior, engine.CollectGLProjectVariables(fp))
	pbranches := entLoadList(prior, engine.CollectGLProtectedBranches(fp))
	ptags := entLoadList(prior, engine.CollectGLProtectedTags(fp))
	tfState := entLoadData(prior, engine.CollectGLTerraformState(fp))
	tfList := entLoadList(prior, engine.CollectGLTerraformState(fp))
	ciYAML := entLoadRaw(prior, engine.CollectGLCIConfig(fp, ".gitlab-ci.yml"))
	runners := reachableRunners(prior, fp)

	cicdVars := normalizeVariables(vars, "project")
	protBranches := normalizeProtectedBranches(pbranches)
	protTags := normalizeProtectedTags(ptags)
	memberRecs := normalizeMembers(members)

	rec := map[string]any{
		"_id":                                  fp,
		"visibility":                           entStr(detail["visibility"]),
		"forking_enabled":                      entStr(detail["forking_access_level"]) != "disabled",
		"fork_pipelines_run_in_parent":         entBool(detail["ci_allow_fork_pipelines_to_run_in_parent_project"]),
		"mr_pipelines_protected":               entBool(detail["protect_merge_request_pipelines"]),
		"merged_results_pipelines":             entBool(detail["merge_pipelines_enabled"]) || entBool(detail["merge_trains_enabled"]),
		"inbound_job_token_scope_enabled":      entBool(detail["ci_job_token_scope_enabled"]),
		"job_token_allowlist":                  jobTokenAllowlist(ci),
		"job_token_push_allowed":               entBool(detail["ci_push_repository_for_job_token_allowed"]),
		"job_token_cross_project_push_allowed": entBool(entGetIn(ci, "ci_cd_settings", "project", "ciCdSettings", "crossProjectPushForJobTokenAllowed")),
		"uses_managed_terraform_state":         !entUnobserved(tfState) && len(tfList) > 0,
		"cache_separation_enabled":             entBool(detail["ci_separated_caches"]),
		"oidc":                                 map[string]any{"sub_claim_components": entListOrEmpty(detail["ci_id_token_sub_claim_components"])},
		"pages_access_level":                   entStr(detail["pages_access_level"]),
		"auto_devops_enabled":                  entBool(detail["auto_devops_enabled"]),
		"has_cicd_config":                      ciYAML != nil,
		"protected_branches":                   protBranches,
		"protected_tags":                       protTags,
		"default_branch_protected":             defaultBranchProtection(protBranches, entStr(detail["default_branch"])),
		"push_rules":                           orEmptyObj(entLoadData(prior, engine.CollectGLPushRules(fp))),
		"cicd_variables":                       cicdVars,
		"public_pipelines":                     publicPipelines(detail),
		"members":                              memberRecs,
		"registry_protection_rules":            registryProtectionRules(prior, fp),
		"duo":                                  projectDuo(prior, fp),
		"pipeline_execution_policy_from_mutable_project": policyFromMutableProject(prior, fp, protBranches),
		"_provenance": prov(engine.CollectGLProject(fp)),
	}

	// Derived existentials / effective booleans (hard contracts C3/C4). The engine
	// cannot express these joins/existentials in a predicate.
	devPushRef := developerPushableUnprotectedRef(protBranches)
	rec["has_guest_member"] = hasMemberAtLevel(members, accessGuest)
	rec["has_developer_pushable_unprotected_ref"] = devPushRef
	rec["has_developer_reachable_secret"] = len(cicdVars) > 0 && devPushRef
	rec["has_masked_unprotected_secret_var"] = anyVar(cicdVars, func(v map[string]any) bool {
		return mBool(v, "masked") && !mBool(v, "protected") && secretShapedKey(mStr(v, "key"))
	})
	rec["has_plain_unprotected_secret_var"] = anyVar(cicdVars, func(v map[string]any) bool {
		return !mBool(v, "masked") && !mBool(v, "protected") && secretShapedKey(mStr(v, "key"))
	})
	rec["has_scoped_unprotected_secret_var"] = anyVar(cicdVars, func(v map[string]any) bool {
		return mStr(v, "environment_scope") != "*" && mStr(v, "environment_scope") != "" && !mBool(v, "protected") && secretShapedKey(mStr(v, "key"))
	})
	rec["developer_pushable_protected_branch"] = anyBranch(protBranches, func(b map[string]any) bool {
		return grantsDeveloper(mList(b, "push_access_levels"))
	})
	rec["developer_mergeable_protected_branch"] = anyBranch(protBranches, func(b map[string]any) bool {
		return grantsDeveloper(mList(b, "merge_access_levels"))
	})
	rec["developer_writable_protected_branch"] = anyBranch(protBranches, func(b map[string]any) bool {
		return grantsDeveloper(mList(b, "push_access_levels")) || grantsDeveloper(mList(b, "merge_access_levels"))
	})
	rec["developer_creatable_wildcard_branch"] = anyBranch(protBranches, func(b map[string]any) bool {
		return isWildcard(mStr(b, "pattern")) && (grantsDeveloper(mList(b, "push_access_levels")) || grantsDeveloper(mList(b, "merge_access_levels")))
	})
	rec["force_push_by_low_trust_pusher"] = anyBranch(protBranches, func(b map[string]any) bool {
		return mBool(b, "allow_force_push") && levelsIncludeAtMost(mList(b, "push_access_levels"), accessDeveloper)
	})
	rec["developer_creatable_protected_tag"] = anyTag(protTags, func(t map[string]any) bool {
		return grantsDeveloper(mList(t, "create_access_levels"))
	})
	rec["push_access_shadowed_by_permissive_rule"] = shadowedByPermissive(protBranches, "push_access_levels")
	rec["create_access_shadowed_by_permissive_tag_rule"] = shadowedTags(protTags)
	rec["force_push_shadowed_by_permissive_rule"] = forcePushShadowed(protBranches)
	rec["no_one_push_creatable_via_merge"] = anyBranch(protBranches, func(b map[string]any) bool {
		return len(mList(b, "push_access_levels")) == 0 && grantsDeveloper(mList(b, "merge_access_levels"))
	})
	rec["has_reachable_runner"] = len(runners) > 0
	rec["has_self_managed_runner"] = anyRunner(runners, func(r map[string]any) bool { return mBool(r, "self_managed") })
	rec["has_protected_self_managed_runner"] = anyRunner(runners, func(r map[string]any) bool {
		return mBool(r, "self_managed") && mBool(r, "ref_protected")
	})
	rec["holds_protected_resources"] = anyVar(cicdVars, func(v map[string]any) bool { return mBool(v, "protected") }) ||
		anyRunner(runners, func(r map[string]any) bool { return mBool(r, "ref_protected") })
	rec["ci_debug_trace_enabled"] = ciDebugTrace(cicdVars, ciYAML)
	rec["auto_devops_deploy_creds_wired"] = anyVar(cicdVars, func(v map[string]any) bool { return deployCredKey(mStr(v, "key")) })
	rec["group_inherited_deploy_vars"] = groupInheritedDeployVars(prior, fp)
	rec["author_can_self_merge"] = authorCanSelfMerge(prior, fp)
	rec["protected_var_scoped_to_writable_ref"] = protectedVarScopedToWritable(cicdVars, protBranches)
	rec["protected_var_scoped_to_tag_pipeline"] = anyVar(cicdVars, func(v map[string]any) bool { return mBool(v, "protected") }) &&
		len(protTags) > 0 && ciYAMLHasTagJob(ciYAML)
	rec["ref_is_ci_trusted"] = anyVar(cicdVars, func(v map[string]any) bool { return mBool(v, "protected") }) || entStr(detail["default_branch"]) != ""
	rec["ref_has_deferred_deploy_identity"] = ciYAMLHasDeployIdentity(ciYAML)
	src, inheritedDevPush := inheritedDefaultBranchProtection(prior, fp, protBranches, entStr(detail["default_branch"]))
	rec["inherited_protection_source"] = src
	rec["inherited_default_branch_developer_pushable"] = inheritedDevPush
	rec["is_schedule_owner"] = projectHasMemberOwnedSchedule(prior, fp, members)

	return emit(cp, timer, engine.NormalizeGLProject(fp), rec)
}

// projectHasMemberOwnedSchedule reports whether a pipeline schedule exists whose
// owner is a project member — the cat-04 triggerer signal that the identity
// starting the scheduled run is a project member (schedules run in the owner's
// context). When the owner id cannot be matched to a member (owner or members
// absent), fall back to "any schedule exists" so the participant is not silently
// forced false on a token that could not read the members list.
func projectHasMemberOwnedSchedule(prior engine.PriorPhase, fp string, members []any) bool {
	schedules := entLoadList(prior, engine.CollectGLPipelineSchedules(fp))
	if len(schedules) == 0 {
		return false
	}
	memberIDs := map[int64]bool{}
	for _, raw := range members {
		if id := entInt64(entMap(raw)["id"]); id != 0 {
			memberIDs[id] = true
		}
	}
	for _, raw := range schedules {
		ownerID := entInt64(entMap(entMap(raw)["owner"])["id"])
		if len(memberIDs) == 0 || ownerID == 0 || memberIDs[ownerID] {
			return true
		}
	}
	return false
}

func publicPipelines(detail map[string]any) bool {
	if v, ok := detail["public_jobs"].(bool); ok {
		return v
	}
	if v, ok := detail["public_pipelines"].(bool); ok {
		return v
	}
	return true
}

func jobTokenAllowlist(ci map[string]any) map[string]any {
	entries := []any{}
	for _, raw := range entListOrEmpty(ci["job_token_allowlist"]) {
		if fp := entStr(entMap(raw)["path_with_namespace"]); fp != "" {
			entries = append(entries, fp)
		}
	}
	for _, raw := range entListOrEmpty(ci["job_token_groups_allowlist"]) {
		if fp := entStr(entMap(raw)["full_path"]); fp != "" {
			entries = append(entries, fp)
		}
	}
	inbound := entBool(entGetIn(ci, "job_token_scope", "inbound_enabled")) ||
		entBool(entGetIn(ci, "ci_cd_settings", "project", "ciCdSettings", "inboundJobTokenScopeEnabled"))
	mode := "open"
	if !inbound {
		mode = "disabled"
	} else if len(entListOrEmpty(ci["job_token_groups_allowlist"])) > 0 {
		mode = "group_scoped"
	} else if len(entListOrEmpty(ci["job_token_allowlist"])) > 0 {
		mode = "project_scoped"
	}
	return map[string]any{
		"mode":         mode,
		"entries":      entries,
		"fine_grained": len(entListOrEmpty(ci["job_token_groups_allowlist"])) > 0,
	}
}

func normalizeVariables(vars []any, scope string) []map[string]any {
	out := []map[string]any{}
	for _, raw := range vars {
		v := entMap(raw)
		if entStr(v["key"]) == "" {
			continue
		}
		out = append(out, map[string]any{
			"key":               entStr(v["key"]),
			"protected":         entBool(v["protected"]),
			"masked":            entBool(v["masked"]),
			"environment_scope": entStr(v["environment_scope"]),
			"scope_level":       scope,
		})
	}
	return out
}

func normalizeProtectedBranches(pbranches []any) []map[string]any {
	out := []map[string]any{}
	for _, raw := range pbranches {
		b := entMap(raw)
		out = append(out, map[string]any{
			"pattern":                      entStr(b["name"]),
			"push_access_levels":           accessLevelValues(b["push_access_levels"]),
			"merge_access_levels":          accessLevelValues(b["merge_access_levels"]),
			"allow_force_push":             entBool(b["allow_force_push"]),
			"code_owner_approval_required": entBool(b["code_owner_approval_required"]),
			"push_named_grant":             hasNamedGrant(b["push_access_levels"]),
			"merge_named_grant":            hasNamedGrant(b["merge_access_levels"]),
		})
	}
	return out
}

func normalizeProtectedTags(ptags []any) []map[string]any {
	out := []map[string]any{}
	for _, raw := range ptags {
		t := entMap(raw)
		out = append(out, map[string]any{
			"pattern":              entStr(t["name"]),
			"create_access_levels": accessLevelValues(t["create_access_levels"]),
			"create_named_grant":   hasNamedGrant(t["create_access_levels"]),
		})
	}
	return out
}

func normalizeMembers(members []any) []map[string]any {
	out := []map[string]any{}
	for _, raw := range members {
		m := entMap(raw)
		out = append(out, map[string]any{
			"access_level": entInt64(m["access_level"]),
			"is_bot":       entBool(m["bot"]) || entBool(m["is_bot"]),
		})
	}
	return out
}

func defaultBranchProtection(branches []map[string]any, defaultBranch string) string {
	for _, b := range branches {
		if globMatch(mStr(b, "pattern"), defaultBranch) {
			switch {
			case grantsDeveloper(mList(b, "push_access_levels")):
				return "developer"
			case len(mList(b, "push_access_levels")) == 0:
				return "maintainer"
			default:
				return "maintainer"
			}
		}
	}
	return "none"
}

func registryProtectionRules(prior engine.PriorPhase, fp string) []any {
	out := []any{}
	out = append(out, entListOrEmpty(anyToVal(entLoadList(prior, engine.CollectGLRegistryTagRules(fp))))...)
	out = append(out, entListOrEmpty(anyToVal(entLoadList(prior, engine.CollectGLPackageProtectionRules(fp))))...)
	return out
}

func anyToVal(l []any) any {
	if l == nil {
		return []any{}
	}
	return l
}

func projectDuo(prior engine.PriorPhase, fp string) map[string]any {
	cfg := entLoadRaw(prior, engine.CollectGLRepoFile(fp, ".gitlab/duo/agent-config.yml"))
	mcp := entLoadRaw(prior, engine.CollectGLRepoFile(fp, ".gitlab/duo/mcp.json"))
	flows := []any{}
	var mcpEndpoint any
	if len(mcp) > 0 {
		var m map[string]any
		if json.Unmarshal(mcp, &m) == nil {
			mcpEndpoint = firstMCPEndpoint(m)
		}
	}
	return map[string]any{
		"config_present": cfg != nil,
		"flows":          flows,
		"mcp_endpoint":   mcpEndpoint,
	}
}

func firstMCPEndpoint(m map[string]any) any {
	for _, key := range []string{"servers", "mcpServers"} {
		if servers := entMap(m[key]); servers != nil {
			for _, v := range servers {
				if url := entStr(entMap(v)["url"]); url != "" {
					return url
				}
			}
		}
	}
	return m["url"]
}

// ---- group ----

func normalizeGroups(ctx context.Context, prior engine.PriorPhase, cp engine.CurrentPhase, org string, projs []projectMeta, timer *engine.PhaseTimer) error {
	groups := groupRoster(prior, org)
	for _, g := range groups {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := normalizeGroup(prior, cp, g, projs, timer); err != nil {
			return err
		}
	}
	return nil
}

// groupRoster is the top-level group plus its collected subgroups.
func groupRoster(prior engine.PriorPhase, org string) []string {
	out := []string{org}
	for _, raw := range entLoadList(prior, engine.CollectGLSubgroups(org)) {
		if fp := entStr(entMap(raw)["full_path"]); fp != "" {
			out = append(out, fp)
		}
	}
	return out
}

func normalizeGroup(prior engine.PriorPhase, cp engine.CurrentPhase, gpath string, projs []projectMeta, timer *engine.PhaseTimer) error {
	detail := entLoadData(prior, engine.CollectGLGroup(gpath))
	if detail == nil {
		return nil
	}
	duo := entLoadData(prior, engine.CollectGLGroupDuo(gpath))
	vars := entLoadList(prior, engine.CollectGLGroupVariables(gpath))
	saml := entLoadData(prior, engine.CollectGLGroupSAML(gpath))

	roleLevel := roleNameToLevel(detail["default_membership_role"])
	projectCreationRole := entStr(detail["project_creation_level"])
	subgroupCreation := entStr(detail["subgroup_creation_level"])

	rec := map[string]any{
		"_id":                                   gpath,
		"default_membership_role":               levelToRoleName(roleLevel),
		"default_branch_protection":             groupBranchProtection(detail),
		"project_creation_role":                 projectCreationRole,
		"project_access_token_creation_allowed": entBool(detail["project_access_token_creation_allowed"]),
		"shared_runners_enabled":                entStr(detail["shared_runners_setting"]) != "disabled_and_unoverridable" && entStr(detail["shared_runners_setting"]) != "disabled_and_overridable",
		"duo_features_enabled":                  duoFeatureEnabled(duo, "group"),
		"prompt_injection_protection_level":     duoGuardrail(duo, "group"),
		"duo_workflow_mcp_enabled":              duoBool(duo, "group", "duoWorkflowMcpEnabled"),
		"domain_allowlist":                      entListOrEmpty(detail["domain_allowlist"]),
		"cicd_variables":                        groupVarRecs(vars),
		"descendants":                           groupDescendants(prior, gpath, projs),
		"group_open_project_creation":           groupOpenCreation(projectCreationRole, subgroupCreation),
		"saml_provisioning_active":              !entUnobserved(saml) && saml != nil && len(saml) > 0,
		"default_role_custom_cicd_ability":      false,
		"_provenance":                           prov(engine.CollectGLGroup(gpath)),
	}
	return emit(cp, timer, engine.NormalizeGLGroup(gpath), rec)
}

func groupVarRecs(vars []any) []map[string]any { return normalizeVariables(vars, "group") }

// groupBranchProtection maps the group default-branch protection to the enum the
// cat-03 rule reads: "none" | "partial" | "full". GitLab exposes this either as
// the legacy integer default_branch_protection (0 none, 1 partial, 2+ full) or
// the newer default_branch_protection_defaults object; a Developer-inclusive push
// grant is "partial", a Maintainer-only (or force-push-blocked) grant is "full".
func groupBranchProtection(detail map[string]any) any {
	if d := entMap(detail["default_branch_protection_defaults"]); d != nil {
		push := accessLevelValues(d["allowed_to_push"])
		if levelsIncludeAtMost(push, accessDeveloper) || entBool(d["allow_force_push"]) {
			return "partial"
		}
		return "full"
	}
	if v, ok := detail["default_branch_protection"]; ok {
		switch entInt64(v) {
		case 0:
			return "none"
		case 1:
			return "partial"
		default:
			return "full"
		}
	}
	return nil
}

func groupDescendants(prior engine.PriorPhase, gpath string, projs []projectMeta) []any {
	out := []any{}
	for _, raw := range entLoadList(prior, engine.CollectGLSubgroups(gpath)) {
		if fp := entStr(entMap(raw)["full_path"]); fp != "" {
			out = append(out, fp)
		}
	}
	for _, p := range projs {
		if p.FullPath == gpath || strings.HasPrefix(p.FullPath, gpath+"/") {
			out = append(out, p.FullPath)
		}
	}
	return out
}

func groupOpenCreation(projectCreationRole, subgroupCreation string) bool {
	permits := func(s string) bool {
		switch s {
		case "developer", "maintainer", "":
			return true
		}
		return false
	}
	return permits(projectCreationRole) || permits(subgroupCreation)
}

// ---- instance ----

func normalizeInstance(prior engine.PriorPhase, cp engine.CurrentPhase, timer *engine.PhaseTimer) error {
	settings := entLoadData(prior, engine.CollectGLInstanceSettings())
	duo := entLoadData(prior, engine.CollectGLInstanceDuo())
	runners := entLoadList(prior, engine.CollectGLInstanceRunners())
	instVars := entLoadList(prior, engine.CollectGLInstanceVariables())
	obs := settings != nil && !entUnobserved(settings)

	// Soft-failed instance surface (gitlab.com, or no admin token): emit the
	// record with the observable keys null so absence is never read as false.
	rec := map[string]any{
		"_id":                                         "instance",
		"allow_local_requests_from_webhooks":          boolOrNil(obs, settings, "allow_local_requests_from_web_hooks_and_services"),
		"runner_registration_token_allowed":           boolOrNil(obs, settings, "allow_runner_registration_token"),
		"valid_runner_registrars":                     entListOrEmpty(settings["valid_runner_registrars"]),
		"auto_devops_enabled":                         boolOrNil(obs, settings, "auto_devops_enabled"),
		"signup_enabled":                              boolOrNil(obs, settings, "signup_enabled"),
		"can_create_group":                            boolOrNil(obs, settings, "can_create_group"),
		"shared_runners_enabled":                      boolOrNil(obs, settings, "shared_runners_enabled"),
		"service_token_expiration_enforced":           boolOrNil(obs, settings, "service_access_tokens_expiration_enforced"),
		"require_admin_approval_after_signup":         boolOrNil(obs, settings, "require_admin_approval_after_user_signup"),
		"project_creation_unrestricted":               projectCreationUnrestricted(obs, settings),
		"duo_features_enabled":                        duoFeatureEnabled(duo, "instance"),
		"duo_workflow_mcp_enabled":                    duoBool(duo, "instance", "duoWorkflowMcpEnabled"),
		"prompt_injection_protection_level":           duoGuardrail(duo, "instance"),
		"outbound_local_requests_allowlist_effective": outboundAllowlistEffective(obs, settings),
		"instance_agent_authorization_enabled":        boolOrNil(obs, settings, "instance_level_ai_beta_features_enabled"),
		"cicd_variables":                              normalizeVariables(instVars, "instance"),
		"_provenance":                                 prov(engine.CollectGLInstanceSettings()),
	}
	selfManagedShared := anyRunner(reachableRunnerList(runners), func(r map[string]any) bool {
		return mStr(r, "runner_type") == "instance_type" && mBool(r, "self_managed")
	})
	rec["open_project_creation"] = obs && entBool(settings["signup_enabled"]) && entBool(settings["shared_runners_enabled"]) && projectCreationUnrestricted(obs, settings) == true
	rec["self_managed_shared_runner_serves_higher_trust"] = selfManagedShared
	rec["reusable_token_scope_serves_secrets"] = selfManagedShared && boolVal(boolOrNil(obs, settings, "allow_runner_registration_token"))
	rec["closed_audience_instance"] = obs && !entBool(settings["signup_enabled"])
	return emit(cp, timer, engine.NormalizeGLInstance(), rec)
}

func boolOrNil(observed bool, m map[string]any, key string) any {
	if !observed {
		return nil
	}
	return entBool(m[key])
}

func boolVal(v any) bool { b, _ := v.(bool); return b }

func projectCreationUnrestricted(observed bool, settings map[string]any) any {
	if !observed {
		return nil
	}
	// default_project_creation is a numeric role code; 0 (nobody) or a specific
	// role restricts, any other authenticated user is the unrestricted case.
	if v, ok := settings["default_project_creation"]; ok {
		return entInt64(v) == 2
	}
	return false
}

func outboundAllowlistEffective(observed bool, settings map[string]any) any {
	if !observed {
		return nil
	}
	return len(entListOrEmpty(settings["outbound_local_requests_whitelist"])) > 0
}

// ---- merge_request ----

func normalizeMergeRequest(prior engine.PriorPhase, cp engine.CurrentPhase, p projectMeta, timer *engine.PhaseTimer) error {
	fp := p.FullPath
	detail := entLoadData(prior, engine.CollectGLProject(fp))
	if detail == nil {
		return nil
	}
	approvals := entLoadData(prior, engine.CollectGLApprovals(fp))
	rules := entLoadList(prior, engine.CollectGLApprovalRules(fp))
	extChecks := entLoadList(prior, engine.CollectGLExternalStatusChecks(fp))
	codeowners := loadCodeowners(prior, fp)
	pbranches := normalizeProtectedBranches(entLoadList(prior, engine.CollectGLProtectedBranches(fp)))
	members := entLoadList(prior, engine.CollectGLProjectMembers(fp))

	approvalsReq := entInt64(approvals["approvals_before_merge"])
	independent := independentApprovers(rules, members)

	rec := map[string]any{
		"_id":                                  fp,
		"author_approval_allowed":              entBool(approvals["merge_requests_author_approval"]),
		"committer_approval_disabled":          entBool(approvals["merge_requests_disable_committers_approval"]),
		"approvals_required":                   approvalsReq,
		"author_controls_approver_count":       !entBool(approvals["disable_overriding_approvers_per_merge_request"]),
		"reset_approvals_on_push":              entBool(approvals["reset_approvals_on_push"]),
		"code_owner_approval_required":         anyBranch(pbranches, func(b map[string]any) bool { return mBool(b, "code_owner_approval_required") }),
		"selective_code_owner_removal":         entBool(approvals["selective_code_owner_removals"]),
		"codeowners":                           codeowners,
		"only_merge_if_pipeline_succeeds":      entBool(detail["only_allow_merge_if_pipeline_succeeds"]),
		"only_merge_if_status_checks_pass":     entBool(detail["only_allow_merge_if_all_status_checks_passed"]),
		"allow_merge_on_skipped_pipeline":      entBool(detail["allow_merge_on_skipped_pipeline"]),
		"external_status_checks":               entListOrEmpty(anyToVal(extChecks)),
		"approval_policy":                      approvalPolicy(prior, fp),
		"approver_set_broad":                   approverSetBroad(rules),
		"independent_approver_count":           independent,
		"trust_relevant_path_optional_only":    boolVal(codeowners["optional_sections"]) && !boolVal(codeowners["self_owned_required"]),
		"target_branch_ci_trusted_unprotected": len(pbranches) == 0,
		"required_jobs_evadable":               requiredJobsEvadable(prior, fp),
		"_provenance":                          prov(engine.CollectGLProject(fp), engine.CollectGLApprovals(fp)),
	}
	return emit(cp, timer, engine.NormalizeGLMergeRequest(fp), rec)
}

func loadCodeowners(prior engine.PriorPhase, fp string) map[string]any {
	var raw []byte
	for _, rp := range []string{"CODEOWNERS", ".gitlab/CODEOWNERS", "docs/CODEOWNERS"} {
		if b := entLoadRaw(prior, engine.CollectGLRepoFile(fp, rp)); b != nil {
			raw = b
			break
		}
	}
	if raw == nil {
		return map[string]any{
			"optional_sections": false, "covers_cicd_config": false, "self_owned_required": false,
		}
	}
	text := string(raw)
	optional := false
	inOptional := false
	coversCI := false
	selfOwned := false
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if strings.HasPrefix(l, "^[") || strings.HasPrefix(l, "[") {
			inOptional = strings.HasPrefix(l, "^[")
			if inOptional {
				optional = true
			}
			continue
		}
		path := strings.Fields(l)[0]
		if strings.Contains(path, ".gitlab-ci.yml") {
			coversCI = true
		}
		if !inOptional && (strings.Contains(path, "CODEOWNERS")) {
			selfOwned = true
		}
	}
	return map[string]any{
		"optional_sections":   optional,
		"covers_cicd_config":  coversCI,
		"self_owned_required": selfOwned,
	}
}

// requiredJobsEvadable reports whether the resolved pipeline can legitimately
// produce a skipped/empty pipeline that still satisfies "pipelines must succeed"
// (cat-06/13, doc line 309): every job is gated behind an author-controllable
// rules:/only:/except:/when: condition, or the workflow: itself carries a
// when: never branch, so an MR can yield no jobs. An unconditional job always runs,
// so nothing is evadable.
func requiredJobsEvadable(prior engine.PriorPhase, fp string) bool {
	pipeline, err := parseCIPipeline(entLoadRaw(prior, engine.CollectGLCIConfig(fp, ".gitlab-ci.yml")))
	if err != nil || pipeline == nil {
		return false
	}
	names := jobNames(pipeline)
	if len(names) == 0 {
		return false
	}
	def := entMap(pipeline["default"])
	for _, name := range names {
		if !jobConditionallyGated(mergeDefault(entMap(pipeline[name]), def)) {
			return false
		}
	}
	return true
}

func jobConditionallyGated(job map[string]any) bool {
	if _, ok := job["rules"]; ok {
		return true
	}
	if _, ok := job["only"]; ok {
		return true
	}
	if _, ok := job["except"]; ok {
		return true
	}
	if w, ok := job["when"]; ok {
		return entStr(w) == "manual" || entStr(w) == "never" || entStr(w) == "delayed"
	}
	return false
}

func approvalPolicy(prior engine.PriorPhase, fp string) map[string]any {
	pol := entLoadData(prior, engine.CollectGLSecurityPolicies(fp))
	nodes := entList(entGetIn(pol, "project", "approvalPolicies", "nodes"))
	enabled := false
	scanners := []any{}
	fallback := any(nil)
	enforcement := any(nil)
	bypassBroad := false
	for _, raw := range nodes {
		n := entMap(raw)
		en := entBool(n["enabled"])
		if en {
			enabled = true
		}
		spec := parsePolicyYAML(entStr(n["yaml"]))
		if spec == nil {
			continue
		}
		for _, s := range policyScanners(spec) {
			scanners = append(scanners, s)
		}
		// fallback_behavior: {fail: open|closed}. GitLab's default is fail_closed;
		// only an explicit fail:open weakens the gate. Report the first policy that
		// declares one so the fail-open rule reads a literal.
		if fallback == nil {
			if fb := entMap(spec["fallback_behavior"]); fb != nil {
				switch entStr(fb["fail"]) {
				case "open":
					fallback = "fail_open"
				case "closed":
					fallback = "fail_closed"
				}
			}
		}
		// enforcement_type: a require_approval action asking for zero approvals is a
		// self-dismissable warning; a positive count is the blocking mode.
		if enforcement == nil && en {
			if warnMode(spec) {
				enforcement = "warn"
			} else if hasRequireApproval(spec) {
				enforcement = "blocking"
			}
		}
		if en && bypassActorBroad(spec) {
			bypassBroad = true
		}
	}
	return map[string]any{
		"enabled":               enabled,
		"fallback_behavior":     fallback,
		"named_scanner_absent":  namedScannerAbsent(prior, fp, scanners),
		"enforcement_type":      enforcement,
		"binds_trusted_target":  false,
		"scope_excludes_target": false,
		"scanners":              scanners,
		"bypass_settings":       nil,
		"scope_broad":           false,
		"bypass_actor_broad":    bypassBroad,
	}
}

// namedScannerAbsent reports whether any scanner the approval policy names has no
// corresponding job/include in the target project's resolved .gitlab-ci.yml, so the
// scan_finding rule can never evaluate (cat-06/09, doc line 303). With no named
// scanners there is nothing that can be absent. A scanner is present when a pipeline
// job name matches it, a GitLab security template include names it, or Auto DevOps
// (which wires the full scanner suite) is on.
func namedScannerAbsent(prior engine.PriorPhase, fp string, scanners []any) bool {
	if len(scanners) == 0 {
		return false
	}
	present := pipelineScannersPresent(prior, fp)
	for _, raw := range scanners {
		name := strings.ToLower(entStr(raw))
		if name != "" && !present[name] {
			return true
		}
	}
	return false
}

// scannerTemplateFrag maps a GitLab scanner id to the distinctive fragment of the
// managed CI template that wires it (matched case-insensitively against include:
// template: strings and job names).
var scannerTemplateFrag = map[string]string{
	"sast":                   "sast",
	"secret_detection":       "secret-detection",
	"dependency_scanning":    "dependency-scanning",
	"container_scanning":     "container-scanning",
	"dast":                   "dast",
	"coverage_fuzzing":       "coverage-fuzzing",
	"api_fuzzing":            "api-fuzzing",
	"cluster_image_scanning": "cluster-image-scanning",
}

func pipelineScannersPresent(prior engine.PriorPhase, fp string) map[string]bool {
	present := map[string]bool{}
	raw := entLoadRaw(prior, engine.CollectGLCIConfig(fp, ".gitlab-ci.yml"))
	pipeline, err := parseCIPipeline(raw)
	if err != nil || pipeline == nil {
		return present
	}
	detail := entLoadData(prior, engine.CollectGLProject(fp))
	autoDevOps := detail != nil && entBool(detail["auto_devops_enabled"])

	jobs := map[string]bool{}
	for _, n := range jobNames(pipeline) {
		jobs[strings.ToLower(n)] = true
	}
	templates := includeTemplateStrings(pipeline["include"])
	for scanner, frag := range scannerTemplateFrag {
		if autoDevOps || jobs[scanner] {
			present[scanner] = true
			continue
		}
		for _, t := range templates {
			if strings.Contains(t, frag) {
				present[scanner] = true
				break
			}
		}
	}
	return present
}

func includeTemplateStrings(node any) []string {
	var out []string
	for _, entry := range includeEntries(node) {
		m, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		for _, k := range []string{"template", "local", "remote"} {
			if s, ok := m[k].(string); ok {
				out = append(out, strings.ToLower(s))
			}
		}
	}
	return out
}

func parsePolicyYAML(y string) map[string]any {
	if y == "" {
		return nil
	}
	var spec map[string]any
	if yamlUnmarshal([]byte(y), &spec) != nil {
		return nil
	}
	return spec
}

func policyScanners(spec map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	for _, raw := range entListOrEmpty(spec["rules"]) {
		for _, s := range entListOrEmpty(entMap(raw)["scanners"]) {
			if name := entStr(s); name != "" && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

func warnMode(spec map[string]any) bool {
	for _, raw := range entListOrEmpty(spec["actions"]) {
		a := entMap(raw)
		if entStr(a["type"]) == "require_approval" {
			if _, ok := a["approvals_required"]; ok && entInt64(a["approvals_required"]) == 0 {
				return true
			}
		}
	}
	return false
}

func hasRequireApproval(spec map[string]any) bool {
	for _, raw := range entListOrEmpty(spec["actions"]) {
		if entStr(entMap(raw)["type"]) == "require_approval" {
			return true
		}
	}
	return false
}

// bypassActorBroad reports whether bypass_settings exempts a broadly-held actor
// (a group, a service account/token, or a branch pattern) rather than naming a
// single break-glass identity.
func bypassActorBroad(spec map[string]any) bool {
	bs := entMap(spec["bypass_settings"])
	if bs == nil {
		return false
	}
	for _, k := range []string{"groups", "service_accounts", "access_tokens", "branches", "roles"} {
		if len(entListOrEmpty(bs[k])) > 0 {
			return true
		}
	}
	return false
}

func approverSetBroad(rules []any) bool {
	for _, raw := range rules {
		r := entMap(raw)
		if len(entListOrEmpty(r["groups"])) > 0 || entBool(r["applies_to_all_protected_branches"]) {
			return true
		}
	}
	return false
}

func independentApprovers(rules []any, members []any) int64 {
	var maxSet int64
	for _, raw := range rules {
		r := entMap(raw)
		if n := int64(len(entListOrEmpty(r["eligible_approvers"]))); n > maxSet {
			maxSet = n
		}
	}
	return maxSet
}

// ---- environment ----

func normalizeEnvironments(prior engine.PriorPhase, cp engine.CurrentPhase, p projectMeta, timer *engine.PhaseTimer) error {
	fp := p.FullPath
	envs := entLoadList(prior, engine.CollectGLEnvironments(fp))
	protEnvs := entLoadList(prior, engine.CollectGLProjectProtectedEnvironments(fp))
	groupProtEnvs := groupProtectedTiers(prior, p)
	protByName := map[string]map[string]any{}
	protNames := []string{}
	for _, raw := range protEnvs {
		pe := entMap(raw)
		name := entStr(pe["name"])
		protByName[name] = pe
		protNames = append(protNames, name)
	}
	for _, raw := range envs {
		e := entMap(raw)
		name := entStr(e["name"])
		if name == "" {
			continue
		}
		pe := protByName[name]
		tier := entStr(e["tier"])
		rules := envApprovalRules(pe)
		rec := map[string]any{
			"_id":                       fp + "/" + name,
			"name":                      name,
			"tier":                      tier,
			"protected":                 pe != nil,
			"self_declared_scope":       pe == nil && tier != "",
			"deploy_approvals_required": entInt64(pe["required_approval_count"]),
			"approval_rules":            rules,
			"allow_pipeline_trigger_approve_deployment": entBool(pe["allow_pipeline_trigger_approve_deployment"]),
			"carries_deploy_context":                    tier == "production" || tier == "staging",
			"near_miss_protected_name":                  nearMissProtected(name, protNames),
			"group_tier_protection_escaped":             tierEscaped(tier, groupProtEnvs, pe),
			"approval_rule_bot_approver":                anyRule(rules, func(r map[string]any) bool { return mBool(r, "is_bot") }),
			"_provenance":                               prov(engine.CollectGLEnvironments(fp)),
		}
		if err := emit(cp, timer, engine.NormalizeGLEnvironment(fp, name), rec); err != nil {
			return err
		}
	}
	return nil
}

func envApprovalRules(pe map[string]any) []any {
	out := []any{}
	for _, raw := range entListOrEmpty(pe["approval_rules"]) {
		r := entMap(raw)
		out = append(out, map[string]any{
			"access_level":          entInt64(r["access_level"]),
			"is_bot":                entBool(entMap(r["user"])["bot"]) || entBool(r["is_bot"]),
			"self_approval_allowed": false,
		})
	}
	return out
}

func groupProtectedTiers(prior engine.PriorPhase, p projectMeta) []string {
	out := []string{}
	group := parentGroup(p.FullPath)
	if group == "" {
		return out
	}
	for _, raw := range entLoadList(prior, engine.CollectGLGroupProtectedEnvironments(group)) {
		if name := entStr(entMap(raw)["name"]); name != "" {
			out = append(out, name)
		}
	}
	return out
}

func nearMissProtected(name string, protNames []string) bool {
	for _, pn := range protNames {
		if pn == name {
			return false
		}
	}
	lname := strings.ToLower(name)
	aliases := map[string]string{"prod": "production", "production": "prod", "stg": "staging", "staging": "stg"}
	for _, pn := range protNames {
		lpn := strings.ToLower(pn)
		if lpn == lname || strings.HasPrefix(lname, lpn+"/") || strings.HasPrefix(lpn, lname+"/") {
			return true
		}
		if aliases[lname] == lpn || aliases[lpn] == lname {
			return true
		}
	}
	return false
}

func tierEscaped(tier string, groupTiers []string, pe map[string]any) bool {
	if len(groupTiers) == 0 || pe != nil {
		return false
	}
	for _, gt := range groupTiers {
		if gt == tier {
			return false
		}
	}
	return true
}

// ---- runner ----

// normalizeRunners emits one record per distinct runner across project, group,
// and instance scope, deduplicated by id.
func normalizeRunners(prior engine.PriorPhase, cp engine.CurrentPhase, org string, projs []projectMeta, timer *engine.PhaseTimer) error {
	settings := entLoadData(prior, engine.CollectGLInstanceSettings())
	reusable := !entUnobserved(settings) && settings != nil && entBool(settings["allow_runner_registration_token"])

	seen := map[int64]bool{}
	emitOne := func(raw any, scope string) error {
		r := entMap(raw)
		id := entInt64(r["id"])
		if id == 0 || seen[id] {
			return nil
		}
		seen[id] = true
		coResident := entLoadList(prior, engine.CollectGLRunnerProjects(id))
		rec := runnerRecord(r, scope, coResident, reusable)
		runnerReachFolds(prior, rec, coResident, scope, projs)
		return emit(cp, timer, engine.NormalizeGLRunner(id), rec)
	}
	for _, raw := range entLoadList(prior, engine.CollectGLInstanceRunners()) {
		if err := emitOne(raw, "instance"); err != nil {
			return err
		}
	}
	for _, g := range groupRoster(prior, org) {
		for _, raw := range entLoadList(prior, engine.CollectGLGroupRunners(g)) {
			if err := emitOne(raw, "group:"+g); err != nil {
				return err
			}
		}
	}
	for _, p := range projs {
		for _, raw := range entLoadList(prior, engine.CollectGLProjectRunners(p.FullPath)) {
			if err := emitOne(raw, "project:"+p.FullPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func runnerRecord(r map[string]any, scope string, coResident []any, reusable bool) map[string]any {
	projects := []any{}
	for _, raw := range coResident {
		if fp := entStr(entMap(raw)["path_with_namespace"]); fp != "" {
			projects = append(projects, fp)
		}
	}
	return map[string]any{
		"_id":                            runnerID(r),
		"runner_type":                    entStr(r["runner_type"]),
		"is_shared":                      entBool(r["is_shared"]),
		"ref_protected":                  entStr(r["access_level"]) == "ref_protected",
		"run_untagged":                   entBool(r["run_untagged"]),
		"locked":                         entBool(r["locked"]),
		"tags":                           sortedStrSet(entListOrEmpty(r["tag_list"])),
		"projects":                       projects,
		"registration_token_reusable":    reusable,
		"self_managed":                   classifySelfManaged(r),
		"spans_trust_boundary":           false,
		"serves_protected_ref_only_jobs": false,
		"serves_untrusted_ref_jobs":      false,
		"untrusted_ref_job_matches_tags": false,
		"bridges_trust_boundary":         len(projects) >= 2,
		"_provenance":                    []provenance{{"scope": scope}},
	}
}

func runnerID(r map[string]any) string { return fmt.Sprintf("%d", entInt64(r["id"])) }

// runnerReachFolds computes the cat-08 runner effective folds (normalizer-computed
// per the field contract) from the runner's reachable projects and the jobs those
// projects target the runner with:
//   - spans_trust_boundary: reachable projects straddle a trust boundary (≥1 holds
//     protected resources AND ≥1 is a broad/low-trust project).
//   - serves_protected_ref_only_jobs / serves_untrusted_ref_jobs: the runner is
//     targeted (by matching tags / run_untagged) by protected-ref-only jobs and/or
//     untrusted-ref jobs — both true means trusted and untrusted workloads share it.
//   - untrusted_ref_job_matches_tags: an untrusted-ref job on an attacker-writable
//     ref carries tags: matching this runner (can be steered onto it).
//
// Reachable projects are the co-resident list from /runners/:id/projects; an
// instance/group runner with an empty list falls back to the roster projects in
// its scope.
func runnerReachFolds(prior engine.PriorPhase, rec map[string]any, coResident []any, scope string, projs []projectMeta) {
	reach := runnerReachProjects(coResident, scope, projs)
	tags := strListOf(listOrEmptyGL(rec, "tags"))
	runUntagged := mBool(rec, "run_untagged")

	holdsProtected, lowTrust := false, false
	servesProtectedOnly, servesUntrusted, untrustedMatchesTags := false, false, false
	for _, proj := range reach {
		vars := entLoadList(prior, engine.CollectGLProjectVariables(proj))
		branches := normalizeProtectedBranches(entLoadList(prior, engine.CollectGLProtectedBranches(proj)))
		protEnvs := entLoadList(prior, engine.CollectGLProjectProtectedEnvironments(proj))
		if anyVar(normalizeVariables(vars, "project"), func(v map[string]any) bool { return mBool(v, "protected") }) || len(protEnvs) > 0 {
			holdsProtected = true
		}
		if developerPushableUnprotectedRef(branches) {
			lowTrust = true
		}
		ciWritable := sourceCIWritableForRunner(branches)
		forEachJobRef(prior, proj, func(gate string, untrusted bool, jobTags []any) {
			if !runnerTargetedBy(tags, runUntagged, jobTags) {
				return
			}
			if untrusted {
				servesUntrusted = true
				if ciWritable {
					untrustedMatchesTags = true
				}
			} else if gate != "none" {
				servesProtectedOnly = true
			}
		})
	}
	rec["spans_trust_boundary"] = holdsProtected && lowTrust
	rec["serves_protected_ref_only_jobs"] = servesProtectedOnly
	rec["serves_untrusted_ref_jobs"] = servesUntrusted
	rec["untrusted_ref_job_matches_tags"] = untrustedMatchesTags
}

func runnerReachProjects(coResident []any, scope string, projs []projectMeta) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range coResident {
		if fp := entStr(entMap(raw)["path_with_namespace"]); fp != "" && !seen[fp] {
			seen[fp] = true
			out = append(out, fp)
		}
	}
	if len(out) > 0 {
		return out
	}
	// Instance/group runner with no co-resident list: fall back to the roster
	// projects in scope (all roster for instance, subtree for group:<path>).
	prefix := strings.TrimPrefix(scope, "group:")
	for _, p := range projs {
		if scope == "instance" || strings.HasPrefix(scope, "instance") ||
			p.FullPath == prefix || strings.HasPrefix(p.FullPath, prefix+"/") {
			out = append(out, p.FullPath)
		}
	}
	return out
}

// runnerTargetedBy reports whether a job with jobTags can land on a runner with
// runnerTags: an untagged job needs run_untagged; a tagged job needs the runner to
// carry every tag it requests.
func runnerTargetedBy(runnerTags []string, runUntagged bool, jobTags []any) bool {
	jt := strListOf(jobTags)
	if len(jt) == 0 {
		return runUntagged
	}
	have := map[string]bool{}
	for _, t := range runnerTags {
		have[t] = true
	}
	for _, t := range jt {
		if !have[t] {
			return false
		}
	}
	return true
}

// forEachJobRef parses a project's entrypoint and yields each job's protected-ref
// gate, untrusted-ref reachability, and tags. Parse failures are skipped (the
// runner folds degrade to false for that project, not an abort).
func forEachJobRef(prior engine.PriorPhase, proj string, fn func(gate string, untrusted bool, jobTags []any)) {
	raw := entLoadRaw(prior, engine.CollectGLCIConfig(proj, ".gitlab-ci.yml"))
	if raw == nil {
		return
	}
	pipeline, err := parseCIPipeline(raw)
	if err != nil || pipeline == nil {
		return
	}
	workflow := entMap(pipeline["workflow"])
	def := entMap(pipeline["default"])
	for _, name := range jobNames(pipeline) {
		job := mergeDefault(entMap(pipeline[name]), def)
		gate := protectedRefGate(job, workflow)
		untrusted := runsOnUntrustedRef(resolveTriggers(job, workflow), gate)
		fn(gate, untrusted, runnerTags(job))
	}
}

// sourceCIWritableForRunner reports the project's CI config / refs are writable by
// a lower-trust member (no protection, or a Developer-writable protected branch).
func sourceCIWritableForRunner(branches []map[string]any) bool {
	return developerPushableUnprotectedRef(branches) || anyBranch(branches, func(b map[string]any) bool {
		return grantsDeveloper(mList(b, "push_access_levels")) || grantsDeveloper(mList(b, "merge_access_levels"))
	})
}

// classifySelfManaged is the load-bearing self_managed classifier. GitLab.com
// shared SaaS runners carry a saas platform / gitlab-hosted description; anything
// else (operator-run) is self-managed.
func classifySelfManaged(r map[string]any) bool {
	desc := strings.ToLower(entStr(r["description"]))
	platform := strings.ToLower(entStr(r["platform"]))
	if strings.Contains(desc, "saas") || strings.Contains(desc, "gitlab-hosted") ||
		strings.Contains(desc, "shared") && strings.Contains(desc, "gitlab.com") {
		return false
	}
	if platform == "" && entStr(r["runner_type"]) == "instance_type" && entBool(r["is_shared"]) && desc == "" {
		return false
	}
	return true
}

// reachableRunners returns project-scope runner records (project runners plus
// inherited group/instance). Used only for project derived booleans; the full
// runner subject records are emitted by normalizeRunners.
func reachableRunners(prior engine.PriorPhase, fp string) []map[string]any {
	out := []map[string]any{}
	for _, raw := range entLoadList(prior, engine.CollectGLProjectRunners(fp)) {
		r := entMap(raw)
		out = append(out, map[string]any{
			"self_managed":  classifySelfManaged(r),
			"ref_protected": entStr(r["access_level"]) == "ref_protected",
			"runner_type":   entStr(r["runner_type"]),
		})
	}
	return out
}

func reachableRunnerList(runners []any) []map[string]any {
	out := []map[string]any{}
	for _, raw := range runners {
		r := entMap(raw)
		out = append(out, map[string]any{
			"self_managed":  classifySelfManaged(r),
			"ref_protected": entStr(r["access_level"]) == "ref_protected",
			"runner_type":   entStr(r["runner_type"]),
		})
	}
	return out
}

// ---- agent ----

func normalizeAgents(prior engine.PriorPhase, cp engine.CurrentPhase, p projectMeta, projs []projectMeta, timer *engine.PhaseTimer) error {
	fp := p.FullPath
	data := entLoadData(prior, engine.CollectGLClusterAgents(fp))
	if data == nil || entUnobserved(data) {
		return nil
	}
	nodes := entList(entGetIn(data, "project", "clusterAgents", "nodes"))
	settings := entLoadData(prior, engine.CollectGLInstanceSettings())
	instAgentAuth := !entUnobserved(settings) && settings != nil && entBool(settings["instance_level_ai_beta_features_enabled"])
	for _, raw := range nodes {
		node := entMap(raw)
		name := entStr(node["name"])
		if name == "" {
			continue
		}
		cfg := parseAgentConfig(entLoadRaw(prior, engine.CollectGLAgentConfig(fp, name)))
		targets, scope := agentTargets(node)
		envFilter := entListOrEmpty(cfg["environments"])
		protOnly := entBool(cfg["protected_branches_only"])
		// The grant's reachable target projects: explicit ci_access targets
		// (projects, or every project under a group target), else the config
		// project itself when the grant is implicit.
		reach := agentReachProjects(targets, fp, projs)
		folds := agentGrantFolds(prior, reach, envFilter, protOnly)
		rec := map[string]any{
			"_id":                                         fp + "/" + name,
			"config_path":                                 ".gitlab/agents/" + name + "/config.yaml",
			"ci_access_scope":                             scope,
			"ci_access_targets":                           targets,
			"implicit_config_project":                     len(targets) == 0,
			"protected_branches_only":                     protOnly,
			"environments_filter":                         envFilter,
			"impersonation":                               agentImpersonation(cfg),
			"default_permissions":                         agentDefaultPermissions(cfg),
			"environments_filter_wildcard":                anyStr(envFilter, func(s string) bool { return strings.Contains(s, "*") }),
			"namespace_plan":                              namespacePlan(prior, fp),
			"instance_agent_authorization_enabled":        instAgentAuth,
			"grant_has_lower_trust_developer":             folds.lowerTrustDeveloper,
			"grant_developer_pushable_unprotected_branch": folds.developerPushableUnprotected,
			"config_project_developer_reachable":          len(targets) == 0 && folds.developerReachable,
			"environments_filter_unprotected":             folds.envFilterUnprotected,
			"grant_developer_authors_matching_env_job":    folds.developerAuthorsMatchingEnvJob,
			"grant_protected_ref_developer_writable":      folds.protectedRefDeveloperWritable,
			"_provenance":                                 prov(engine.CollectGLClusterAgents(fp)),
		}
		if err := emit(cp, timer, engine.NormalizeGLAgent(fp, name), rec); err != nil {
			return err
		}
	}
	return nil
}

// agentImpersonation returns the access_as impersonation config, or NIL when no
// access_as is configured (cat-15: rules read impersonation == null; an empty
// {} would never match that predicate).
func agentImpersonation(cfg map[string]any) any {
	m := entMap(cfg["access_as"])
	if len(m) == 0 {
		return nil
	}
	return m
}

// agentReachProjects resolves the project paths a ci_access grant authorizes:
// each explicit project target, every roster project under a group target, or
// the agent's own config project when the grant is implicit.
func agentReachProjects(targets []any, configProject string, projs []projectMeta) []string {
	if len(targets) == 0 {
		return []string{configProject}
	}
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	rosterHas := map[string]bool{}
	for _, p := range projs {
		rosterHas[p.FullPath] = true
	}
	for _, raw := range targets {
		t := entStr(raw)
		if rosterHas[t] {
			add(t)
			continue
		}
		// Group target: every roster project inside the group subtree.
		for _, p := range projs {
			if p.FullPath == t || strings.HasPrefix(p.FullPath, t+"/") {
				add(p.FullPath)
			}
		}
	}
	return out
}

type agentFolds struct {
	lowerTrustDeveloper            bool
	developerPushableUnprotected   bool
	developerReachable             bool
	envFilterUnprotected           bool
	developerAuthorsMatchingEnvJob bool
	protectedRefDeveloperWritable  bool
}

// agentGrantFolds computes the cat-15 agent-ci-access effective folds from each
// reachable target project's collected membership, protected-branch/tag, and
// protected-environment data. These are the correlation the DSL cannot express
// (agent grant → per-target membership + ref/env protection).
func agentGrantFolds(prior engine.PriorPhase, reach []string, envFilter []any, protectedBranchesOnly bool) agentFolds {
	var f agentFolds
	for _, tgt := range reach {
		members := entLoadList(prior, engine.CollectGLProjectMembers(tgt))
		branches := normalizeProtectedBranches(entLoadList(prior, engine.CollectGLProtectedBranches(tgt)))
		tags := normalizeProtectedTags(entLoadList(prior, engine.CollectGLProtectedTags(tgt)))
		protEnvs := entLoadList(prior, engine.CollectGLProjectProtectedEnvironments(tgt))

		hasDeveloper := hasMemberAtLevel(members, accessDeveloper)
		if hasDeveloper {
			f.lowerTrustDeveloper = true
			f.developerReachable = true
		}
		devPushUnprot := developerPushableUnprotectedRef(branches)
		if hasDeveloper && devPushUnprot {
			f.developerPushableUnprotected = true
			f.developerReachable = true
		}
		// A protected ref a Developer can land on satisfies protected_branches_only:
		// a Developer-writable protected branch, a Developer-creatable wildcard
		// branch, or a Developer-creatable protected tag.
		if hasDeveloper && (anyBranch(branches, func(b map[string]any) bool {
			return grantsDeveloper(mList(b, "push_access_levels")) || grantsDeveloper(mList(b, "merge_access_levels"))
		}) || anyTag(tags, func(t map[string]any) bool {
			return grantsDeveloper(mList(t, "create_access_levels"))
		})) {
			f.protectedRefDeveloperWritable = true
		}
		// A fixed (non-wildcard) filter name absent from the target's protected
		// environments (or protected with a Developer-inclusive deployer) gates
		// nothing.
		if agentEnvFilterUnprotected(envFilter, protEnvs) {
			f.envFilterUnprotected = true
		}
		// A Developer can author a job binding environment: to a filter-matching
		// value while running on a ref they can reach: unprotected when the grant
		// is not protected_branches_only, else a Developer-landable protected ref.
		if hasDeveloper && len(envFilter) > 0 {
			refReachable := devPushUnprot
			if protectedBranchesOnly {
				refReachable = f.protectedRefDeveloperWritable
			}
			if refReachable {
				f.developerAuthorsMatchingEnvJob = true
			}
		}
	}
	return f
}

// agentEnvFilterUnprotected: at least one fixed (non-wildcard) filter name is not
// covered by an exact protected-environment entry, or is protected only with a
// Developer-inclusive deployer list, so the name is not a real boundary.
func agentEnvFilterUnprotected(envFilter []any, protEnvs []any) bool {
	prot := map[string]map[string]any{}
	for _, raw := range protEnvs {
		pe := entMap(raw)
		prot[entStr(pe["name"])] = pe
	}
	for _, raw := range envFilter {
		name := entStr(raw)
		if name == "" || strings.Contains(name, "*") {
			continue
		}
		pe, ok := prot[name]
		if !ok {
			return true
		}
		for _, r := range entListOrEmpty(pe["deploy_access_levels"]) {
			if entInt64(entMap(r)["access_level"]) <= accessDeveloper && entInt64(entMap(r)["access_level"]) > 0 {
				return true
			}
		}
	}
	return false
}

func agentTargets(node map[string]any) ([]any, string) {
	targets := []any{}
	for _, raw := range entList(entGetIn(node, "ciAccessAuthorizedProjects", "nodes")) {
		if fp := entStr(entMap(raw)["fullPath"]); fp != "" {
			targets = append(targets, fp)
		}
	}
	groups := entList(entGetIn(node, "ciAccessAuthorizedGroups", "nodes"))
	for _, raw := range groups {
		if fp := entStr(entMap(raw)["fullPath"]); fp != "" {
			targets = append(targets, fp)
		}
	}
	scope := "project"
	if len(groups) > 0 {
		scope = "group"
	}
	return targets, scope
}

func parseAgentConfig(raw []byte) map[string]any {
	if raw == nil {
		return map[string]any{}
	}
	var cfg map[string]any
	if yamlUnmarshal(raw, &cfg) != nil {
		return map[string]any{}
	}
	ci := entMap(cfg["ci_access"])
	// ci_access holds project/group entries whose shared shape carries
	// environments/protected_branches_only/default_namespace access_as.
	out := map[string]any{}
	if pb, ok := firstAccessField(ci, "protected_branches_only"); ok {
		out["protected_branches_only"] = pb
	}
	if envs, ok := firstAccessListField(ci, "environments"); ok {
		out["environments"] = envs
	}
	if aa, ok := firstAccessField(ci, "access_as"); ok {
		out["access_as"] = aa
	}
	if dp, ok := firstAccessField(ci, "default_namespace"); ok {
		out["default_permissions"] = dp
	}
	return out
}

func firstAccessField(ci map[string]any, key string) (any, bool) {
	for _, scope := range []string{"projects", "groups"} {
		for _, raw := range entList(ci[scope]) {
			if v, ok := entMap(raw)[key]; ok {
				return v, true
			}
		}
	}
	if v, ok := ci[key]; ok {
		return v, true
	}
	return nil, false
}

func firstAccessListField(ci map[string]any, key string) ([]any, bool) {
	v, ok := firstAccessField(ci, key)
	if !ok {
		return nil, false
	}
	return entListOrEmpty(v), true
}

func agentDefaultPermissions(cfg map[string]any) bool {
	if _, ok := cfg["access_as"]; ok {
		return false
	}
	return true
}

func namespacePlan(prior engine.PriorPhase, fp string) any {
	group := parentGroup(fp)
	if group == "" {
		return nil
	}
	ns := entLoadData(prior, engine.CollectGLNamespace(group))
	if ns == nil || entUnobserved(ns) {
		return nil
	}
	return entStr(ns["plan"])
}

// ---- credential ----

func normalizeCredentials(prior engine.PriorPhase, cp engine.CurrentPhase, p projectMeta, timer *engine.PhaseTimer) error {
	fp := p.FullPath
	settings := entLoadData(prior, engine.CollectGLInstanceSettings())
	expEnforced := !entUnobserved(settings) && settings != nil && entBool(settings["service_access_tokens_expiration_enforced"])
	usesOIDC := ciYAMLHasDeployIdentity(entLoadRaw(prior, engine.CollectGLCIConfig(fp, ".gitlab-ci.yml")))

	emitCred := func(kind, key string, rec map[string]any) error {
		rec["_id"] = kind + ":" + key
		rec["kind"] = kind
		rec["project_uses_oidc"] = usesOIDC
		rec["_provenance"] = []provenance{{"scope": "project:" + fp}}
		return emit(cp, timer, engine.NormalizeGLCredential(kind, kind+"-"+key), rec)
	}

	for _, raw := range entLoadList(prior, engine.CollectGLProjectDeployTokens(fp)) {
		t := entMap(raw)
		if err := emitCred("deploy_token", credKey(fp, "dt", t["id"]), deployTokenRec(t, "project", expEnforced)); err != nil {
			return err
		}
	}
	for _, raw := range entLoadList(prior, engine.CollectGLGroupDeployTokens(parentGroup(fp))) {
		t := entMap(raw)
		if err := emitCred("deploy_token", credKey(parentGroup(fp), "gdt", t["id"]), deployTokenRec(t, "group", expEnforced)); err != nil {
			return err
		}
	}
	for _, raw := range entLoadList(prior, engine.CollectGLProjectAccessTokens(fp)) {
		t := entMap(raw)
		if err := emitCred("project_access_token", credKey(fp, "pat", t["id"]), accessTokenRec(t, "project", expEnforced)); err != nil {
			return err
		}
	}
	for _, raw := range entLoadList(prior, engine.CollectGLGroupAccessTokens(parentGroup(fp))) {
		t := entMap(raw)
		if err := emitCred("group_access_token", credKey(parentGroup(fp), "gat", t["id"]), accessTokenRec(t, "group", expEnforced)); err != nil {
			return err
		}
	}
	for _, raw := range entLoadList(prior, engine.CollectGLDeployKeys(fp)) {
		k := entMap(raw)
		if err := emitCred("deploy_key", credKey(fp, "dk", k["id"]), deployKeyRec(k)); err != nil {
			return err
		}
	}
	// static_cloud_cred (cat-11): P2 collects variable KEYS (values stripped), so a
	// cloud-cred-shaped variable key is a collected source for a static cloud
	// credential. The credential IS the variable, so in_unprotected_variable is
	// directly derivable (the variable's own protected flag). PATs have no P2
	// collect source and are a documented known-gap — not fabricated here.
	for i, raw := range entLoadList(prior, engine.CollectGLProjectVariables(fp)) {
		v := entMap(raw)
		key := entStr(v["key"])
		if !cloudCredKey(key) {
			continue
		}
		if err := emitCred("static_cloud_cred", credKey(fp, "scc", int64(i)), staticCloudCredRec(v, "project")); err != nil {
			return err
		}
	}
	return nil
}

// staticCloudCredRec builds a static_cloud_cred credential from a cloud-cred-shaped
// CI/CD variable. The credential's reachability via the variable is not a deferred
// leg here (the variable IS the credential), so in_unprotected_variable is the
// variable's own protected flag.
func staticCloudCredRec(v map[string]any, scopeLevel string) map[string]any {
	unprotected := !entBool(v["protected"])
	return map[string]any{
		"scopes":                              []any{},
		"access_level":                        nil,
		"non_expiring":                        true,
		"revoked":                             false,
		"auto_injected":                       false,
		"name":                                entStr(v["key"]),
		"scope_level":                         scopeLevel,
		"service_account":                     false,
		"long_lived":                          true,
		"can_push":                            false,
		"in_unprotected_variable":             unprotected,
		"key_pattern":                         "cloud",
		"deploy_key_fingerprint":              nil,
		"backing_identity_breadth":            []any{},
		"is_schedule_owner":                   false,
		"creator_has_target_protected_access": false,
	}
}

var cloudCredFrags = []string{
	"AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN",
	"AZURE_CLIENT_SECRET", "AZURE_CLIENT_ID", "ARM_CLIENT_SECRET",
	"GCP_SA_KEY", "GCP_SERVICE_ACCOUNT", "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CREDENTIALS",
	"DIGITALOCEAN_ACCESS_TOKEN", "DO_TOKEN", "ALIYUN_ACCESS_KEY",
}

// cloudCredKey matches a variable key that names a static cloud credential (a
// long-lived cloud key), narrower than the generic secret heuristic.
func cloudCredKey(key string) bool {
	u := strings.ToUpper(key)
	for _, frag := range cloudCredFrags {
		if strings.Contains(u, frag) {
			return true
		}
	}
	return false
}

func credKey(scope, kind string, id any) string {
	return fmt.Sprintf("%s-%s-%d", glSlug(scope), kind, entInt64(id))
}

func glSlug(s string) string { return strings.ReplaceAll(s, "/", "-") }

func deployTokenRec(t map[string]any, scopeLevel string, expEnforced bool) map[string]any {
	name := entStr(t["name"])
	return map[string]any{
		"scopes":                              sortedStrSet(entListOrEmpty(t["scopes"])),
		"access_level":                        nil,
		"non_expiring":                        t["expires_at"] == nil,
		"revoked":                             entBool(t["revoked"]) || entBool(t["expired"]),
		"auto_injected":                       name == "gitlab-deploy-token",
		"name":                                name,
		"scope_level":                         scopeLevel,
		"service_account":                     false,
		"long_lived":                          longLived(t["expires_at"], expEnforced),
		"can_push":                            tokenHasScope(t, "write_repository"),
		"in_unprotected_variable":             false,
		"key_pattern":                         nil,
		"deploy_key_fingerprint":              nil,
		"backing_identity_breadth":            []any{},
		"is_schedule_owner":                   false,
		"creator_has_target_protected_access": false,
	}
}

func accessTokenRec(t map[string]any, scopeLevel string, expEnforced bool) map[string]any {
	return map[string]any{
		"scopes":                              sortedStrSet(entListOrEmpty(t["scopes"])),
		"access_level":                        entInt64(t["access_level"]),
		"non_expiring":                        t["expires_at"] == nil,
		"revoked":                             entBool(t["revoked"]) || !boolDefaultTrue(t["active"]),
		"auto_injected":                       false,
		"name":                                entStr(t["name"]),
		"scope_level":                         scopeLevel,
		"service_account":                     false,
		"long_lived":                          longLived(t["expires_at"], expEnforced),
		"can_push":                            tokenHasScope(t, "write_repository") || tokenHasScope(t, "api"),
		"in_unprotected_variable":             false,
		"key_pattern":                         nil,
		"deploy_key_fingerprint":              nil,
		"backing_identity_breadth":            accessTokenBreadth(t),
		"is_schedule_owner":                   false,
		"creator_has_target_protected_access": false,
	}
}

func deployKeyRec(k map[string]any) map[string]any {
	return map[string]any{
		"scopes":                              []any{},
		"access_level":                        nil,
		"non_expiring":                        k["expires_at"] == nil,
		"revoked":                             false,
		"auto_injected":                       false,
		"name":                                entStr(k["title"]),
		"scope_level":                         "project",
		"service_account":                     false,
		"long_lived":                          k["expires_at"] == nil,
		"can_push":                            entBool(k["can_push"]),
		"deploy_key_fingerprint":              firstNonEmpty(entStr(k["fingerprint_sha256"]), entStr(k["fingerprint"])),
		"key_pattern":                         nil,
		"in_unprotected_variable":             false,
		"backing_identity_breadth":            []any{},
		"is_schedule_owner":                   false,
		"creator_has_target_protected_access": false,
	}
}

func accessTokenBreadth(t map[string]any) []any {
	// user-memberships is collected per backing user id; absent → [] (C1).
	return []any{}
}

func tokenHasScope(t map[string]any, scope string) bool {
	for _, s := range entListOrEmpty(t["scopes"]) {
		if entStr(s) == scope {
			return true
		}
	}
	return false
}

func boolDefaultTrue(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return true
}

// longLived: expires_at null OR ≥ ~330 days out (covers legacy non-expiring and
// the ~1-year default). Dates are ISO8601 (YYYY-MM-DD or full timestamp).
func longLived(expiresAt any, expEnforced bool) bool {
	s := entStr(expiresAt)
	if s == "" {
		return true
	}
	exp := parseDatePrefix(s)
	if exp.IsZero() {
		return false
	}
	return exp.Sub(nowUTC()).Hours() >= 330*24
}

// ---- integration ----

func normalizeIntegrations(prior engine.PriorPhase, cp engine.CurrentPhase, p projectMeta, timer *engine.PhaseTimer) error {
	fp := p.FullPath
	detail := entLoadData(prior, engine.CollectGLProject(fp))
	settings := entLoadData(prior, engine.CollectGLInstanceSettings())
	allowLocal := !entUnobserved(settings) && settings != nil && entBool(settings["allow_local_requests_from_web_hooks_and_services"])

	// A Maintainer can edit a project hook/integration's delivery URL but sits below
	// the Owner-trust of whoever set the write-only credential (doc line 418). Its
	// presence, ANDed per-record with an attached write credential, is the
	// editor_below_credential_trust fold the cat-14 recapture rules read.
	hasEditorBelowTrust := hasMemberAtLevel(entLoadList(prior, engine.CollectGLProjectMembers(fp)), accessMaintainer)

	emitInt := func(kind, key string, rec map[string]any) error {
		rec["_id"] = fp + "/" + kind + ":" + key
		rec["kind"] = kind
		rec["_provenance"] = prov(engine.CollectGLProject(fp))
		return emit(cp, timer, engine.NormalizeGLIntegration(fp, kind, key), rec)
	}

	for _, raw := range entLoadList(prior, engine.CollectGLWebhooks(fp)) {
		h := entMap(raw)
		if err := emitInt("webhook", fmt.Sprintf("%d", entInt64(h["id"])), webhookRec(h, allowLocal, hasEditorBelowTrust)); err != nil {
			return err
		}
	}
	for _, raw := range entLoadList(prior, engine.CollectGLIntegrations(fp)) {
		i := entMap(raw)
		if err := emitInt("integration", entStr(i["slug"]), integrationRec(i, allowLocal, hasEditorBelowTrust)); err != nil {
			return err
		}
	}
	if detail != nil && entBool(detail["mirror"]) {
		if err := emitInt("pull_mirror", "pull", pullMirrorRec(detail, prior, fp, hasEditorBelowTrust)); err != nil {
			return err
		}
	}
	for idx, raw := range entLoadList(prior, engine.CollectGLMirrors(fp)) {
		m := entMap(raw)
		if err := emitInt("push_mirror", fmt.Sprintf("%d", idx), mirrorRec(m, detail, prior, fp, hasEditorBelowTrust)); err != nil {
			return err
		}
	}
	if detail != nil && entStr(detail["pages_access_level"]) != "disabled" && entStr(detail["pages_access_level"]) != "" {
		if err := emitInt("pages", "pages", pagesRec(detail)); err != nil {
			return err
		}
	}
	return nil
}

func webhookRec(h map[string]any, allowLocal, hasEditorBelowTrust bool) map[string]any {
	tokenPresent := entBool(h["token_present"])
	headers := entListOrEmpty(h["custom_headers"])
	return map[string]any{
		"url":                           entStr(h["url"]),
		"url_mutable":                   true,
		"token_present":                 tokenPresent,
		"custom_headers":                headers,
		"allows_local_network":          allowLocal && !entBool(h["enable_ssl_verification"]) || allowLocal,
		"webhook_signing_token_present": entBool(h["signing_token_present"]),
		"firable_event_trigger":         webhookFirable(h),
		"editor_below_credential_trust": hasEditorBelowTrust && (tokenPresent || len(headers) > 0),
	}
}

func webhookFirable(h map[string]any) bool {
	for _, k := range []string{"push_events", "note_events", "merge_requests_events", "pipeline_events", "issues_events", "tag_push_events"} {
		if entBool(h[k]) {
			return true
		}
	}
	return false
}

func integrationRec(i map[string]any, allowLocal, hasEditorBelowTrust bool) map[string]any {
	tokenPresent := entBool(i["active"]) && entBool(i["token_present"])
	return map[string]any{
		"url":                           "",
		"url_mutable":                   true,
		"token_present":                 tokenPresent,
		"custom_headers":                []any{},
		"allows_local_network":          allowLocal,
		"webhook_signing_token_present": false,
		"firable_event_trigger":         webhookFirable(i),
		"editor_below_credential_trust": hasEditorBelowTrust && tokenPresent,
	}
}

// pullMirrorRec normalizes the cat-14 pull-mirror surface. Pull mirroring is a
// project-detail attribute (mirror==true + import_url), not a /remote_mirrors
// entry — those are push mirrors and stay empty for pull-only projects.
func pullMirrorRec(detail map[string]any, prior engine.PriorPhase, fp string, hasEditorBelowTrust bool) map[string]any {
	importURL := entStr(detail["import_url"])
	triggerPipelines := entBool(detail["mirror_trigger_builds"])
	allBranches := !entBool(detail["only_mirror_protected_branches"])
	branches := normalizeProtectedBranches(entLoadList(prior, engine.CollectGLProtectedBranches(fp)))
	defaultBranch := entStr(detail["default_branch"])
	defaultProtected := anyBranch(branches, func(b map[string]any) bool { return globMatch(mStr(b, "pattern"), defaultBranch) })
	vars := mirrorReachableVars(prior, fp)
	protectedBranchPipeline := triggerPipelines && (defaultProtected || !allBranches)
	mirror := map[string]any{
		"trigger_pipelines":            triggerPipelines,
		"all_branches":                 allBranches,
		"upstream_untrusted_host":      mirrorUntrustedHost(importURL, fp),
		"protected_default_branch":     defaultProtected,
		"reaches_protected_variable":   protectedBranchPipeline && anyVar(vars, func(v map[string]any) bool { return mBool(v, "protected") }),
		"reaches_unprotected_variable": triggerPipelines && anyVar(vars, func(v map[string]any) bool { return !mBool(v, "protected") }),
		"job_token_push_allowed":       entBool(detail["ci_push_repository_for_job_token_allowed"]),
	}
	tokenPresent := importURL != "" && strings.Contains(importURL, "@")
	return map[string]any{
		"url":                           importURL,
		"url_mutable":                   true,
		"token_present":                 tokenPresent,
		"custom_headers":                []any{},
		"allows_local_network":          false,
		"webhook_signing_token_present": false,
		"firable_event_trigger":         triggerPipelines,
		"editor_below_credential_trust": hasEditorBelowTrust && tokenPresent,
		"mirror":                        mirror,
	}
}

func mirrorRec(m, detail map[string]any, prior engine.PriorPhase, fp string, hasEditorBelowTrust bool) map[string]any {
	importURL := entStr(m["url"])
	if importURL == "" {
		importURL = entStr(m["import_url"])
	}
	triggerPipelines := entBool(m["trigger_pipelines"])
	allBranches := !entBool(m["only_protected_branches"])
	branches := normalizeProtectedBranches(entLoadList(prior, engine.CollectGLProtectedBranches(fp)))
	defaultBranch := ""
	if detail != nil {
		defaultBranch = entStr(detail["default_branch"])
	}
	defaultProtected := anyBranch(branches, func(b map[string]any) bool { return globMatch(mStr(b, "pattern"), defaultBranch) })
	// The auto-triggered mirror pipeline runs on the mirrored branch(es). A
	// protected CI/CD variable is reachable only when the mirror pipeline runs on
	// a protected branch (default branch protected, or mirror confined to protected
	// branches); an unprotected/masked variable is reachable on any mirrored branch.
	vars := mirrorReachableVars(prior, fp)
	protectedBranchPipeline := triggerPipelines && (defaultProtected || !allBranches)
	mirror := map[string]any{
		"trigger_pipelines":            triggerPipelines,
		"all_branches":                 allBranches,
		"upstream_untrusted_host":      mirrorUntrustedHost(importURL, fp),
		"protected_default_branch":     defaultProtected,
		"reaches_protected_variable":   protectedBranchPipeline && anyVar(vars, func(v map[string]any) bool { return mBool(v, "protected") }),
		"reaches_unprotected_variable": triggerPipelines && anyVar(vars, func(v map[string]any) bool { return !mBool(v, "protected") }),
		"job_token_push_allowed":       detail != nil && entBool(detail["ci_push_repository_for_job_token_allowed"]),
	}
	tokenPresent := importURL != "" && strings.Contains(importURL, "@")
	return map[string]any{
		"url":                           importURL,
		"url_mutable":                   true,
		"token_present":                 tokenPresent,
		"custom_headers":                []any{},
		"allows_local_network":          false,
		"webhook_signing_token_present": false,
		"firable_event_trigger":         entBool(m["trigger_pipelines"]),
		"editor_below_credential_trust": hasEditorBelowTrust && tokenPresent,
		"mirror":                        mirror,
	}
}

// mirrorReachableVars is the project's own CI/CD variables plus the parent
// group's inherited variables — the set a mirror-triggered pipeline can read.
func mirrorReachableVars(prior engine.PriorPhase, fp string) []map[string]any {
	out := normalizeVariables(entLoadList(prior, engine.CollectGLProjectVariables(fp)), "project")
	if group := parentGroup(fp); group != "" {
		out = append(out, normalizeVariables(entLoadList(prior, engine.CollectGLGroupVariables(group)), "group")...)
	}
	return out
}

func mirrorUntrustedHost(importURL, fp string) bool {
	if importURL == "" {
		return false
	}
	group := strings.SplitN(fp, "/", 2)[0]
	return !strings.Contains(importURL, group)
}

func pagesRec(detail map[string]any) map[string]any {
	return map[string]any{
		"url":                           entStr(detail["web_url"]),
		"url_mutable":                   false,
		"token_present":                 false,
		"custom_headers":                []any{},
		"allows_local_network":          false,
		"webhook_signing_token_present": false,
		"firable_event_trigger":         false,
		"editor_below_credential_trust": false,
		"pages":                         map[string]any{"reads_secret": false},
	}
}

// ---- shared helpers over normalized shapes ----

func orEmptyObj(m map[string]any) map[string]any {
	if m == nil || entUnobserved(m) {
		return map[string]any{}
	}
	return m
}

func anyVar(vars []map[string]any, pred func(map[string]any) bool) bool {
	for _, v := range vars {
		if pred(v) {
			return true
		}
	}
	return false
}

func anyBranch(branches []map[string]any, pred func(map[string]any) bool) bool {
	for _, b := range branches {
		if pred(b) {
			return true
		}
	}
	return false
}

func anyTag(tags []map[string]any, pred func(map[string]any) bool) bool {
	for _, t := range tags {
		if pred(t) {
			return true
		}
	}
	return false
}

func anyRunner(runners []map[string]any, pred func(map[string]any) bool) bool {
	for _, r := range runners {
		if pred(r) {
			return true
		}
	}
	return false
}

func anyRule(rules []any, pred func(map[string]any) bool) bool {
	for _, raw := range rules {
		if pred(entMap(raw)) {
			return true
		}
	}
	return false
}

func anyStr(list []any, pred func(string) bool) bool {
	for _, v := range list {
		if pred(entStr(v)) {
			return true
		}
	}
	return false
}

func grantsDeveloper(levels []any) bool {
	return levelsInclude(levels, accessDeveloper)
}

func developerPushableUnprotectedRef(branches []map[string]any) bool {
	if len(branches) == 0 {
		return true
	}
	for _, b := range branches {
		if isWildcard(mStr(b, "pattern")) && grantsDeveloper(mList(b, "push_access_levels")) {
			return true
		}
	}
	return false
}

func isWildcard(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[")
}

// globMatch is a minimal wildcard match (only '*' wildcards, GitLab
// protected-branch semantics) sufficient for default-branch coverage checks.
func globMatch(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return false
	}
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(name[pos:], part)
		if idx < 0 {
			return false
		}
		if i == 0 && idx != 0 {
			return false
		}
		pos += idx + len(part)
	}
	if parts[len(parts)-1] != "" && !strings.HasSuffix(name, parts[len(parts)-1]) {
		return false
	}
	return true
}

// shadowedByPermissive: ≥2 rules match a common branch and the union of their
// access grants a lower-trust actor than the narrowest matching rule intended.
func shadowedByPermissive(branches []map[string]any, levelKey string) bool {
	for i := range branches {
		matches := []map[string]any{branches[i]}
		for j := range branches {
			if i != j && patternsOverlap(mStr(branches[i], "pattern"), mStr(branches[j], "pattern")) {
				matches = append(matches, branches[j])
			}
		}
		if len(matches) < 2 {
			continue
		}
		// The narrowest matching rule's intent vs the most-permissive (lowest
		// numeric) grant across all matching rules: a gap means a broader rule
		// shadows the tighter one.
		grants := make([]int64, 0, len(matches))
		for _, m := range matches {
			if lo := lowestGrant(mList(m, levelKey)); lo > 0 {
				grants = append(grants, lo)
			}
		}
		if len(grants) < 2 {
			continue
		}
		lo, hi := grants[0], grants[0]
		for _, g := range grants[1:] {
			lo = min(lo, g)
			hi = max(hi, g)
		}
		if lo < hi {
			return true
		}
	}
	return false
}

func shadowedTags(tags []map[string]any) bool {
	for i := range tags {
		for j := range tags {
			if i != j && patternsOverlap(mStr(tags[i], "pattern"), mStr(tags[j], "pattern")) {
				loI := lowestGrant(mList(tags[i], "create_access_levels"))
				loJ := lowestGrant(mList(tags[j], "create_access_levels"))
				if loI > 0 && loJ > 0 && loI != loJ {
					return true
				}
			}
		}
	}
	return false
}

func forcePushShadowed(branches []map[string]any) bool {
	for i := range branches {
		if mBool(branches[i], "allow_force_push") {
			continue
		}
		for j := range branches {
			if i != j && patternsOverlap(mStr(branches[i], "pattern"), mStr(branches[j], "pattern")) &&
				mBool(branches[j], "allow_force_push") &&
				levelsIncludeAtMost(mList(branches[j], "push_access_levels"), accessDeveloper) {
				return true
			}
		}
	}
	return false
}

func patternsOverlap(a, b string) bool {
	return a == b || globMatch(a, stripGlob(b)) || globMatch(b, stripGlob(a))
}

func stripGlob(p string) string { return strings.ReplaceAll(p, "*", "x") }

func lowestGrant(levels []any) int64 {
	lo := int64(0)
	for _, v := range levels {
		l := entInt64(v)
		if l > 0 && (lo == 0 || l < lo) {
			lo = l
		}
	}
	return lo
}

func protectedVarScopedToWritable(vars []map[string]any, branches []map[string]any) bool {
	writable := anyBranch(branches, func(b map[string]any) bool {
		return grantsDeveloper(mList(b, "push_access_levels")) || grantsDeveloper(mList(b, "merge_access_levels"))
	}) || len(branches) == 0
	return writable && anyVar(vars, func(v map[string]any) bool { return mBool(v, "protected") })
}

func deployCredKey(key string) bool {
	u := strings.ToUpper(key)
	return strings.HasPrefix(u, "AUTO_DEVOPS_") || strings.HasPrefix(u, "KUBE_") || strings.Contains(u, "KUBECONFIG")
}

func groupInheritedDeployVars(prior engine.PriorPhase, fp string) bool {
	group := parentGroup(fp)
	if group == "" {
		return false
	}
	for _, raw := range entLoadList(prior, engine.CollectGLGroupVariables(group)) {
		if deployCredKey(entStr(entMap(raw)["key"])) {
			return true
		}
	}
	return false
}

func authorCanSelfMerge(prior engine.PriorPhase, fp string) bool {
	approvals := entLoadData(prior, engine.CollectGLApprovals(fp))
	if approvals == nil || entUnobserved(approvals) {
		return true
	}
	req := entInt64(approvals["approvals_before_merge"])
	return req == 0 || entBool(approvals["merge_requests_author_approval"])
}

func policyFromMutableProject(prior engine.PriorPhase, fp string, branches []map[string]any) bool {
	pol := entLoadData(prior, engine.CollectGLSecurityPolicies(fp))
	nodes := entList(entGetIn(pol, "project", "scanExecutionPolicies", "nodes"))
	if len(nodes) == 0 {
		return false
	}
	return developerPushableUnprotectedRef(branches)
}

func inheritedDefaultBranchProtection(prior engine.PriorPhase, fp string, branches []map[string]any, defaultBranch string) (string, bool) {
	for _, b := range branches {
		if globMatch(mStr(b, "pattern"), defaultBranch) {
			return "project", grantsDeveloper(mList(b, "push_access_levels")) && !mBool(b, "allow_force_push")
		}
	}
	group := parentGroup(fp)
	if group != "" {
		g := entLoadData(prior, engine.CollectGLGroup(group))
		if d := entMap(g["default_branch_protection_defaults"]); d != nil {
			if levelsInclude(accessLevelValues(d["allowed_to_push"]), accessDeveloper) {
				return "group", true
			}
			return "group", false
		}
	}
	return "instance", false
}

func ciDebugTrace(vars []map[string]any, ciYAML []byte) bool {
	for _, v := range vars {
		if strings.EqualFold(mStr(v, "key"), "CI_DEBUG_TRACE") {
			return true
		}
	}
	if ciYAML != nil {
		return ciYAMLDebugTrace(ciYAML)
	}
	return false
}

func firstNonEmpty(vals ...string) any {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return nil
}

func sortedStrSet(list []any) []any {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range list {
		s := entStr(v)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	res := make([]any, len(out))
	for i, s := range out {
		res[i] = s
	}
	return res
}

func parentGroup(fp string) string {
	i := strings.LastIndex(fp, "/")
	if i < 0 {
		return ""
	}
	return fp[:i]
}

func duoFeatureEnabled(duo map[string]any, scope string) any {
	if duo == nil || entUnobserved(duo) {
		return nil
	}
	return duoBool(duo, scope, "duoFeaturesEnabled")
}
