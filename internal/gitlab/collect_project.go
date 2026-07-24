package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func collectOneProject(ctx context.Context, cl GitLab, cp engine.CurrentPhase, pt projectRef, timer *engine.PhaseTimer) error {
	fp, pid := pt.FullPath, pt.ID
	idRef := fmt.Sprintf("%d", pid)
	base := "/projects/" + idRef
	lbl := func(s string) string { return fp + "/" + s }

	var projRaw json.RawMessage
	softSurface(timer, lbl("detail"), func() error {
		raw, status, err := softGet(ctx, cl, base, nil)
		if err != nil {
			return err
		}
		projRaw = raw
		// MR settings, mirror fields, id-token sub-claim, pages access level are all
		// carried on the project detail — no extra file (spec §5 "folded").
		return writeOrMark(cp, engine.CollectGLProject(fp), "project", base, raw, status)
	})

	listSurface := func(label, apiPath, rel, collector string, params url.Values) {
		softSurface(timer, lbl(label), func() error {
			items, status, err := softList(ctx, cl, apiPath, params)
			if err != nil {
				return err
			}
			return writeListOrMark(cp, rel, collector, apiPath, items, status)
		})
	}
	getSurface := func(label, apiPath, rel, collector string, params url.Values) {
		softSurface(timer, lbl(label), func() error {
			raw, status, err := softGet(ctx, cl, apiPath, params)
			if err != nil {
				return err
			}
			return writeOrMark(cp, rel, collector, apiPath, raw, status)
		})
	}

	listSurface("members", base+"/members/all", engine.CollectGLProjectMembers(fp), "project-members", nil)
	softSurface(timer, lbl("variables"), func() error { return collectProjectVariables(ctx, cl, cp, fp, base) })
	listSurface("protected-branches", base+"/protected_branches", engine.CollectGLProtectedBranches(fp), "protected-branches", nil)
	listSurface("protected-tags", base+"/protected_tags", engine.CollectGLProtectedTags(fp), "protected-tags", nil)
	listSurface("environments", base+"/environments", engine.CollectGLEnvironments(fp), "environments", nil)
	listSurface("protected-environments", base+"/protected_environments", engine.CollectGLProjectProtectedEnvironments(fp), "project-protected-environments", nil)
	listSurface("deployments", base+"/deployments", engine.CollectGLDeployments(fp), "deployments", url.Values{"order_by": {"id"}, "sort": {"desc"}})
	getSurface("approvals", base+"/approvals", engine.CollectGLApprovals(fp), "approvals", nil)
	listSurface("approval-rules", base+"/approval_rules", engine.CollectGLApprovalRules(fp), "approval-rules", nil)
	listSurface("external-status-checks", base+"/external_status_checks", engine.CollectGLExternalStatusChecks(fp), "external-status-checks", nil)
	getSurface("push-rules", base+"/push_rule", engine.CollectGLPushRules(fp), "push-rules", nil)
	listSurface("integrations", base+"/integrations", engine.CollectGLIntegrations(fp), "integrations", nil)
	listSurface("webhooks", base+"/hooks", engine.CollectGLWebhooks(fp), "webhooks", nil)
	listSurface("mirrors", base+"/remote_mirrors", engine.CollectGLMirrors(fp), "mirrors", nil)
	listSurface("deploy-tokens", base+"/deploy_tokens", engine.CollectGLProjectDeployTokens(fp), "project-deploy-tokens", nil)
	listSurface("deploy-keys", base+"/deploy_keys", engine.CollectGLDeployKeys(fp), "deploy-keys", nil)
	listSurface("access-tokens", base+"/access_tokens", engine.CollectGLProjectAccessTokens(fp), "project-access-tokens", nil)
	listSurface("pipeline-schedules", base+"/pipeline_schedules", engine.CollectGLPipelineSchedules(fp), "pipeline-schedules", nil)
	listSurface("registry-tag-rules", base+"/registry/protection/tag/rules", engine.CollectGLRegistryTagRules(fp), "registry-tag-rules", nil)
	listSurface("package-protection-rules", base+"/packages/protection/rules", engine.CollectGLPackageProtectionRules(fp), "package-protection-rules", nil)
	listSurface("secure-files", base+"/secure_files", engine.CollectGLSecureFiles(fp), "secure-files", nil)
	listSurface("terraform-state", base+"/terraform/state", engine.CollectGLTerraformState(fp), "terraform-state", nil)

	softSurface(timer, lbl("runners"), func() error { return collectProjectRunners(ctx, cl, cp, fp, base, timer) })
	softSurface(timer, lbl("ci-settings"), func() error { return collectProjectCISettings(ctx, cl, cp, fp, base) })
	softSurface(timer, lbl("security-policies"), func() error { return collectSecurityPolicies(ctx, cl, cp, fp) })
	softSurface(timer, lbl("cluster-agents"), func() error { return collectClusterAgents(ctx, cl, cp, fp, base, projRaw) })
	softSurface(timer, lbl("ci-config"), func() error { return collectCIConfig(ctx, cl, cp, fp, base, projRaw) })
	softSurface(timer, lbl("codeowners"), func() error { return collectCodeowners(ctx, cl, cp, fp, base, projRaw) })
	softSurface(timer, lbl("duo-files"), func() error { return collectDuoFiles(ctx, cl, cp, fp, base, projRaw) })

	return nil
}

// collectProjectVariables strips value before write — variable values are never
// collected (spec §5 / fields doc).
func collectProjectVariables(ctx context.Context, cl GitLab, cp engine.CurrentPhase, fp, base string) error {
	apiPath := base + "/variables"
	items, status, err := softList(ctx, cl, apiPath, nil)
	if err != nil {
		return err
	}
	rel := engine.CollectGLProjectVariables(fp)
	if status != 0 {
		return writeListOrMark(cp, rel, "project-variables", apiPath, nil, status)
	}
	stripped := make([]json.RawMessage, 0, len(items))
	for _, raw := range items {
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) == nil {
			delete(m, "value")
			if b, err := json.Marshal(m); err == nil {
				stripped = append(stripped, b)
				continue
			}
		}
		stripped = append(stripped, raw)
	}
	return writeListOrMark(cp, rel, "project-variables", apiPath, stripped, 0)
}

// collectProjectRunners lists project runners, enriches each with per-runner detail
// (run_untagged, access_level, locked, tag_list — the runner-subject rule fields),
// and captures its co-residency project set. A flaky per-runner call marks that
// runner and continues.
func collectProjectRunners(ctx context.Context, cl GitLab, cp engine.CurrentPhase, fp, base string, timer *engine.PhaseTimer) error {
	apiPath := base + "/runners"
	items, status, err := softList(ctx, cl, apiPath, nil)
	if err != nil {
		return err
	}
	items = enrichRunners(ctx, cl, items, timer, fp)
	if err := writeListOrMark(cp, engine.CollectGLProjectRunners(fp), "project-runners", apiPath, items, status); err != nil {
		return err
	}
	if status != 0 {
		return nil
	}
	for _, r := range items {
		id := numField(r, "id")
		if id == 0 {
			continue
		}
		rp := fmt.Sprintf("/runners/%d/projects", id)
		projs, pstatus, perr := softList(ctx, cl, rp, nil)
		if perr != nil {
			appendErr(timer, fmt.Sprintf("%s/runner/%d/projects: %v", fp, id, perr))
			continue
		}
		if err := writeListOrMark(cp, engine.CollectGLRunnerProjects(id), "runner-projects", rp, projs, pstatus); err != nil {
			return err
		}
	}
	return nil
}

// enrichRunners fetches GET /runners/:id per listed runner and merges the detail
// over the list record, so the ref_protected (access_level), run_untagged, locked,
// and tag_list fields the runner-subject rules key on are present. The list record
// alone omits them. A soft per-runner failure keeps the bare list entry; a transport
// error is recorded and the bare entry kept. Bounded by the same concurrency as the
// fan-out via a small fixed cap since the runner set per scope is tiny.
func enrichRunners(ctx context.Context, cl GitLab, items []json.RawMessage, timer *engine.PhaseTimer, scope string) []json.RawMessage {
	if len(items) == 0 {
		return items
	}
	out := make([]json.RawMessage, len(items))
	engine.RunPartial(ctx, runnerDetailConcurrency, indexed(items),
		func(ctx context.Context, it idxRaw) (struct{}, error) {
			out[it.i] = it.raw
			id := numField(it.raw, "id")
			if id == 0 {
				return struct{}{}, nil
			}
			detail, dstatus, derr := softGet(ctx, cl, fmt.Sprintf("/runners/%d", id), nil)
			if derr != nil {
				appendErr(timer, fmt.Sprintf("%s/runner/%d/detail: %v", scope, id, derr))
				return struct{}{}, nil
			}
			if dstatus == 0 && detail != nil {
				if merged := mergeRaw(it.raw, detail); merged != nil {
					out[it.i] = merged
				}
			}
			return struct{}{}, nil
		}, nil)
	return out
}

const runnerDetailConcurrency = 8

type idxRaw struct {
	i   int
	raw json.RawMessage
}

func indexed(items []json.RawMessage) []idxRaw {
	out := make([]idxRaw, len(items))
	for i, r := range items {
		out[i] = idxRaw{i: i, raw: r}
	}
	return out
}

// mergeRaw overlays detail's keys onto base (detail wins). Returns nil if either
// side is not a JSON object so the caller can keep the original list record.
func mergeRaw(base, detail json.RawMessage) json.RawMessage {
	var b, d map[string]json.RawMessage
	if json.Unmarshal(base, &b) != nil || json.Unmarshal(detail, &d) != nil {
		return nil
	}
	maps.Copy(b, d)
	out, err := json.Marshal(b)
	if err != nil {
		return nil
	}
	return out
}

const projectCICdQuery = `query($fullPath: ID!) {
  project(fullPath: $fullPath) {
    ciCdSettings { jobTokenScopeEnabled pushRepositoryForJobTokenAllowed inboundJobTokenScopeEnabled crossProjectPushForJobTokenAllowed }
  }
}`

// collectProjectCISettings folds the GraphQL ciCdSettings job-token toggles
// (including crossProjectPushForJobTokenAllowed) together with the REST
// job_token_scope booleans and the inbound allowlist entries — both the
// project-scoped (/allowlist) and group-scoped (/groups_allowlist) lists — into
// one file. The entries feed job_token_allowlist{mode,entries,fine_grained} and
// the target.job_token_allowlist chain participant, which the inbound/outbound
// booleans alone cannot express.
func collectProjectCISettings(ctx context.Context, cl GitLab, cp engine.CurrentPhase, fp, base string) error {
	data, gstatus, err := graphQLSoft(ctx, cl, projectCICdQuery, map[string]any{"fullPath": fp})
	if err != nil {
		return err
	}
	scope, sstatus, err := softGet(ctx, cl, base+"/job_token_scope", nil)
	if err != nil {
		return err
	}
	allowlist, astatus, err := softList(ctx, cl, base+"/job_token_scope/allowlist", nil)
	if err != nil {
		return err
	}
	groupsAllowlist, gastatus, err := softList(ctx, cl, base+"/job_token_scope/groups_allowlist", nil)
	if err != nil {
		return err
	}
	bundle := map[string]any{
		"ci_cd_settings":             gqlPart(data, gstatus),
		"job_token_scope":            rawPart(scope, sstatus),
		"job_token_allowlist":        listOrMark(allowlist, astatus),
		"job_token_groups_allowlist": listOrMark(groupsAllowlist, gastatus),
	}
	return envelopeSrc(cp, engine.CollectGLCISettings(fp), "ci-settings", sourceGQL,
		"graphql:project.ciCdSettings+/job_token_scope{,/allowlist,/groups_allowlist}", bundle)
}

const clusterAgentsQuery = `query($fullPath: ID!) {
  project(fullPath: $fullPath) {
    clusterAgents {
      nodes {
        id name
        ciAccessAuthorizedProjects { nodes { id fullPath } }
        ciAccessAuthorizedGroups { nodes { id fullPath } }
      }
    }
  }
}`

// collectClusterAgents writes the GraphQL agent grant graph, then fetches each
// agent's .gitlab/agents/<name>/config.yaml (config_path, protected_branches_only,
// ci_access.environments filter, access_as impersonation, default_permissions —
// none of which the clusterAgents query exposes). Config fetch is soft per agent.
func collectClusterAgents(ctx context.Context, cl GitLab, cp engine.CurrentPhase, fp, base string, projRaw json.RawMessage) error {
	data, status, err := graphQLSoft(ctx, cl, clusterAgentsQuery, map[string]any{"fullPath": fp})
	if err != nil {
		return err
	}
	rel := engine.CollectGLClusterAgents(fp)
	if status != 0 {
		return envelopeSrc(cp, rel, "cluster-agents", sourceGQL, "graphql:project.clusterAgents", map[string]any{"_unobserved": status})
	}
	if err := envelopeSrc(cp, rel, "cluster-agents", sourceGQL, "graphql:project.clusterAgents", data); err != nil {
		return err
	}
	for _, name := range agentNames(data) {
		if err := collectAgentConfig(ctx, cl, cp, fp, base, name, projRaw); err != nil {
			return err
		}
	}
	return nil
}

func agentNames(data json.RawMessage) []string {
	nodes := objField(objField(objField(data, "project"), "clusterAgents"), "nodes")
	var arr []json.RawMessage
	if json.Unmarshal(nodes, &arr) != nil {
		return nil
	}
	names := make([]string, 0, len(arr))
	for _, n := range arr {
		if name := strField(n, "name"); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// collectAgentConfig fetches the raw config.yaml at the config path. The agent's
// config lives at .gitlab/agents/<name>/config.yaml on the default branch. Absent
// config (a bare registration) soft-404s and is skipped.
func collectAgentConfig(ctx context.Context, cl GitLab, cp engine.CurrentPhase, fp, base, name string, projRaw json.RawMessage) error {
	ref := defaultBranch(projRaw)
	cfgPath := ".gitlab/agents/" + name + "/config.yaml"
	p := base + "/repository/files/" + url.PathEscape(cfgPath) + "/raw"
	b, _, err := cl.GetRaw(ctx, p, url.Values{"ref": {ref}})
	if err != nil {
		if isSoft(err) {
			return nil
		}
		return err
	}
	if len(b) == 0 {
		return nil
	}
	return cp.WriteRaw(engine.CollectGLAgentConfig(fp, name), b)
}

// collectCIConfig fetches the raw .gitlab-ci.yml at the default branch. Full
// include-tree resolution (local/project/template/component) is P3's job; the raw
// entrypoint is captured here.
func collectCIConfig(ctx context.Context, cl GitLab, cp engine.CurrentPhase, fp, base string, projRaw json.RawMessage) error {
	ref := defaultBranch(projRaw)
	p := base + "/repository/files/" + url.PathEscape(".gitlab-ci.yml") + "/raw"
	b, _, err := cl.GetRaw(ctx, p, url.Values{"ref": {ref}})
	if err != nil {
		if isSoft(err) {
			return nil
		}
		return err
	}
	if len(b) == 0 {
		return nil
	}
	return cp.WriteRaw(engine.CollectGLCIConfig(fp, ".gitlab-ci.yml"), b)
}

func gqlPart(data json.RawMessage, status int) any {
	if status != 0 {
		return map[string]any{"_unobserved": status}
	}
	return data
}

func rawPart(raw json.RawMessage, status int) any {
	if status != 0 {
		return map[string]any{"_unobserved": status}
	}
	return raw
}
