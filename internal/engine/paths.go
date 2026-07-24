package engine

import (
	"fmt"
	"path"
	"strings"
)

const (
	dirCollect   = "00-collect"
	dirNormalize = "10-normalize"
	dirScan      = "20-scan"
)

func CollectOrg(org string) string { return path.Join(dirCollect, "org", org+".json") }

func CollectRepo(repo string) string { return path.Join(dirCollect, "repos", repo+".json") }

func CollectActionsSettings(repo string) string {
	return path.Join(dirCollect, "actions-settings", repo+".json")
}

func CollectRulesetsOrg(org string) string {
	return path.Join(dirCollect, "rulesets", org+".json")
}

func CollectRulesetsRepo(repo string) string {
	return path.Join(dirCollect, "rulesets", repo+".json")
}

func CollectEnvironment(repo, env string) string {
	return path.Join(dirCollect, "environments", repo, env+".json")
}

// scopeKey is one of "<org>", "<repo>", or "<repo>__<env>".
func CollectSecrets(scopeKey string) string {
	return path.Join(dirCollect, "secrets", scopeKey+".json")
}

// scopeKey is one of "<org>", "<repo>", or "<repo>__<env>".
func CollectVariables(scopeKey string) string {
	return path.Join(dirCollect, "variables", scopeKey+".json")
}

func CollectAppsInstallations(org string) string {
	return path.Join(dirCollect, "apps", org, "installations.json")
}

func CollectApp(org, slug string) string {
	return path.Join(dirCollect, "apps", org, slug+".json")
}

func CollectDeployKeys(repo string) string {
	return path.Join(dirCollect, "deploy-keys", repo+".json")
}

// scopeKey is the org name or a repo name.
func CollectRunners(scopeKey string) string {
	return path.Join(dirCollect, "runners", scopeKey+".json")
}

func CollectRunnerGroup(groupID int64) string {
	return path.Join(dirCollect, "runner-groups", fmt.Sprintf("%d.json", groupID))
}

func CollectMembers(org string) string {
	return path.Join(dirCollect, "members", org+".json")
}

func CollectWorkflowYAML(repo, filename string) string {
	return path.Join(dirCollect, "workflows", repo, filename)
}

func CollectWorkflowMeta(repo, filename string) string {
	return path.Join(dirCollect, "workflows", repo, filename+".meta.json")
}

// branchSlug strips a leading "refs/heads/" then maps "/" -> "__". Non-injective,
// matching safeRef: "release/1.0" -> "release__1.0".
func branchSlug(ref string) string {
	ref = strings.TrimPrefix(ref, "refs/heads/")
	return strings.ReplaceAll(ref, "/", "__")
}

// repoBranchDir keeps the bare "<repo>" segment for the default branch so legacy
// paths stay byte-stable; non-default branches get "<repo>@<branchSlug>".
func repoBranchDir(repo, ref string, isDefault bool) string {
	if isDefault {
		return repo
	}
	return repo + "@" + branchSlug(ref)
}

func CollectWorkflowYAMLBranch(repo, ref string, isDefault bool, filename string) string {
	return path.Join(dirCollect, "workflows", repoBranchDir(repo, ref, isDefault), filename)
}

func CollectWorkflowMetaBranch(repo, ref string, isDefault bool, filename string) string {
	return path.Join(dirCollect, "workflows", repoBranchDir(repo, ref, isDefault), filename+".meta.json")
}

func CollectActionYAML(owner, actionRepo, pathInRepo, ref string) string {
	return path.Join(dirCollect, "actions",
		fmt.Sprintf("%s__%s__%s@%s.yaml", owner, actionRepo, safePath(pathInRepo), safeRef(ref)))
}

func CollectActionMeta(owner, actionRepo, pathInRepo, ref string) string {
	return path.Join(dirCollect, "actions",
		fmt.Sprintf("%s__%s__%s@%s.meta.json", owner, actionRepo, safePath(pathInRepo), safeRef(ref)))
}

func CollectRefResolution(owner, actionRepo, ref string) string {
	return path.Join(dirCollect, "action-resolutions",
		fmt.Sprintf("%s__%s@%s.json", owner, actionRepo, safeRef(ref)))
}

// ---- GitLab collect paths ----
//
// glKey sanitizes a GitLab group/project full path (slash-separated) for use as a
// single path segment: anything outside [A-Za-z0-9.-] becomes '-'. '_' is folded
// too, since multi-component keys are joined with "__" (adoKey's rationale).
func glKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' {
			b.WriteByte(c)
		} else {
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

func glCollect(parts ...string) string {
	return path.Join(append([]string{dirCollect}, parts...)...)
}

// Group-scope surfaces (key = group full path).
func CollectGLGroup(g string) string        { return glCollect("group", glKey(g)+".json") }
func CollectGLSubgroups(g string) string    { return glCollect("subgroups", glKey(g)+".json") }
func CollectGLSharedGroups(g string) string { return glCollect("shared-groups", glKey(g)+".json") }
func CollectGLGroupMembers(g string) string {
	return glCollect("members", "group", glKey(g)+".json")
}
func CollectGLGroupVariables(g string) string {
	return glCollect("variables", "group", glKey(g)+".json")
}
func CollectGLGroupRunners(g string) string {
	return glCollect("runners", "group", glKey(g)+".json")
}
func CollectGLGroupProtectedEnvironments(g string) string {
	return glCollect("protected-environments", "group", glKey(g)+".json")
}
func CollectGLGroupCISettings(g string) string {
	return glCollect("group-ci-settings", glKey(g)+".json")
}
func CollectGLGroupDuo(g string) string {
	return glCollect("duo", "group", glKey(g)+".json")
}
func CollectGLGroupDeployTokens(g string) string {
	return glCollect("deploy-tokens", "group", glKey(g)+".json")
}
func CollectGLGroupAccessTokens(g string) string {
	return glCollect("access-tokens", "group", glKey(g)+".json")
}
func CollectGLGroupSAML(g string) string {
	return glCollect("saml", "group", glKey(g)+".json")
}
func CollectGLNamespace(g string) string {
	return glCollect("namespace", glKey(g)+".json")
}

// Project-scope surfaces (key = project full path).
func CollectGLProject(p string) string { return glCollect("project", glKey(p)+".json") }
func CollectGLProjectMembers(p string) string {
	return glCollect("members", "project", glKey(p)+".json")
}
func CollectGLProjectVariables(p string) string {
	return glCollect("variables", "project", glKey(p)+".json")
}
func CollectGLProtectedBranches(p string) string {
	return glCollect("protected-branches", glKey(p)+".json")
}
func CollectGLProtectedTags(p string) string {
	return glCollect("protected-tags", glKey(p)+".json")
}
func CollectGLProjectRunners(p string) string {
	return glCollect("runners", "project", glKey(p)+".json")
}
func CollectGLRunnerProjects(id int64) string {
	return glCollect("runner-projects", fmt.Sprintf("%d.json", id))
}
func CollectGLEnvironments(p string) string { return glCollect("environments", glKey(p)+".json") }
func CollectGLProjectProtectedEnvironments(p string) string {
	return glCollect("protected-environments", "project", glKey(p)+".json")
}
func CollectGLDeployments(p string) string   { return glCollect("deployments", glKey(p)+".json") }
func CollectGLApprovals(p string) string     { return glCollect("approvals", glKey(p)+".json") }
func CollectGLApprovalRules(p string) string { return glCollect("approval-rules", glKey(p)+".json") }
func CollectGLPushRules(p string) string     { return glCollect("push-rules", glKey(p)+".json") }
func CollectGLIntegrations(p string) string  { return glCollect("integrations", glKey(p)+".json") }
func CollectGLWebhooks(p string) string      { return glCollect("webhooks", glKey(p)+".json") }
func CollectGLMirrors(p string) string       { return glCollect("mirrors", glKey(p)+".json") }
func CollectGLProjectDeployTokens(p string) string {
	return glCollect("deploy-tokens", "project", glKey(p)+".json")
}
func CollectGLDeployKeys(p string) string { return glCollect("deploy-keys", glKey(p)+".json") }
func CollectGLProjectAccessTokens(p string) string {
	return glCollect("access-tokens", "project", glKey(p)+".json")
}
func CollectGLPipelineSchedules(p string) string {
	return glCollect("pipeline-schedules", glKey(p)+".json")
}
func CollectGLCISettings(p string) string { return glCollect("ci-settings", glKey(p)+".json") }
func CollectGLRegistryTagRules(p string) string {
	return glCollect("registry-tag-rules", glKey(p)+".json")
}
func CollectGLPackageProtectionRules(p string) string {
	return glCollect("package-protection-rules", glKey(p)+".json")
}
func CollectGLExternalStatusChecks(p string) string {
	return glCollect("external-status-checks", glKey(p)+".json")
}
func CollectGLSecureFiles(p string) string {
	return glCollect("secure-files", glKey(p)+".json")
}
func CollectGLTerraformState(p string) string {
	return glCollect("terraform-state", glKey(p)+".json")
}
func CollectGLSecurityPolicies(p string) string {
	return glCollect("security-policies", glKey(p)+".json")
}
func CollectGLClusterAgents(p string) string { return glCollect("cluster-agents", glKey(p)+".json") }
func CollectGLAgentConfig(p, name string) string {
	return glCollect("agent-configs", glKey(p), glKey(name)+".json")
}
func CollectGLCIConfig(p, rel string) string { return glCollect("ci-config", glKey(p), rel) }
func CollectGLRepoFile(p, rel string) string { return glCollect("repo-files", glKey(p), rel) }

// Instance-scope surfaces (self-hosted / admin token).
func CollectGLInstanceVariables() string { return glCollect("variables", "instance.json") }
func CollectGLInstanceRunners() string   { return glCollect("runners", "instance.json") }
func CollectGLInstanceSettings() string  { return glCollect("instance-settings.json") }
func CollectGLInstanceDuo() string       { return glCollect("duo", "instance.json") }
func CollectGLServiceAccounts() string   { return glCollect("service-accounts", "instance.json") }
func CollectGLUserMemberships(id int64) string {
	return glCollect("user-memberships", fmt.Sprintf("%d.json", id))
}

func NormalizeJob(repo, workflow, jobID string) string {
	return path.Join(dirNormalize, "jobs",
		fmt.Sprintf("%s__%s__%s.json", repo, wfStem(workflow), jobID))
}

func NormalizeJobBranch(repo, ref string, isDefault bool, workflow, jobID string) string {
	return path.Join(dirNormalize, "jobs",
		fmt.Sprintf("%s__%s__%s.json", repoBranchDir(repo, ref, isDefault), wfStem(workflow), jobID))
}

func Finding(ruleID, subjectHash string) string {
	return path.Join(dirScan, "findings", ruleID+"__"+subjectHash+".json")
}

func ScanSummary() string { return path.Join(dirScan, "_summary.json") }

func RunMeta() string { return "_meta.json" }

// safePath reproduces Python's path.replace("/","__").lstrip("__"): lstrip uses
// char-set semantics, so it strips ANY leading '_', not just the "__" pair.
func safePath(p string) string {
	s := strings.ReplaceAll(p, "/", "__")
	s = strings.TrimLeft(s, "_")
	if s == "" {
		return "_root"
	}
	return s
}

func safeRef(ref string) string { return strings.ReplaceAll(ref, "/", "__") }

// wfStem strips ".yml" then ".yaml", each at most once and in that order, to
// match Python's chained removesuffix.
func wfStem(wf string) string {
	wf = strings.TrimSuffix(wf, ".yml")
	wf = strings.TrimSuffix(wf, ".yaml")
	return wf
}
