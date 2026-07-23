package engine

import (
	"crypto/sha256"
	"encoding/hex"
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

// ---- Azure DevOps collect paths ----
//
// adoKey sanitizes an ADO project/repo/host name for use as a path segment:
// anything outside [A-Za-z0-9._-] becomes '-'. ADO names are already restricted,
// so this only guards the rare space/slash.
func adoKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		// '_' is deliberately NOT preserved: the NormalizeADO*/CollectADO* helpers
		// join sanitized components with "__", so a component containing "_" would
		// make that delimiter ambiguous (X + Y__Z vs X__Y + Z collide).
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

func adoCollect(parts ...string) string {
	return path.Join(append([]string{dirCollect}, parts...)...)
}

// Org-scope surfaces (key = org).
func CollectADOConnectionData(org string) string {
	return adoCollect("connection-data", adoKey(org)+".json")
}
func CollectADOProjects(org string) string { return adoCollect("projects", adoKey(org)+".json") }
func CollectADOSecurityNS(org string) string {
	return adoCollect("security-namespaces", adoKey(org)+".json")
}
func CollectADOGraph(org string) string      { return adoCollect("graph", adoKey(org)+".json") }
func CollectADOExtensions(org string) string { return adoCollect("extensions", adoKey(org)+".json") }
func CollectADOServiceHooks(org string) string {
	return adoCollect("service-hooks", adoKey(org)+".json")
}
func CollectADOFeeds(org string) string { return adoCollect("feeds", adoKey(org)+".json") }

// Org agent pools (key = poolID).
func CollectADOPool(poolID int64) string {
	return adoCollect("pools", fmt.Sprintf("%d.json", poolID))
}
func CollectADOPoolAgents(poolID int64) string {
	return adoCollect("pool-agents", fmt.Sprintf("%d.json", poolID))
}
func CollectADOElasticPool(poolID int64) string {
	return adoCollect("elastic-pools", fmt.Sprintf("%d.json", poolID))
}
func CollectADOEndpointACL(project, connID string) string {
	return adoCollect("acl-endpoint", adoKey(project), adoKey(connID)+".json")
}

// Project-scope surfaces (key = project).
func CollectADOProject(project string) string { return adoCollect("project", adoKey(project)+".json") }
func CollectADOGeneralSettings(project string) string {
	return adoCollect("general-settings", adoKey(project)+".json")
}
func CollectADOProjectProps(project string) string {
	return adoCollect("project-properties", adoKey(project)+".json")
}
func CollectADORepos(project string) string { return adoCollect("repos", adoKey(project)+".json") }
func CollectADOPolicies(project string) string {
	return adoCollect("policies", adoKey(project)+".json")
}
func CollectADOPolicyTypes(project string) string {
	return adoCollect("policy-types", adoKey(project)+".json")
}
func CollectADOServiceConnections(project string) string {
	return adoCollect("service-connections", adoKey(project)+".json")
}
func CollectADOVariableGroups(project string) string {
	return adoCollect("variable-groups", adoKey(project)+".json")
}
func CollectADOSecureFiles(project string) string {
	return adoCollect("secure-files", adoKey(project)+".json")
}
func CollectADOEnvironments(project string) string {
	return adoCollect("environments", adoKey(project)+".json")
}
func CollectADODeploymentGroups(project string) string {
	return adoCollect("deployment-groups", adoKey(project)+".json")
}
func CollectADOTaskGroups(project string) string {
	return adoCollect("task-groups", adoKey(project)+".json")
}
func CollectADOAgentQueues(project string) string {
	return adoCollect("agent-queues", adoKey(project)+".json")
}
func CollectADOBuildDefs(project string) string {
	return adoCollect("build-definitions", adoKey(project)+".json")
}
func CollectADOPipelines(project string) string {
	return adoCollect("pipelines", adoKey(project)+".json")
}
func CollectADOReleases(project string) string {
	return adoCollect("releases", adoKey(project)+".json")
}
func CollectADOReleaseFull(project string, id int64) string {
	return adoCollect("release-definition", adoKey(project), fmt.Sprintf("%d.json", id))
}
func CollectADOBuildACL(project string) string {
	return adoCollect("acl-build", adoKey(project)+".json")
}

// Per-pipeline / per-resource / per-repo (nested under project).
func CollectADOBuildDefFull(project string, id int64) string {
	return adoCollect("build-definition", adoKey(project), fmt.Sprintf("%d.json", id))
}
func CollectADOPipelinePreview(project string, id int64) string {
	return adoCollect("pipeline-preview", adoKey(project), fmt.Sprintf("%d.json", id))
}
func CollectADOPipelineYAML(project string, id int64, name string) string {
	return adoCollect("pipeline-yaml", adoKey(project), fmt.Sprintf("%d__%s.json", id, adoKey(name)))
}
func CollectADOEnvironmentDetail(project string, envID int64) string {
	return adoCollect("environment-detail", adoKey(project), fmt.Sprintf("%d.json", envID))
}
func CollectADOPipelinePerms(project, rtype, rid string) string {
	return adoCollect("pipeline-permissions", adoKey(project), adoKey(rtype)+"__"+adoKey(rid)+".json")
}
func CollectADOChecks(project, rtype, rid string) string {
	return adoCollect("checks", adoKey(project), adoKey(rtype)+"__"+adoKey(rid)+".json")
}
func CollectADORepoACL(project, repo string) string {
	return adoCollect("acl-repo", adoKey(project), adoKey(repo)+".json")
}

// ---- Azure DevOps normalize paths ----
func adoNorm(parts ...string) string {
	return path.Join(append([]string{dirNormalize}, parts...)...)
}

func NormalizeADOOrg(org string) string { return adoNorm("org", adoKey(org)+".json") }
func NormalizeADOProject(project string) string {
	return adoNorm("projects", adoKey(project)+".json")
}
func NormalizeADORepo(project, repo string) string {
	return adoNorm("repos", adoKey(project)+"__"+adoKey(repo)+".json")
}
func NormalizeADOPipeline(project string, id int64) string {
	return adoNorm("pipelines", fmt.Sprintf("%s__%d.json", adoKey(project), id))
}
func NormalizeADOJob(project string, pipelineID int64, stage, job string) string {
	return adoNorm("jobs", fmt.Sprintf("%s__%d__%s__%s.json", adoKey(project), pipelineID, adoKey(stage), adoKey(job)))
}
func NormalizeADOServiceConnection(project, connID string) string {
	return adoNorm("service-connections", adoKey(project)+"__"+adoKey(connID)+".json")
}
func NormalizeADOVariableGroup(project string, id int64) string {
	return adoNorm("variable-groups", fmt.Sprintf("%s__%d.json", adoKey(project), id))
}
func NormalizeADOEnvironment(project, name string) string {
	return adoNorm("environments", adoKey(project)+"__"+adoKey(name)+".json")
}
func NormalizeADOBranch(project, repo, branch string) string {
	return adoNorm("branches", adoKey(project)+"__"+adoKey(repo)+"__"+adoKey(branch)+".json")
}
func NormalizeADOStage(project string, pipelineID int64, stage string) string {
	return adoNorm("stages", fmt.Sprintf("%s__%d__%s.json", adoKey(project), pipelineID, adoKey(stage)))
}
func NormalizeADOKeyVault(project, vault string) string {
	return adoNorm("key-vaults", adoKey(project)+"__"+adoKey(vault)+".json")
}
func NormalizeADOExtension(id string) string {
	return adoNorm("extensions", adoKey(id)+".json")
}
func NormalizeADOSecureFile(project, id string) string {
	return adoNorm("secure-files", adoKey(project)+"__"+adoKey(id)+".json")
}
func NormalizeADOServiceHook(id string) string {
	return adoNorm("service-hooks", adoKey(id)+".json")
}
func NormalizeADOAgentPool(id int64) string {
	return adoNorm("agent-pools", fmt.Sprintf("%d.json", id))
}
func NormalizeADOFeed(scope, id string) string {
	return adoNorm("feeds", adoKey(scope)+"__"+adoKey(id)+".json")
}
func NormalizeADOPolicy(project, repo, policyType string) string {
	return adoNorm("policies", adoKey(project)+"__"+adoKey(repo)+"__"+adoKey(policyType)+".json")
}
func NormalizeADOPrincipal(kind, descriptor string) string {
	return adoNorm("principals", adoKey(kind), adoKey(descriptor)+".json")
}
// NormalizeADOEdges hashes the composite key into a fixed-length, collision-free
// stem. Callers build keys by joining components with "__", but adoKey folds "_"
// to "-", which would both flatten that delimiter and overflow the 255-byte path
// limit for long branch/connection/input names. The readable components stay as
// fields on the edge record; the filename only has to be unique.
func NormalizeADOEdges(kind, key string) string {
	sum := sha256.Sum256([]byte(key))
	return adoNorm("edges", adoKey(kind), hex.EncodeToString(sum[:16])+".json")
}
func NormalizeADOSecretVariable(groupID int64, name string) string {
	return adoNorm("secret-variables", fmt.Sprintf("%d__%s.json", groupID, adoKey(name)))
}
func NormalizeADOWIFCredential(connID, subject string) string {
	return adoNorm("wif-credentials", adoKey(connID)+"__"+adoKey(subject)+".json")
}
func NormalizeADOProjectAgentPool(project string, poolID int64) string {
	return adoNorm("project-agent-pools", fmt.Sprintf("%s__%d.json", adoKey(project), poolID))
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
