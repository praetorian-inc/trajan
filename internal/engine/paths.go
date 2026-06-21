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
