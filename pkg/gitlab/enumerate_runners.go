package gitlab

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/analysis/parser"
)

// EnumerateRunners discovers GitLab runners for a project and optionally its group/instance.
// projectPath: "owner/repo" format
// includeGroup: fetch group runners (requires project to belong to a group)
// includeInstance: fetch instance-wide runners (requires admin access)
func (p *Platform) EnumerateRunners(ctx context.Context, projectPath string, includeGroup, includeInstance bool) (*RunnersEnumerateResult, error) {
	result := &RunnersEnumerateResult{
		ProjectRunners:  make([]RunnerInfo, 0),
		GroupRunners:    make([]RunnerInfo, 0),
		InstanceRunners: make([]RunnerInfo, 0),
	}

	// Get project to find ID and group
	project, err := p.client.GetProject(ctx, projectPath)
	if err != nil {
		result.Errors = append(result.Errors, "getting project: "+err.Error())
		return result, nil
	}

	// Check if this is GitLab SaaS (gitlab.com)
	// Skip shared SaaS runners to avoid noise
	isSaaS := strings.Contains(strings.ToLower(p.client.baseURL), "gitlab.com")

	// 1. Get project runners
	projectRunners, err := p.client.ListProjectRunners(ctx, project.ID)
	if err != nil {
		result.Errors = append(result.Errors, "listing project runners: "+err.Error())
	} else {
		// On GitLab SaaS, filter out shared runners (saas-linux-*, saas-macos-*, etc.)
		// Only show truly self-hosted/custom project runners
		if isSaaS {
			originalCount := len(projectRunners)
			projectRunners = filterSelfHostedRunners(projectRunners)
			// Only add informational note if we actually filtered out runners
			// and ended up with zero self-hosted runners
			if originalCount > 0 && len(projectRunners) == 0 {
				// Don't add to Errors - this is expected behavior on SaaS
				// The message will be clear from "0 runners" in the output
			}
		}
		result.ProjectRunners = projectRunners
	}

	// 2. Get group runners if requested and project has a namespace
	if includeGroup && project.Namespace.FullPath != "" {
		// Get the group to find its ID
		group, err := p.client.GetGroup(ctx, project.Namespace.FullPath)
		if err != nil {
			result.Errors = append(result.Errors, "getting group: "+err.Error())
		} else {
			groupRunners, err := p.client.ListGroupRunners(ctx, group.ID)
			if err != nil {
				result.Errors = append(result.Errors, "listing group runners: "+err.Error())
			} else {
				// On GitLab SaaS, filter out shared runners
				if isSaaS {
					groupRunners = filterSelfHostedRunners(groupRunners)
				}
				result.GroupRunners = groupRunners
			}
		}
	}

	// 3. Get instance runners if requested (admin only)
	if includeInstance {
		instanceRunners, err := p.client.ListInstanceRunners(ctx)
		if err != nil {
			if IsPermissionError(err) {
				result.Errors = append(result.Errors, "listing instance runners: admin access required (403)")
			} else {
				result.Errors = append(result.Errors, "listing instance runners: "+err.Error())
			}
		} else {
			// On GitLab SaaS, filter out shared runners
			if isSaaS {
				instanceRunners = filterSelfHostedRunners(instanceRunners)
			}
			result.InstanceRunners = instanceRunners
		}
	}

	// Build summary
	result.Summary = buildRunnerSummary(result.ProjectRunners, result.GroupRunners, result.InstanceRunners)

	return result, nil
}

// AnalyzeWorkflowTags analyzes .gitlab-ci.yml content to extract required runner tags
// and compares them against available runners to identify gaps.
func (p *Platform) AnalyzeWorkflowTags(ctx context.Context, yamlContent []byte, availableRunners []RunnerInfo) (*WorkflowTagAnalysis, error) {
	analysis := &WorkflowTagAnalysis{
		RequiredTags:  make([]string, 0),
		AvailableTags: make([]string, 0),
		MissingTags:   make([]string, 0),
	}

	// Extract required tags from workflow
	requiredTags, err := extractWorkflowTags(yamlContent)
	if err != nil {
		return nil, fmt.Errorf("extracting workflow tags: %w", err)
	}
	analysis.RequiredTags = requiredTags

	// Build set of available tags from runners
	availableTagsSet := make(map[string]bool)
	for _, runner := range availableRunners {
		for _, tag := range runner.Tags {
			availableTagsSet[tag] = true
		}
	}

	// Convert to slice
	for tag := range availableTagsSet {
		analysis.AvailableTags = append(analysis.AvailableTags, tag)
	}

	// Find missing tags (required but not available)
	for _, tag := range requiredTags {
		if !availableTagsSet[tag] {
			analysis.MissingTags = append(analysis.MissingTags, tag)
		}
	}

	analysis.ProjectsAnalyzed = 1

	return analysis, nil
}

// extractWorkflowTags parses GitLab CI YAML and extracts all unique runner tags from jobs.
func extractWorkflowTags(yamlContent []byte) ([]string, error) {
	// Parse GitLab CI file
	gitlabParser := parser.NewGitLabParser()
	workflow, err := gitlabParser.Parse(yamlContent)
	if err != nil {
		return nil, fmt.Errorf("parsing GitLab CI: %w", err)
	}

	// Extract tags from raw GitLab CI structure
	glCI, ok := workflow.Raw.(*parser.GitLabCI)
	if !ok {
		return nil, fmt.Errorf("unexpected workflow type")
	}

	// Collect all unique tags from jobs
	tagsSet := make(map[string]bool)
	for _, job := range glCI.Jobs {
		for _, tag := range job.Tags {
			tagsSet[tag] = true
		}
	}

	// Convert to slice
	tags := make([]string, 0, len(tagsSet))
	for tag := range tagsSet {
		tags = append(tags, tag)
	}

	return tags, nil
}

// buildRunnerSummary generates summary statistics from runner lists.
func buildRunnerSummary(project, group, instance []RunnerInfo) RunnerSummary {
	summary := RunnerSummary{
		Project:  len(project),
		Group:    len(group),
		Instance: len(instance),
	}

	// Count online/offline across all runner types
	// Allocate fresh slice to avoid mutating caller's data
	allRunners := make([]RunnerInfo, 0, len(project)+len(group)+len(instance))
	allRunners = append(allRunners, project...)
	allRunners = append(allRunners, group...)
	allRunners = append(allRunners, instance...)

	for _, runner := range allRunners {
		summary.Total++
		if runner.Online {
			summary.Online++
		} else {
			summary.Offline++
		}
	}

	return summary
}

// filterSelfHostedRunners filters out GitLab SaaS shared runners.
// On gitlab.com, the shared runners (saas-linux-*, saas-macos-*, saas-windows-*, etc.)
// create noise and aren't interesting for red team reconnaissance.
// Only truly self-hosted/custom runners are relevant for attacks.
func filterSelfHostedRunners(runners []RunnerInfo) []RunnerInfo {
	filtered := make([]RunnerInfo, 0)
	for _, runner := range runners {
		// Filter out GitLab SaaS shared runners by description pattern
		desc := strings.ToLower(runner.Description)
		if strings.Contains(desc, "saas-linux") ||
			strings.Contains(desc, "saas-macos") ||
			strings.Contains(desc, "saas-windows") ||
			strings.Contains(desc, "shared-gitlab-org") ||
			strings.Contains(desc, "shared-runners-manager") ||
			strings.Contains(desc, ".runners-manager.gitlab.com") {
			continue // Skip SaaS shared runners
		}
		// Keep self-hosted and custom runners
		filtered = append(filtered, runner)
	}
	return filtered
}
