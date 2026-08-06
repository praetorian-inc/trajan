package gitlab

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/analysis/parser"
)

// includeInstance requires admin access.
func (p *Platform) EnumerateRunners(ctx context.Context, projectPath string, includeGroup, includeInstance bool) (*RunnersEnumerateResult, error) {
	result := &RunnersEnumerateResult{
		ProjectRunners:  make([]RunnerInfo, 0),
		GroupRunners:    make([]RunnerInfo, 0),
		InstanceRunners: make([]RunnerInfo, 0),
	}

	project, err := p.client.GetProject(ctx, projectPath)
	if err != nil {
		result.Errors = append(result.Errors, "getting project: "+err.Error())
		return result, nil
	}

	// SaaS shared runners are filtered out as noise.
	isSaaS := strings.Contains(strings.ToLower(p.client.baseURL), "gitlab.com")

	projectRunners, err := p.client.ListProjectRunners(ctx, project.ID)
	if err != nil {
		result.Errors = append(result.Errors, "listing project runners: "+err.Error())
	} else {
		if isSaaS {
			// An empty result on SaaS is expected, not an error.
			projectRunners = filterSelfHostedRunners(projectRunners)
		}
		result.ProjectRunners = projectRunners
	}

	if includeGroup && project.Namespace.FullPath != "" {
		group, err := p.client.GetGroup(ctx, project.Namespace.FullPath)
		if err != nil {
			result.Errors = append(result.Errors, "getting group: "+err.Error())
		} else {
			groupRunners, err := p.client.ListGroupRunners(ctx, group.ID)
			if err != nil {
				result.Errors = append(result.Errors, "listing group runners: "+err.Error())
			} else {
				if isSaaS {
					groupRunners = filterSelfHostedRunners(groupRunners)
				}
				result.GroupRunners = groupRunners
			}
		}
	}

	if includeInstance {
		instanceRunners, err := p.client.ListInstanceRunners(ctx)
		if err != nil {
			if IsPermissionError(err) {
				result.Errors = append(result.Errors, "listing instance runners: admin access required (403)")
			} else {
				result.Errors = append(result.Errors, "listing instance runners: "+err.Error())
			}
		} else {
			if isSaaS {
				instanceRunners = filterSelfHostedRunners(instanceRunners)
			}
			result.InstanceRunners = instanceRunners
		}
	}

	result.Summary = buildRunnerSummary(result.ProjectRunners, result.GroupRunners, result.InstanceRunners)

	return result, nil
}

func (p *Platform) AnalyzeWorkflowTags(ctx context.Context, yamlContent []byte, availableRunners []RunnerInfo) (*WorkflowTagAnalysis, error) {
	analysis := &WorkflowTagAnalysis{
		RequiredTags:  make([]string, 0),
		AvailableTags: make([]string, 0),
		MissingTags:   make([]string, 0),
	}

	requiredTags, err := extractWorkflowTags(yamlContent)
	if err != nil {
		return nil, fmt.Errorf("extracting workflow tags: %w", err)
	}
	analysis.RequiredTags = requiredTags

	availableTagsSet := make(map[string]bool)
	for i := range availableRunners {
		runner := &availableRunners[i]
		for _, tag := range runner.Tags {
			availableTagsSet[tag] = true
		}
	}

	for tag := range availableTagsSet {
		analysis.AvailableTags = append(analysis.AvailableTags, tag)
	}

	for _, tag := range requiredTags {
		if !availableTagsSet[tag] {
			analysis.MissingTags = append(analysis.MissingTags, tag)
		}
	}

	analysis.ProjectsAnalyzed = 1

	return analysis, nil
}

func extractWorkflowTags(yamlContent []byte) ([]string, error) {
	gitlabParser := parser.NewGitLabParser()
	workflow, err := gitlabParser.Parse(yamlContent)
	if err != nil {
		return nil, fmt.Errorf("parsing GitLab CI: %w", err)
	}

	glCI, ok := workflow.Raw.(*parser.GitLabCI)
	if !ok {
		return nil, fmt.Errorf("unexpected workflow type")
	}

	tagsSet := make(map[string]bool)
	for _, job := range glCI.Jobs {
		for _, tag := range job.Tags {
			tagsSet[tag] = true
		}
	}

	tags := make([]string, 0, len(tagsSet))
	for tag := range tagsSet {
		tags = append(tags, tag)
	}

	return tags, nil
}

func buildRunnerSummary(project, group, instance []RunnerInfo) RunnerSummary {
	summary := RunnerSummary{
		Project:  len(project),
		Group:    len(group),
		Instance: len(instance),
	}

	// Allocate fresh slice to avoid mutating caller's data
	allRunners := make([]RunnerInfo, 0, len(project)+len(group)+len(instance))
	allRunners = append(allRunners, project...)
	allRunners = append(allRunners, group...)
	allRunners = append(allRunners, instance...)

	for i := range allRunners {
		runner := &allRunners[i]
		summary.Total++
		if runner.Online {
			summary.Online++
		} else {
			summary.Offline++
		}
	}

	return summary
}

// gitlab.com's shared runners are noise; only self-hosted runners matter here.
func filterSelfHostedRunners(runners []RunnerInfo) []RunnerInfo {
	filtered := make([]RunnerInfo, 0)
	for _, runner := range runners {
		desc := strings.ToLower(runner.Description)
		if strings.Contains(desc, "saas-linux") ||
			strings.Contains(desc, "saas-macos") ||
			strings.Contains(desc, "saas-windows") ||
			strings.Contains(desc, "shared-gitlab-org") ||
			strings.Contains(desc, "shared-runners-manager") ||
			strings.Contains(desc, ".runners-manager.gitlab.com") {
			continue
		}
		filtered = append(filtered, runner)
	}
	return filtered
}
