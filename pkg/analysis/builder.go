package analysis

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/analysis/parser"
	"github.com/praetorian-inc/trajan/pkg/detections/shared/taintsources"
	"github.com/praetorian-inc/trajan/pkg/gitlab"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// The azure parser registers as "azure" while the platform ID is "azuredevops".
var platformParserName = map[string]string{
	"azuredevops": "azure",
	"github":      "github",
	"gitlab":      "gitlab",
}

func BuildGraph(repoSlug, path string, content []byte, metadata ...map[string]interface{}) (*graph.Graph, error) {
	detectedParser := parser.DetectParser(path)
	if detectedParser == nil && len(metadata) > 0 {
		if platform, ok := metadata[0]["platform"].(string); ok && platform != "" {
			parserName := platform
			if mapped, known := platformParserName[platform]; known {
				parserName = mapped
			}
			detectedParser = parser.GetParser(parserName)
		}
	}
	if detectedParser != nil {
		normalized, err := detectedParser.Parse(content)
		if err != nil {
			return nil, fmt.Errorf("parsing workflow with %s parser: %w", detectedParser.Platform(), err)
		}
		return BuildGraphFromNormalized(repoSlug, path, normalized, metadata...)
	}

	wf, err := parser.ParseWorkflow(content) //nolint:staticcheck // SA1019: legacy fallback path intentionally uses the GitHub-only parser
	if err != nil {
		return nil, fmt.Errorf("parsing workflow: %w", err)
	}

	g := graph.NewGraph()
	builder := &graphBuilder{
		graph:    g,
		repoSlug: repoSlug,
		path:     path,
		workflow: wf,
	}

	if err := builder.build(); err != nil {
		return nil, err
	}

	if len(metadata) > 0 {
		for key, value := range metadata[0] {
			g.SetMetadata(key, value)
		}
	}

	return g, nil
}

func BuildGraphFromNormalized(repoSlug, path string, workflow *parser.NormalizedWorkflow, metadata ...map[string]interface{}) (*graph.Graph, error) {
	g := graph.NewGraph()

	// Must precede build: detections read graph metadata during construction.
	if len(metadata) > 0 {
		for key, value := range metadata[0] {
			g.SetMetadata(key, value)
		}
	}

	builder := &normalizedGraphBuilder{
		graph:    g,
		repoSlug: repoSlug,
		path:     path,
		workflow: workflow,
	}

	if len(metadata) > 0 && workflow.Platform == "gitlab" {
		if client, ok := metadata[0]["gitlab_client"]; ok {
			if projectID, ok := metadata[0]["gitlab_project_id"].(int); ok {
				if ref, ok := metadata[0]["gitlab_ref"].(string); ok {
					if gitlabClient, ok := client.(*gitlab.Client); ok {
						builder.resolver = gitlab.NewIncludeResolver(gitlabClient, projectID, ref)
					}
				}
			}
		}
	}

	if err := builder.build(); err != nil {
		return nil, err
	}

	return g, nil
}

type graphBuilder struct {
	graph    *graph.Graph
	repoSlug string
	path     string
	workflow *parser.GitHubWorkflow
}

func (b *graphBuilder) build() error {
	triggers := b.workflow.GetTriggers()

	wfID := fmt.Sprintf("%s:%s", b.repoSlug, b.path)
	wfNode := graph.NewWorkflowNode(wfID, b.workflow.Name, b.path, b.repoSlug, triggers)

	for _, trigger := range triggers {
		switch trigger {
		case "pull_request_target":
			wfNode.AddTag(graph.TagPullRequestTarget)
		case "issue_comment":
			wfNode.AddTag(graph.TagIssueComment)
		case "workflow_run":
			wfNode.AddTag(graph.TagWorkflowRun)
		case "pull_request":
			wfNode.AddTag(graph.TagPullRequest)
		case "push":
			wfNode.AddTag(graph.TagPush)
		case "workflow_dispatch":
			wfNode.AddTag(graph.TagWorkflowDispatch)
		case "fork":
			wfNode.AddTag(graph.TagFork)
		case "issues":
			wfNode.AddTag(graph.TagIssues)
		case "discussion", "discussion_comment":
			wfNode.AddTag(graph.TagDiscussion)
		case "merge_request":
			wfNode.AddTag(graph.TagMergeRequest)
		case "external_pull_request":
			wfNode.AddTag(graph.TagExternalPullRequest)
		}
	}

	b.graph.AddNode(wfNode)

	for jobName, job := range b.workflow.Jobs {
		if err := b.buildJob(wfID, jobName, &job); err != nil {
			return err
		}
	}

	return nil
}

func (b *graphBuilder) buildJob(wfID, jobName string, job *parser.GitHubJob) error {
	jobID := fmt.Sprintf("%s:job:%s", wfID, jobName)
	jobNode := graph.NewJobNode(jobID, jobName, job.GetRunsOn())

	if job.IsSelfHostedRunner() {
		jobNode.AddTag(graph.TagSelfHostedRunner)
	}

	if perms, ok := job.Permissions.(map[string]interface{}); ok {
		jobNode.Permissions = make(map[string]string)
		for k, v := range perms {
			if strVal, ok := v.(string); ok {
				jobNode.Permissions[k] = strVal
				if strVal == "write" {
					jobNode.AddTag(graph.TagWritePermissions)
				}
			}
		}
	}

	jobNode.Needs = job.GetNeeds()
	jobNode.Uses = job.Uses
	jobNode.If = job.If

	b.graph.AddNode(jobNode)
	b.graph.AddEdge(wfID, jobID, graph.EdgeContains)

	for i, step := range job.Steps {
		if err := b.buildStep(jobID, i, &step); err != nil {
			return err
		}
	}

	return nil
}

func (b *graphBuilder) buildStep(jobID string, index int, step *parser.GitHubStep) error {
	stepID := fmt.Sprintf("%s:step:%d", jobID, index)
	stepNode := graph.NewStepNode(stepID, step.Name, index)
	stepNode.Uses = step.Uses
	stepNode.Run = step.Run
	stepNode.With = step.With
	stepNode.Env = step.Env
	stepNode.If = step.If

	if strings.Contains(step.Uses, "actions/checkout") {
		stepNode.AddTag(graph.TagCheckout)

		if ref, ok := step.With["ref"]; ok {
			refLower := strings.ToLower(ref)
			if strings.Contains(ref, "github.event.pull_request.head") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
			// Requires "head" so that a steps.*.base_sha output does not match.
			if strings.Contains(refLower, "steps.") && strings.Contains(refLower, "head") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
			if strings.Contains(refLower, "refs/pull/") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
			if strings.Contains(ref, "github.event.issue") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
			if strings.Contains(ref, "github.event.workflow_run") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
		}
	}

	if strings.Contains(step.Uses, "actions/download-artifact") {
		stepNode.AddTag(graph.TagArtifactDownload)
	}
	if strings.Contains(step.Uses, "actions/upload-artifact") {
		stepNode.AddTag(graph.TagArtifactUpload)
	}

	if strings.Contains(step.Uses, "actions/cache") {
		stepNode.AddTag(graph.TagCacheRestore)
	}

	if step.Run != "" && containsInjectableContext(step.Run) {
		stepNode.AddTag(graph.TagInjectable)
	}

	b.graph.AddNode(stepNode)
	b.graph.AddEdge(jobID, stepID, graph.EdgeContains)

	return nil
}

func containsInjectableContext(s string) bool {
	for _, ctx := range taintsources.GitHubTaintedContexts {
		if strings.Contains(s, ctx) {
			return true
		}
	}
	return strings.Contains(s, taintsources.InputsPrefix)
}

type normalizedGraphBuilder struct {
	graph    *graph.Graph
	repoSlug string
	path     string
	workflow *parser.NormalizedWorkflow
	resolver interface{} // GitLab IncludeResolver or nil
}

func (b *normalizedGraphBuilder) build() error {
	wfID := fmt.Sprintf("%s:%s", b.repoSlug, b.path)
	name := b.workflow.Name
	if name == "" {
		name = b.path
	}
	wfNode := graph.NewWorkflowNode(wfID, name, b.path, b.repoSlug, b.workflow.Triggers)

	for _, trigger := range b.workflow.Triggers {
		switch trigger {
		case "pull_request_target":
			wfNode.AddTag(graph.TagPullRequestTarget)
		case "issue_comment":
			wfNode.AddTag(graph.TagIssueComment)
		case "workflow_run":
			wfNode.AddTag(graph.TagWorkflowRun)
		case "pull_request":
			wfNode.AddTag(graph.TagPullRequest)
		case "push":
			wfNode.AddTag(graph.TagPush)
		case "workflow_dispatch":
			wfNode.AddTag(graph.TagWorkflowDispatch)
		case "fork":
			wfNode.AddTag(graph.TagFork)
		case "issues":
			wfNode.AddTag(graph.TagIssues)
		case "discussion", "discussion_comment":
			wfNode.AddTag(graph.TagDiscussion)
		case "merge_request":
			wfNode.AddTag(graph.TagMergeRequest)
		case "external_pull_request":
			wfNode.AddTag(graph.TagExternalPullRequest)
		}
	}

	if b.workflow.Raw != nil {
		if glCI, ok := b.workflow.Raw.(*parser.GitLabCI); ok && glCI != nil {
			for _, inc := range glCI.Includes {
				wfNode.Includes = append(wfNode.Includes, graph.Include{
					Type:     string(inc.Type),
					Path:     inc.Path,
					Remote:   inc.Remote,
					Project:  inc.Project,
					Ref:      inc.Ref,
					Template: inc.Template,
				})
			}
		}
	}

	wfNode.Env = b.workflow.Env
	wfNode.TriggerLines = b.workflow.TriggerLines

	b.graph.AddNode(wfNode)

	if b.resolver != nil && b.workflow.Platform == "gitlab" {
		ctx := context.Background()
		_ = b.resolveGitLabIncludes(ctx, wfNode)
	}

	for jobID, job := range b.workflow.Jobs {
		if err := b.buildJob(wfID, jobID, job); err != nil {
			return err
		}
	}

	return nil
}

func (b *normalizedGraphBuilder) buildJob(wfID, jobID string, job *parser.NormalizedJob) error {
	jobNodeID := fmt.Sprintf("%s:job:%s", wfID, jobID)
	jobNode := graph.NewJobNode(jobNodeID, job.Name, job.RunsOn)
	jobNode.Line = job.Line

	if job.SelfHosted {
		jobNode.AddTag(graph.TagSelfHostedRunner)
	}

	if job.Permissions != nil {
		jobNode.Permissions = make(map[string]string)

		if job.Permissions.WriteAll {
			jobNode.AddTag(graph.TagWritePermissions)
		}

		for scope, access := range job.Permissions.Scopes {
			jobNode.Permissions[scope] = access
			if access == "write" {
				jobNode.AddTag(graph.TagWritePermissions)
			}
		}
	}

	jobNode.Needs = job.Needs
	jobNode.Uses = job.Uses
	jobNode.If = job.Condition
	jobNode.Environment = job.Environment
	jobNode.Env = job.Env
	jobNode.ComputedTriggers = b.computeJobTriggers(job)
	jobNode.RunnerTags = job.RunnerTags

	b.graph.AddNode(jobNode)
	b.graph.AddEdge(wfID, jobNodeID, graph.EdgeContains)

	for i, step := range job.Steps {
		if err := b.buildStep(jobNodeID, i, step); err != nil {
			return err
		}
	}

	return nil
}

func (b *normalizedGraphBuilder) buildStep(jobID string, index int, step *parser.NormalizedStep) error {
	stepID := fmt.Sprintf("%s:step:%d", jobID, index)
	stepNode := graph.NewStepNode(stepID, step.Name, step.Line)
	stepNode.Uses = step.Uses
	stepNode.Run = step.Run
	stepNode.With = step.With
	stepNode.Env = step.Env
	stepNode.WithLines = step.WithLines
	stepNode.EnvLines = step.EnvLines
	stepNode.If = step.Condition

	if strings.Contains(step.Uses, "actions/checkout") {
		stepNode.AddTag(graph.TagCheckout)

		if ref, ok := step.With["ref"]; ok {
			refLower := strings.ToLower(ref)
			if strings.Contains(ref, "github.event.pull_request.head") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
			// Requires "head" so that a steps.*.base_sha output does not match.
			if strings.Contains(refLower, "steps.") && strings.Contains(refLower, "head") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
			if strings.Contains(refLower, "refs/pull/") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
			if strings.Contains(ref, "github.event.issue") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
			if strings.Contains(ref, "github.event.workflow_run") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
		}
	}

	if strings.Contains(step.Uses, "actions/download-artifact") {
		stepNode.AddTag(graph.TagArtifactDownload)
	}
	if strings.Contains(step.Uses, "actions/upload-artifact") {
		stepNode.AddTag(graph.TagArtifactUpload)
	}

	if strings.Contains(step.Uses, "actions/cache") {
		stepNode.AddTag(graph.TagCacheRestore)
	}

	if step.Run != "" && containsInjectableContext(step.Run) {
		stepNode.AddTag(graph.TagInjectable)
	}

	b.graph.AddNode(stepNode)
	b.graph.AddEdge(jobID, stepID, graph.EdgeContains)

	return nil
}

func (b *normalizedGraphBuilder) computeJobTriggers(job *parser.NormalizedJob) []string {
	triggers := make(map[string]bool)

	for _, t := range b.workflow.Triggers {
		triggers[t] = true
	}

	if job.Condition != "" {
		condition := strings.ToLower(job.Condition)

		// Quoted so that "pushgateway" does not match "push".
		sourceMap := map[string]string{
			`"merge_request_event"`:         "merge_request",
			`'merge_request_event'`:         "merge_request",
			`"external_pull_request_event"`: "external_pull_request",
			`'external_pull_request_event'`: "external_pull_request",
			`"push"`:                        "push",
			`'push'`:                        "push",
			`"schedule"`:                    "schedule",
			`'schedule'`:                    "schedule",
		}
		for pattern, trigger := range sourceMap {
			if strings.Contains(condition, pattern) {
				triggers[trigger] = true
			}
		}
	}

	result := make([]string, 0, len(triggers))
	for t := range triggers {
		result = append(result, t)
	}
	return result
}

func (b *normalizedGraphBuilder) resolveGitLabIncludes(ctx context.Context, parentWfNode *graph.WorkflowNode) error {
	resolver, ok := b.resolver.(*gitlab.IncludeResolver)
	if !ok {
		return fmt.Errorf("resolver is not a GitLab IncludeResolver")
	}

	if b.workflow.Raw == nil {
		return nil
	}

	glCI, ok := b.workflow.Raw.(*parser.GitLabCI)
	if !ok || glCI == nil {
		return nil
	}

	if len(glCI.Includes) == 0 {
		return nil
	}

	resolved, err := resolver.ResolveIncludes(ctx, glCI.Includes)
	if err != nil {
		// Best effort: an unresolvable include degrades the graph, never fails the run.
		return nil
	}

	for _, inc := range resolved {
		if err := b.createIncludedWorkflowNode(ctx, inc, parentWfNode); err != nil {
			continue
		}
	}

	return nil
}

func (b *normalizedGraphBuilder) createIncludedWorkflowNode(ctx context.Context, inc *gitlab.IncludedWorkflow, parentWfNode *graph.WorkflowNode) error {
	if inc == nil || inc.Workflow == nil {
		return fmt.Errorf("invalid included workflow")
	}

	includedWfID := fmt.Sprintf("%s:included:%s", parentWfNode.ID(), inc.Source)

	name := inc.Workflow.Name
	if name == "" {
		name = fmt.Sprintf("included-%s", inc.Type)
	}

	// GitLab includes run in the including pipeline's triggering context.
	includedWfNode := graph.NewWorkflowNode(
		includedWfID,
		name,
		inc.Path,
		b.repoSlug,
		parentWfNode.Triggers,
	)

	for _, tag := range parentWfNode.Tags() {
		includedWfNode.AddTag(tag)
	}

	includedWfNode.Env = inc.Workflow.Env
	includedWfNode.TriggerLines = inc.Workflow.TriggerLines

	b.graph.AddNode(includedWfNode)

	b.graph.AddEdge(parentWfNode.ID(), includedWfID, graph.EdgeIncludes)

	// GetIncludedWorkflows reads these metadata entries to render include content.
	includedWfObject := platforms.Workflow{
		Name:     name,
		Path:     inc.Path,
		Content:  inc.Content,
		RepoSlug: b.repoSlug,
	}

	metadataKey := fmt.Sprintf("included_workflow:%s", inc.Source)
	b.graph.SetMetadata(metadataKey, includedWfObject)

	for jobID, job := range inc.Workflow.Jobs {
		if err := b.buildJob(includedWfID, jobID, job); err != nil {
			continue
		}
	}

	for _, nestedInc := range inc.Includes {
		if err := b.createIncludedWorkflowNode(ctx, nestedInc, includedWfNode); err != nil {
			continue
		}
	}

	return nil
}
