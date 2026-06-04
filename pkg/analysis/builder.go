// pkg/analysis/builder.go
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

// platformParserName maps Trajan platform identifiers to parser registry names.
// Needed because the azure parser registers as "azure" but the platform is identified as "azuredevops".
var platformParserName = map[string]string{
	"azuredevops": "azure",
	"github":      "github",
	"gitlab":      "gitlab",
}

// BuildGraph builds a workflow graph from YAML content
// Auto-detects platform (GitHub, GitLab, etc.) based on file path
func BuildGraph(repoSlug, path string, content []byte, metadata ...map[string]interface{}) (*graph.Graph, error) {
	// Try to detect parser based on path
	detectedParser := parser.DetectParser(path)
	// If no parser was detected by filename, fall back to platform hint from metadata.
	// Use platformParserName to translate platform IDs (e.g. "azuredevops") to parser names (e.g. "azure").
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
		// Use platform-specific parser → NormalizedWorkflow → normalizedGraphBuilder
		normalized, err := detectedParser.Parse(content)
		if err != nil {
			return nil, fmt.Errorf("parsing workflow with %s parser: %w", detectedParser.Platform(), err)
		}
		return BuildGraphFromNormalized(repoSlug, path, normalized, metadata...)
	}

	// Fallback to legacy GitHub Actions parser for backward compatibility
	wf, err := parser.ParseWorkflow(content)
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

	// Set metadata if provided
	if len(metadata) > 0 {
		for key, value := range metadata[0] {
			g.SetMetadata(key, value)
		}
	}

	return g, nil
}

// BuildGraphFromNormalized builds a workflow graph from a NormalizedWorkflow
// This supports multi-platform workflows (GitHub, GitLab, BitBucket, Azure DevOps)
func BuildGraphFromNormalized(repoSlug, path string, workflow *parser.NormalizedWorkflow, metadata ...map[string]interface{}) (*graph.Graph, error) {
	g := graph.NewGraph()

	// Set metadata before building graph (detections may need it)
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

	// Create GitLab resolver if metadata present
	if len(metadata) > 0 && workflow.Platform == "gitlab" {
		if client, ok := metadata[0]["gitlab_client"]; ok {
			if projectID, ok := metadata[0]["gitlab_project_id"].(int); ok {
				if ref, ok := metadata[0]["gitlab_ref"].(string); ok {
					// Type assert to *gitlab.Client
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
	workflow *parser.Workflow
}

func (b *graphBuilder) build() error {
	triggers := b.workflow.GetTriggers()

	// Create workflow node
	wfID := fmt.Sprintf("%s:%s", b.repoSlug, b.path)
	wfNode := graph.NewWorkflowNode(wfID, b.workflow.Name, b.path, b.repoSlug, triggers)

	// Tag workflow with triggers
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

	// Build job nodes
	for jobName, job := range b.workflow.Jobs {
		if err := b.buildJob(wfID, jobName, &job); err != nil {
			return err
		}
	}

	return nil
}

func (b *graphBuilder) buildJob(wfID, jobName string, job *parser.Job) error {
	jobID := fmt.Sprintf("%s:job:%s", wfID, jobName)
	jobNode := graph.NewJobNode(jobID, jobName, job.GetRunsOn())

	// Tag self-hosted runners
	if job.IsSelfHostedRunner() {
		jobNode.AddTag(graph.TagSelfHostedRunner)
	}

	// Check and store permissions
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
	jobNode.Uses = job.Uses // Set reusable workflow reference
	jobNode.If = job.If

	b.graph.AddNode(jobNode)
	b.graph.AddEdge(wfID, jobID, graph.EdgeContains)

	// Build step nodes
	for i, step := range job.Steps {
		if err := b.buildStep(jobID, i, &step); err != nil {
			return err
		}
	}

	return nil
}

func (b *graphBuilder) buildStep(jobID string, index int, step *parser.Step) error {
	stepID := fmt.Sprintf("%s:step:%d", jobID, index)
	stepNode := graph.NewStepNode(stepID, step.Name, index)
	stepNode.Uses = step.Uses
	stepNode.Run = step.Run
	stepNode.With = step.With
	stepNode.Env = step.Env
	stepNode.If = step.If

	// Tag actions/checkout
	if strings.Contains(step.Uses, "actions/checkout") {
		stepNode.AddTag(graph.TagCheckout)

		// Check for unsafe checkout (PR refs)
		if ref, ok := step.With["ref"]; ok {
			refLower := strings.ToLower(ref)
			// Direct PR refs
			if strings.Contains(ref, "github.event.pull_request.head") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
			// Dynamic outputs from steps - must include "head" to avoid base_sha false positives
			if strings.Contains(refLower, "steps.") && strings.Contains(refLower, "head") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
			// PR refs from expressions (refs/pull/)
			if strings.Contains(refLower, "refs/pull/") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
			// Issue number based checkouts (fetch PR from issue)
			if strings.Contains(ref, "github.event.issue") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
			// Workflow run PR refs
			if strings.Contains(ref, "github.event.workflow_run") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
		}
	}

	// Tag artifact actions
	if strings.Contains(step.Uses, "actions/download-artifact") {
		stepNode.AddTag(graph.TagArtifactDownload)
	}
	if strings.Contains(step.Uses, "actions/upload-artifact") {
		stepNode.AddTag(graph.TagArtifactUpload)
	}

	// Tag cache actions (explicit actions/cache plus cache-side-effects of
	// common setup-language actions). See isCacheRestoreStep.
	if isCacheRestoreStep(step.Uses, step.With) {
		stepNode.AddTag(graph.TagCacheRestore)
	}

	// Tag injectable contexts in run commands
	if step.Run != "" && containsInjectableContext(step.Run) {
		stepNode.AddTag(graph.TagInjectable)
	}

	b.graph.AddNode(stepNode)
	b.graph.AddEdge(jobID, stepID, graph.EdgeContains)

	return nil
}

// isCacheRestoreStep reports whether a step seeds or restores a build cache.
// Covers the explicit actions/cache action plus the cache: side-effects of
// common setup-language actions (setup-node, setup-go, setup-python,
// setup-java with cache:*; ruby/setup-ruby with bundler-cache: true) and
// pnpm/action-setup, which always seeds the pnpm store. Both buildStep
// implementations in this file use this so they stay in sync.
func isCacheRestoreStep(uses string, with map[string]string) bool {
	if strings.Contains(uses, "actions/cache") {
		return true
	}
	if strings.Contains(uses, "pnpm/action-setup") {
		return true
	}
	if with["cache"] != "" {
		for _, setup := range []string{
			"actions/setup-node",
			"actions/setup-go",
			"actions/setup-python",
			"actions/setup-java",
		} {
			if strings.Contains(uses, setup) {
				return true
			}
		}
	}
	if strings.EqualFold(with["bundler-cache"], "true") &&
		strings.Contains(uses, "ruby/setup-ruby") {
		return true
	}
	return false
}

// containsInjectableContext checks if a string contains potentially injectable contexts
func containsInjectableContext(s string) bool {
	for _, ctx := range taintsources.GitHubTaintedContexts {
		if strings.Contains(s, ctx) {
			return true
		}
	}
	if strings.Contains(s, taintsources.InputsPrefix) {
		return true
	}
	return false
}

// normalizedGraphBuilder builds graphs from NormalizedWorkflow (multi-platform support)
type normalizedGraphBuilder struct {
	graph    *graph.Graph
	repoSlug string
	path     string
	workflow *parser.NormalizedWorkflow
	resolver interface{} // GitLab IncludeResolver or nil
}

func (b *normalizedGraphBuilder) build() error {
	// Create workflow node
	wfID := fmt.Sprintf("%s:%s", b.repoSlug, b.path)
	name := b.workflow.Name
	if name == "" {
		name = b.path
	}
	wfNode := graph.NewWorkflowNode(wfID, name, b.path, b.repoSlug, b.workflow.Triggers)

	// Tag workflow with triggers
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

	// Populate includes from Raw (platform-specific data)
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

	// Resolve GitLab includes if resolver is available
	if b.resolver != nil && b.workflow.Platform == "gitlab" {
		ctx := context.Background()
		if err := b.resolveGitLabIncludes(ctx, wfNode); err != nil {
			// Log warning but continue - graceful degradation
			// In production, use structured logging
			// For now, continue building the graph even if includes fail
		}
	}

	// Build job nodes
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
	jobNode.Line = job.Line // Set line number from parser

	if job.SelfHosted {
		jobNode.AddTag(graph.TagSelfHostedRunner)
	}

	// Check and store permissions
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
	jobNode.Uses = job.Uses // Set reusable workflow reference
	jobNode.If = job.Condition
	jobNode.Environment = job.Environment
	jobNode.Env = job.Env                                // Set job-level environment variables
	jobNode.ComputedTriggers = b.computeJobTriggers(job) // Compute effective triggers
	jobNode.RunnerTags = job.RunnerTags                  // Set runner tags (for GitLab runner selection)

	b.graph.AddNode(jobNode)
	b.graph.AddEdge(wfID, jobNodeID, graph.EdgeContains)

	// Build step nodes
	for i, step := range job.Steps {
		if err := b.buildStep(jobNodeID, i, step); err != nil {
			return err
		}
	}

	return nil
}

func (b *normalizedGraphBuilder) buildStep(jobID string, index int, step *parser.NormalizedStep) error {
	stepID := fmt.Sprintf("%s:step:%d", jobID, index)
	stepNode := graph.NewStepNode(stepID, step.Name, step.Line) // Use step.Line instead of index
	stepNode.Uses = step.Uses
	stepNode.Run = step.Run
	stepNode.With = step.With
	stepNode.Env = step.Env
	stepNode.WithLines = step.WithLines
	stepNode.EnvLines = step.EnvLines
	stepNode.If = step.Condition

	// Tag actions/checkout
	if strings.Contains(step.Uses, "actions/checkout") {
		stepNode.AddTag(graph.TagCheckout)

		// Check for unsafe checkout (PR refs)
		if ref, ok := step.With["ref"]; ok {
			refLower := strings.ToLower(ref)
			// Direct PR refs
			if strings.Contains(ref, "github.event.pull_request.head") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
			// Dynamic outputs from steps - must include "head" to avoid base_sha false positives
			if strings.Contains(refLower, "steps.") && strings.Contains(refLower, "head") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
			// PR refs from expressions (refs/pull/)
			if strings.Contains(refLower, "refs/pull/") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
			// Issue number based checkouts (fetch PR from issue)
			if strings.Contains(ref, "github.event.issue") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
			// Workflow run PR refs
			if strings.Contains(ref, "github.event.workflow_run") {
				stepNode.AddTag(graph.TagUnsafeCheckout)
			}
		}
	}

	// Tag artifact actions
	if strings.Contains(step.Uses, "actions/download-artifact") {
		stepNode.AddTag(graph.TagArtifactDownload)
	}
	if strings.Contains(step.Uses, "actions/upload-artifact") {
		stepNode.AddTag(graph.TagArtifactUpload)
	}

	// Tag cache actions (explicit actions/cache plus cache-side-effects of
	// common setup-language actions). See isCacheRestoreStep.
	if isCacheRestoreStep(step.Uses, step.With) {
		stepNode.AddTag(graph.TagCacheRestore)
	}

	// Tag injectable contexts in run commands
	if step.Run != "" && containsInjectableContext(step.Run) {
		stepNode.AddTag(graph.TagInjectable)
	}

	b.graph.AddNode(stepNode)
	b.graph.AddEdge(jobID, stepID, graph.EdgeContains)

	return nil
}

// computeJobTriggers determines what triggers would cause a job to run
// Combines workflow-level triggers with job-level rules
func (b *normalizedGraphBuilder) computeJobTriggers(job *parser.NormalizedJob) []string {
	triggers := make(map[string]bool)

	// 1. Inherit workflow-level triggers
	for _, t := range b.workflow.Triggers {
		triggers[t] = true
	}

	// 2. Extract from job.Condition (job-level rules)
	if job.Condition != "" {
		condition := strings.ToLower(job.Condition)

		// Match quoted source names to avoid false positives
		// (e.g., "pushgateway" should not match "push")
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

	// Convert to slice
	result := make([]string, 0, len(triggers))
	for t := range triggers {
		result = append(result, t)
	}
	return result
}

// resolveGitLabIncludes resolves GitLab CI includes and creates workflow nodes for them
func (b *normalizedGraphBuilder) resolveGitLabIncludes(ctx context.Context, parentWfNode *graph.WorkflowNode) error {
	// Type assert the resolver to IncludeResolver
	resolver, ok := b.resolver.(*gitlab.IncludeResolver)
	if !ok {
		return fmt.Errorf("resolver is not a GitLab IncludeResolver")
	}

	// Extract includes from the workflow's Raw GitLabCI data
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

	// Resolve all includes
	resolved, err := resolver.ResolveIncludes(ctx, glCI.Includes)
	if err != nil {
		// Graceful degradation - log warning but continue
		return nil
	}

	// Create workflow nodes for each resolved include
	for _, inc := range resolved {
		if err := b.createIncludedWorkflowNode(ctx, inc, parentWfNode); err != nil {
			// Continue on error - graceful degradation
			continue
		}
	}

	return nil
}

// createIncludedWorkflowNode creates a workflow node for an included workflow and recursively processes its children
func (b *normalizedGraphBuilder) createIncludedWorkflowNode(ctx context.Context, inc *gitlab.IncludedWorkflow, parentWfNode *graph.WorkflowNode) error {
	if inc == nil || inc.Workflow == nil {
		return fmt.Errorf("invalid included workflow")
	}

	includedWfID := fmt.Sprintf("%s:included:%s", parentWfNode.ID(), inc.Source)

	name := inc.Workflow.Name
	if name == "" {
		// Use a descriptive name based on the include source
		name = fmt.Sprintf("included-%s", inc.Type)
	}

	// Use the parent's triggers for included workflows
	// GitLab includes inherit the triggering context
	includedWfNode := graph.NewWorkflowNode(
		includedWfID,
		name,
		inc.Path, // Use clean path for display
		b.repoSlug,
		parentWfNode.Triggers, // Inherit triggers from parent
	)

	// Tag the workflow with the same tags as the parent
	for _, tag := range parentWfNode.Tags() {
		includedWfNode.AddTag(tag)
	}

	includedWfNode.Env = inc.Workflow.Env
	includedWfNode.TriggerLines = inc.Workflow.TriggerLines

	b.graph.AddNode(includedWfNode)

	b.graph.AddEdge(parentWfNode.ID(), includedWfID, graph.EdgeIncludes)

	// Store as platforms.Workflow so GetIncludedWorkflows() can access content for rendering
	includedWfObject := platforms.Workflow{
		Name:     name,
		Path:     inc.Path, // Use clean path for display
		Content:  inc.Content,
		RepoSlug: b.repoSlug,
	}

	metadataKey := fmt.Sprintf("included_workflow:%s", inc.Source)
	b.graph.SetMetadata(metadataKey, includedWfObject)

	// Build job nodes for the included workflow
	for jobID, job := range inc.Workflow.Jobs {
		if err := b.buildJob(includedWfID, jobID, job); err != nil {
			// Continue on error
			continue
		}
	}

	// Recursively process nested includes
	for _, nestedInc := range inc.Includes {
		if err := b.createIncludedWorkflowNode(ctx, nestedInc, includedWfNode); err != nil {
			// Continue on error
			continue
		}
	}

	return nil
}
