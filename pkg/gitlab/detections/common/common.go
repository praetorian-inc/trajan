package common

import (
	"regexp"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

// InjectableContexts are user-controllable GitLab CI predefined variables.
// These variables can be manipulated by external attackers through merge requests,
// commits, tags, or other user-controlled inputs.
var InjectableContexts = []string{
	"CI_MERGE_REQUEST_TITLE",
	"CI_MERGE_REQUEST_DESCRIPTION",
	"CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
	"CI_COMMIT_MESSAGE",
	"CI_COMMIT_DESCRIPTION",
	"CI_COMMIT_TITLE",
	"CI_COMMIT_TAG",
	"CI_COMMIT_REF_NAME",
	"CI_COMMIT_BRANCH",
	"CI_EXTERNAL_PULL_REQUEST_TARGET_BRANCH_NAME",
	"CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME",
}

// ZeroClickTriggers are events that external attackers can trigger
// without requiring write access or human approval.
// Note: TagNote (comment events) is NOT a valid CI_PIPELINE_SOURCE in GitLab
// and cannot trigger pipelines natively.
var ZeroClickTriggers = map[graph.Tag]bool{
	graph.TagMergeRequest:        true,
	graph.TagExternalPullRequest: true,
	graph.TagPipeline:            true,
}

// DangerousTokenVariables are CI variables that expose sensitive tokens
// Using these in untrusted contexts can lead to privilege escalation
var DangerousTokenVariables = []string{
	"CI_JOB_TOKEN",
	"CI_REGISTRY_PASSWORD",
	"CI_DEPLOY_PASSWORD",
	"CI_REPOSITORY_URL", // Contains embedded credentials
}

// VariableExpressionRegex matches GitLab $VARIABLE and ${VARIABLE} patterns
var VariableExpressionRegex = regexp.MustCompile(`\$\{?[A-Za-z_][A-Za-z0-9_]*\}?`)

// GetStepParentWorkflow finds the parent workflow node for a step.
// Traverses: Step -> Job -> Workflow
// Returns nil if:
// - step is nil
// - step has no parent job
// - job has no parent workflow
// - parent is not a WorkflowNode
func GetStepParentWorkflow(g *graph.Graph, step *graph.StepNode) *graph.WorkflowNode {
	if step == nil {
		return nil
	}

	// Get parent job
	jobNode, ok := g.GetNode(step.Parent())
	if !ok {
		return nil
	}

	// Get parent workflow
	wfNode, ok := g.GetNode(jobNode.Parent())
	if !ok {
		return nil
	}

	// Type assert to WorkflowNode
	if wf, ok := wfNode.(*graph.WorkflowNode); ok {
		return wf
	}

	return nil
}

// GetJobParentWorkflow finds the parent workflow node for a job.
// Returns nil if job has no parent workflow or parent is not a WorkflowNode.
func GetJobParentWorkflow(g *graph.Graph, job *graph.JobNode) *graph.WorkflowNode {
	if job == nil {
		return nil
	}

	// Get parent workflow
	wfNode, ok := g.GetNode(job.Parent())
	if !ok {
		return nil
	}

	// Type assert to WorkflowNode
	if wf, ok := wfNode.(*graph.WorkflowNode); ok {
		return wf
	}

	return nil
}

// IsRootWorkflow returns true if the workflow is a root (not included by another workflow).
// Root workflows have no incoming EdgeIncludes edges.
// These are typically main .gitlab-ci.yml files or standalone workflow files.
// Workflows that are included via the 'include' keyword will have incoming EdgeIncludes edges
// and therefore are not roots.
func IsRootWorkflow(g *graph.Graph, wf *graph.WorkflowNode) bool {
	if wf == nil {
		return false
	}

	// Check for incoming EdgeIncludes edges
	for _, edge := range g.GetIncomingEdges(wf.ID()) {
		if edge.Type == graph.EdgeIncludes {
			return false // This workflow is included by another
		}
	}

	return true // No incoming includes, this is a root workflow
}

// HasMergeRequestTrigger checks if the workflow triggers on merge requests.
// Uses DFS to also check job-level If conditions for MR references.
func HasMergeRequestTrigger(wf *graph.WorkflowNode, g *graph.Graph) bool {
	// Check tags for merge request indicators
	for _, tag := range wf.Tags() {
		if tag == graph.TagMergeRequest || tag == graph.TagExternalPullRequest {
			return true
		}
	}

	// Fallback: check if workflow has merge_request in triggers (case-insensitive)
	for _, trigger := range wf.Triggers {
		triggerLower := strings.ToLower(trigger)
		if strings.Contains(triggerLower, "merge_request") ||
			strings.Contains(triggerLower, "external_pull_request") {
			return true
		}
	}

	// Also check job-level If conditions for merge request references
	foundMR := false
	graph.DFS(g, wf.ID(), func(node graph.Node) bool {
		if job, ok := node.(*graph.JobNode); ok {
			if JobRunsOnMRExplicit(job) {
				foundMR = true
				return false // Stop DFS, we found it
			}
		}
		return true
	})

	return foundMR
}

// JobRunsOnMRExplicit checks if a job explicitly mentions MR events in its If condition.
func JobRunsOnMRExplicit(job *graph.JobNode) bool {
	if job.If == "" {
		return false
	}

	ifLower := strings.ToLower(job.If)
	return strings.Contains(ifLower, "merge_request") ||
		strings.Contains(ifLower, "external_pull_request")
}

// JobRunsOnMR checks if a job runs on merge request events.
// This includes jobs that explicitly mention MR events OR jobs without If conditions
// in workflows that have MR triggers.
func JobRunsOnMR(job *graph.JobNode, wf *graph.WorkflowNode, g *graph.Graph) bool {
	// If job explicitly mentions MR events, it runs on MR
	if JobRunsOnMRExplicit(job) {
		return true
	}

	// If job has an If condition but doesn't mention MR events, it doesn't run on MR
	if job.If != "" {
		return false
	}

	// Job has no If condition - check if workflow has MR trigger
	return HasMergeRequestTrigger(wf, g)
}

// IsProtectedBranchOnly checks if a job is restricted to protected branches.
// Returns false if the condition also includes MR trigger conditions,
// since that means the job can still run on merge requests.
func IsProtectedBranchOnly(job *graph.JobNode) bool {
	if job.If == "" {
		return false
	}

	ifLower := strings.ToLower(job.If)

	// Check for protected branch patterns
	protectedBranchPatterns := []string{
		"== \"main\"",
		"== \"master\"",
		"== 'main'",
		"== 'master'",
		"=~ /^main$/",
		"=~ /^master$/",
		"ci_commit_branch == \"main\"",
		"ci_commit_branch == \"master\"",
		"ci_commit_branch == 'main'",
		"ci_commit_branch == 'master'",
		"ci_commit_ref_name == \"main\"",
		"ci_commit_ref_name == \"master\"",
		"ci_commit_ref_name == 'main'",
		"ci_commit_ref_name == 'master'",
	}

	// Only return true if the condition ONLY restricts to protected branches
	// and doesn't also include MR trigger conditions
	hasMRCondition := strings.Contains(ifLower, "merge_request_event") ||
		strings.Contains(ifLower, "external_pull_request_event")

	if hasMRCondition {
		return false
	}

	for _, pattern := range protectedBranchPatterns {
		if strings.Contains(ifLower, pattern) {
			return true
		}
	}

	return false
}
