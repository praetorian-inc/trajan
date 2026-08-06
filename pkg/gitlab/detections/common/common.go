package common

import (
	"regexp"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

// GitLab CI predefined variables an outside attacker can set via a merge request, commit or tag.
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

// Events an outside attacker can trigger without write access or human approval.
// TagNote is absent: comment events are not a CI_PIPELINE_SOURCE in GitLab.
var ZeroClickTriggers = map[graph.Tag]bool{
	graph.TagMergeRequest:        true,
	graph.TagExternalPullRequest: true,
	graph.TagPipeline:            true,
}

// Using these in untrusted contexts can lead to privilege escalation
var DangerousTokenVariables = []string{
	"CI_JOB_TOKEN",
	"CI_REGISTRY_PASSWORD",
	"CI_DEPLOY_PASSWORD",
	"CI_REPOSITORY_URL", // Contains embedded credentials
}

var VariableExpressionRegex = regexp.MustCompile(`\$\{?[A-Za-z_][A-Za-z0-9_]*\}?`)

// Traverses: Step -> Job -> Workflow
func GetStepParentWorkflow(g *graph.Graph, step *graph.StepNode) *graph.WorkflowNode {
	if step == nil {
		return nil
	}

	jobNode, ok := g.GetNode(step.Parent())
	if !ok {
		return nil
	}

	wfNode, ok := g.GetNode(jobNode.Parent())
	if !ok {
		return nil
	}

	if wf, ok := wfNode.(*graph.WorkflowNode); ok {
		return wf
	}

	return nil
}

func GetJobParentWorkflow(g *graph.Graph, job *graph.JobNode) *graph.WorkflowNode {
	if job == nil {
		return nil
	}

	wfNode, ok := g.GetNode(job.Parent())
	if !ok {
		return nil
	}

	if wf, ok := wfNode.(*graph.WorkflowNode); ok {
		return wf
	}

	return nil
}

// Root workflows have no incoming EdgeIncludes edges.
func IsRootWorkflow(g *graph.Graph, wf *graph.WorkflowNode) bool {
	if wf == nil {
		return false
	}

	for _, edge := range g.GetIncomingEdges(wf.ID()) {
		if edge.Type == graph.EdgeIncludes {
			return false
		}
	}

	return true
}

func HasMergeRequestTrigger(wf *graph.WorkflowNode, g *graph.Graph) bool {
	for _, tag := range wf.Tags() {
		if tag == graph.TagMergeRequest || tag == graph.TagExternalPullRequest {
			return true
		}
	}

	for _, trigger := range wf.Triggers {
		triggerLower := strings.ToLower(trigger)
		if strings.Contains(triggerLower, "merge_request") ||
			strings.Contains(triggerLower, "external_pull_request") {
			return true
		}
	}

	foundMR := false
	graph.DFS(g, wf.ID(), func(node graph.Node) bool {
		if job, ok := node.(*graph.JobNode); ok {
			if JobRunsOnMRExplicit(job) {
				foundMR = true
				return false // false stops the DFS
			}
		}
		return true
	})

	return foundMR
}

func JobRunsOnMRExplicit(job *graph.JobNode) bool {
	if job.If == "" {
		return false
	}

	ifLower := strings.ToLower(job.If)
	return strings.Contains(ifLower, "merge_request") ||
		strings.Contains(ifLower, "external_pull_request")
}

// A job with no If condition inherits the workflow's MR trigger.
func JobRunsOnMR(job *graph.JobNode, wf *graph.WorkflowNode, g *graph.Graph) bool {
	if JobRunsOnMRExplicit(job) {
		return true
	}

	if job.If != "" {
		return false
	}

	return HasMergeRequestTrigger(wf, g)
}

// False when the condition also matches MR events, since the job can still run on a merge request.
func IsProtectedBranchOnly(job *graph.JobNode) bool {
	if job.If == "" {
		return false
	}

	ifLower := strings.ToLower(job.If)

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
