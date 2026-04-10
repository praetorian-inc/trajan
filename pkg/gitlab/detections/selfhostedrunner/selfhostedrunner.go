package selfhostedrunner

import (
	"context"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/gitlab/detections/common"
)

func init() {
	registry.RegisterDetection("gitlab", "self-hosted-runner-exposure", func() detections.Detection {
		return New()
	})
}

// Detection detects self-hosted or group runner usage on untrusted merge request triggers
type Detection struct {
	base.BaseDetection
	gitlabSaaSRunners map[string]bool
}

// New creates a new self-hosted-runner-exposure detection
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection(
			"self-hosted-runner-exposure",
			"gitlab",
			detections.SeverityHigh,
		),
		// GitLab SaaS runner tags are safe (GitLab-hosted)
		gitlabSaaSRunners: map[string]bool{
			"saas-linux-small-amd64":    true,
			"saas-linux-medium-amd64":   true,
			"saas-linux-large-amd64":    true,
			"saas-linux-xlarge-amd64":   true,
			"saas-macos-medium-m1":      true,
			"saas-windows-medium-amd64": true,
		},
	}
}

// Detect analyzes the graph for self-hosted runners on untrusted triggers
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	// Get all workflow nodes
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)

	for _, wfNode := range workflows {
		wf, ok := wfNode.(*graph.WorkflowNode)
		if !ok {
			continue
		}

		// Only DFS from root workflows to avoid duplicates
		if !common.IsRootWorkflow(g, wf) {
			continue
		}

		// DFS to find jobs that use self-hosted runners
		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			job, ok := node.(*graph.JobNode)
			if !ok {
				return true
			}

			// Skip if job is restricted to protected branches only
			if isProtectedBranchOnly(job) {
				return true
			}

			// Check if job runs on merge request trigger
			// This checks both workflow-level and job-level triggers
			if !jobRunsOnMR(job, wf) {
				return true
			}

			// Check if job uses a self-hosted or non-GitLab runner
			if d.usesSelfHostedRunner(job.RunnerTags) {
				finding := d.createFinding(g, job)
				findings = append(findings, finding)
			}

			return true
		})
	}

	return findings, nil
}

// hasMergeRequestTrigger checks if the workflow triggers on merge requests
func hasMergeRequestTrigger(wf *graph.WorkflowNode) bool {
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

	return false
}

// jobRunsOnMR checks if a job runs on merge request events
func jobRunsOnMR(job *graph.JobNode, wf *graph.WorkflowNode) bool {
	// If job explicitly mentions MR events, it runs on MR
	if jobRunsOnMRExplicit(job) {
		return true
	}

	// If the workflow doesn't have MR trigger, job can't run on MR
	if !hasMergeRequestTrigger(wf) {
		return false
	}

	// Workflow has MR trigger
	// Jobs inherit workflow triggers unless explicitly excluded
	// The If condition adds constraints but doesn't remove the MR trigger
	// (unless it's a protected branch condition, which is checked separately)
	return true
}

// jobRunsOnMRExplicit checks if a job explicitly mentions MR events in its If condition
func jobRunsOnMRExplicit(job *graph.JobNode) bool {
	if job.If == "" {
		return false
	}

	ifLower := strings.ToLower(job.If)
	return strings.Contains(ifLower, "merge_request") ||
		strings.Contains(ifLower, "external_pull_request")
}

// isProtectedBranchOnly checks if a job is restricted to protected branches
func isProtectedBranchOnly(job *graph.JobNode) bool {
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
		// If condition mentions both MR and protected branch, it's not safe
		return false
	}

	for _, pattern := range protectedBranchPatterns {
		if strings.Contains(ifLower, pattern) {
			return true
		}
	}

	return false
}

// usesSelfHostedRunner checks if a job uses self-hosted or non-GitLab runners
func (d *Detection) usesSelfHostedRunner(runnerTags []string) bool {
	// Empty tags mean default shared runners (safe on GitLab.com)
	if len(runnerTags) == 0 {
		return false
	}

	// Check each tag
	for _, tag := range runnerTags {
		tagLower := strings.ToLower(tag)

		// Check if explicitly self-hosted
		if tagLower == "self-hosted" {
			return true
		}

		// Check against known GitLab SaaS runners
		if !d.gitlabSaaSRunners[tagLower] {
			// This tag is not a known GitLab SaaS runner, so it's custom/self-hosted
			return true
		}
	}

	// All tags are GitLab SaaS runners (safe)
	return false
}

// createFinding creates a finding for self-hosted runner exposure
func (d *Detection) createFinding(g *graph.Graph, job *graph.JobNode) detections.Finding {
	wf := getJobParentWorkflow(g, job)
	if wf == nil {
		// Fallback to empty workflow info if parent not found
		wf = &graph.WorkflowNode{}
	}
	// Determine trigger type for evidence
	triggerType := "merge request"
	for _, tag := range wf.Tags() {
		if tag == graph.TagExternalPullRequest {
			triggerType = "external pull request"
			break
		}
	}

	// Build evidence
	runnerTagsStr := strings.Join(job.RunnerTags, ", ")
	evidence := "Job runs on self-hosted or group runner (" + runnerTagsStr + ") and is triggered by " + triggerType + " events. "
	evidence += "Attackers can compromise runner infrastructure, access secrets from other projects sharing the runner, or persist code between runs."

	// Create line range for the job
	var lineRanges []detections.LineRange
	if job.Line > 0 {
		lineRanges = []detections.LineRange{
			{
				Start: job.Line,
				End:   job.Line + 2, // Job + tags line
				Label: "self-hosted runner on MR",
			},
		}
	}

	return detections.Finding{
		Type:       detections.VulnSelfHostedRunner,
		Platform:   "gitlab",
		Class:      detections.GetVulnerabilityClass(detections.VulnSelfHostedRunner),
		Severity:   detections.SeverityHigh,
		Confidence: detections.ConfidenceHigh,
		Complexity: detections.ComplexityZeroClick,
		Repository:   wf.RepoSlug,
		Workflow:     wf.Path,
		WorkflowFile: wf.Path,
		Job:          job.Name,
		Line:       job.Line,
		Trigger:    strings.Join(wf.Triggers, ", "),
		Evidence:   evidence,
		Remediation: "Restrict this job to protected branches only by adding a rules condition like '$CI_COMMIT_BRANCH == \"main\"' or use GitLab SaaS runners (saas-linux-small-amd64, etc.) instead of self-hosted runners for untrusted merge requests.\n\n" +
			"Example:\n\n" +
			"  " + job.Name + ":\n" +
			"    tags:\n" +
			"      - saas-linux-medium-amd64\n" +
			"    rules:\n" +
			"      - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n" +
			"    script:\n" +
			"      - npm test\n\n" +
			"Or restrict to protected branches:\n\n" +
			"  " + job.Name + ":\n" +
			"    tags:\n" +
			"      - self-hosted\n" +
			"    rules:\n" +
			"      - if: '$CI_COMMIT_BRANCH == \"main\"'\n" +
			"    script:\n" +
			"      - deploy.sh",
		Details: &detections.FindingDetails{
			LineRanges: lineRanges,
		},
	}
}

// getJobParentWorkflow finds the parent workflow node for a job.
// Returns nil if job has no parent workflow or parent is not a WorkflowNode.
func getJobParentWorkflow(g *graph.Graph, job *graph.JobNode) *graph.WorkflowNode {
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
