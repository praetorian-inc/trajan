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
			if common.IsProtectedBranchOnly(job) {
				return true
			}

			// Check if job runs on merge request trigger
			// This checks both workflow-level and job-level triggers
			if !common.JobRunsOnMR(job, wf, g) {
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
	wf := common.GetJobParentWorkflow(g, job)
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
		Type:         detections.VulnSelfHostedRunner,
		Platform:     "gitlab",
		Class:        detections.GetVulnerabilityClass(detections.VulnSelfHostedRunner),
		Severity:     detections.SeverityHigh,
		Confidence:   detections.ConfidenceHigh,
		Complexity:   detections.ComplexityZeroClick,
		Repository:   wf.RepoSlug,
		Workflow:     wf.Path,
		WorkflowFile: wf.Path,
		Job:          job.Name,
		Line:         job.Line,
		Trigger:      strings.Join(wf.Triggers, ", "),
		Evidence:     evidence,
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
