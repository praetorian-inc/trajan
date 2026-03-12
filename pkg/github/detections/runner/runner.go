package runner

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/github"
	"github.com/praetorian-inc/trajan/pkg/github/detections/common"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func init() {
	registry.RegisterDetection("github", "self-hosted-runner", func() detections.Detection {
		return New()
	})
}

// Detection detects self-hosted runner usage
type Detection struct {
	base.BaseDetection
	resolver     *reusableWorkflowResolver
	resolverOnce sync.Once
}

// New creates a new runner plugin
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("self-hosted-runner", "github", detections.SeverityHigh),
	}
}

// Detect analyzes the graph for self-hosted runner usage with double-layer validation
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	// Layer 1: Find jobs configured to use self-hosted runners
	jobs := g.GetNodesByTag(graph.TagSelfHostedRunner)

	// Layer 2: Check if actual runners exist (from metadata)
	runnersExist := false
	hasRunnerData := false
	if runnerData, ok := g.GetMetadata("runners"); ok {
		if runnerResult, ok := runnerData.(*github.RunnersResult); ok {
			// Only treat runner data as valid if we didn't get permission errors
			if len(runnerResult.PermissionErrors) == 0 {
				hasRunnerData = true
			}
			// Check if any runners are registered
			for _, runners := range runnerResult.Runners {
				if len(runners) > 0 {
					runnersExist = true
					break
				}
			}
		}
	}

	for _, jobNode := range jobs {
		job := jobNode.(*graph.JobNode)

		wfNode, ok := g.GetNode(job.Parent())
		if !ok {
			continue
		}
		wf := wfNode.(*graph.WorkflowNode)

		// Double-layer: Only flag if BOTH config uses self-hosted AND runners exist
		// OR if we couldn't check runner existence
		if runnersExist || !hasRunnerData {
			findings = append(findings, createFinding(wf, job, hasRunnerData, runnersExist))
		}
	}

	// Second pass: resolve reusable workflow callers (jobs with Uses set).
	// The parser now skips tagging these, so we resolve the callee to check.
	var ghClient *github.Client
	if clientData, ok := g.GetMetadata("github_client"); ok {
		ghClient, _ = clientData.(*github.Client)
	}
	var allWorkflows map[string][]platforms.Workflow
	if wfData, ok := g.GetMetadata("all_workflows"); ok {
		allWorkflows, _ = wfData.(map[string][]platforms.Workflow)
	}

	// Only proceed if we have at least some way to resolve callees
	if ghClient != nil || allWorkflows != nil {
		d.resolverOnce.Do(func() {
			d.resolver = newResolver(ghClient, allWorkflows)
		})

		for _, node := range g.GetNodesByType(graph.NodeTypeJob) {
			job := node.(*graph.JobNode)
			if job.Uses == "" {
				continue
			}

			wfNode, ok := g.GetNode(job.Parent())
			if !ok {
				continue
			}
			wf := wfNode.(*graph.WorkflowNode)

			isSelfHosted, resolvedRunsOn, err := d.resolver.resolveCallee(ctx, wf.RepoSlug, job.Uses, 0)
			if err != nil || !isSelfHosted {
				continue
			}

			// Tag the job and update the graph index so downstream queries find it
			g.UpdateNodeTag(job.ID(), graph.TagSelfHostedRunner)
			job.RunsOn = resolvedRunsOn

			if runnersExist || !hasRunnerData {
				findings = append(findings, createFinding(wf, job, hasRunnerData, runnersExist))
			}
		}
	}

	return findings, nil
}

func createFinding(wf *graph.WorkflowNode, job *graph.JobNode, hasRunnerData, runnersConfirmed bool) detections.Finding {
	severity := detections.SeverityMedium
	isZeroClick := false

	for _, tag := range wf.Tags() {
		if common.ZeroClickTriggers[tag] {
			severity = detections.SeverityHigh
			isZeroClick = true
			break
		}
	}

	// Create line range for job with self-hosted runner
	var lineRanges []detections.LineRange
	if job.Line > 0 {
		lineRanges = []detections.LineRange{
			{
				Start: job.Line,
				End:   job.Line + 2, // Job + runs-on line
				Label: "self-hosted runner",
			},
		}
	}

	// Build evidence with layer information
	evidence := fmt.Sprintf("Layer 1 (Config): Job configured to use self-hosted runner (%s). ", job.RunsOn)

	if hasRunnerData {
		if runnersConfirmed {
			evidence += "Layer 2 (Verified): Self-hosted runners are registered and available. "
		} else {
			evidence += "Layer 2 (Verified): No self-hosted runners currently registered. "
		}
	} else {
		evidence += "Layer 2 (Unknown): Could not verify if runners exist (requires permissions). "
	}

	if isZeroClick && runnersConfirmed {
		evidence += "RISK: Zero-click trigger + confirmed runners = external attackers can execute code on your infrastructure."
	} else if isZeroClick {
		evidence += "Potential risk if runners are later added to zero-click trigger workflow."
	} else if runnersConfirmed {
		evidence += "Confirmed runners present risk of code persistence between runs."
	} else {
		evidence += "Configuration indicates potential future risk."
	}

	return detections.Finding{
		Type:       detections.VulnSelfHostedRunner,
		Platform:   "github",
		Class:      detections.GetVulnerabilityClass(detections.VulnSelfHostedRunner),
		Severity:   severity,
		Confidence: detections.ConfidenceHigh,
		Repository: wf.RepoSlug,
		Workflow:   wf.Path, // Use path
		Job:        job.Name,
		Line:       job.Line,
		Trigger:    strings.Join(wf.Triggers, ", "),
		Evidence:   evidence,
		Details: &detections.FindingDetails{
			LineRanges: lineRanges,
		},
	}
}
