package cache

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
)

func init() {
	registry.RegisterDetection("github", "cache-poisoning", func() detections.Detection {
		return New()
	})
}

type Detection struct {
	base.BaseDetection
}

func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("cache-poisoning", "github", detections.SeverityHigh),
	}
}

func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	// Get workflows with privileged triggers (workflow_run or pull_request_target)
	workflowRunNodes := g.GetNodesByTag(graph.TagWorkflowRun)
	pullRequestTargetNodes := g.GetNodesByTag(graph.TagPullRequestTarget)

	// Combine both privileged trigger types
	privilegedNodes := append(workflowRunNodes, pullRequestTargetNodes...)

	for _, wfNode := range privilegedNodes {
		wf, ok := wfNode.(*graph.WorkflowNode)
		if !ok {
			continue
		}

		// Determine trigger type for reporting
		trigger := "workflow_run"
		if wf.HasTag(graph.TagPullRequestTarget) {
			trigger = "pull_request_target"
		}

		// Track cache restore and subsequent execution
		var cacheStep *graph.StepNode
		var jobNode *graph.JobNode

		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			switch node.Type() {
			case graph.NodeTypeJob:
				job, ok := node.(*graph.JobNode)
				if !ok {
					return true
				}
				jobNode = job
				cacheStep = nil // Reset per job
			case graph.NodeTypeStep:
				step, ok := node.(*graph.StepNode)
				if !ok {
					return true
				}

				// Found cache restore
				if step.HasTag(graph.TagCacheRestore) {
					cacheStep = step
					return true
				}

				// If we found cache restore and now see code execution (not just validation)
				if cacheStep != nil && step.Run != "" && detections.IsExecutionSink(step.Run) {
					findings = append(findings, createFinding(wf, jobNode, cacheStep, step, trigger))
					cacheStep = nil // Reset to avoid duplicates
				}
			}
			return true
		})
	}

	return findings, nil
}

func createFinding(wf *graph.WorkflowNode, job *graph.JobNode, cacheStep, execStep *graph.StepNode, trigger string) detections.Finding {
	evidence := fmt.Sprintf("Workflow uses %s trigger, restores cache via %s, then executes code that may use poisoned cache contents.", trigger, cacheStep.Uses)

	jobName := ""
	if job != nil {
		jobName = job.Name
	}

	// Build attack chain for detailed view
	attackChain := detections.BuildChainFromNodes(
		wf,        // Trigger
		job,       // Job containing cache restore
		cacheStep, // Cache restore step
		execStep,  // Execution step (sink)
	)

	// Create line ranges for both cache restore and execution steps
	var lineRanges []detections.LineRange

	// Highlight cache restore step (where poison enters)
	if cacheStep.Line > 0 {
		lineRanges = append(lineRanges, detections.LineRange{
			Start: cacheStep.Line,
			End:   cacheStep.Line + 4, // Cache restore typically 4-5 lines
			Label: "cache restore",
		})
	}

	// Highlight execution step (where poison is used)
	if execStep != nil && execStep.Line > 0 {
		lineRanges = append(lineRanges, detections.LineRange{
			Start: execStep.Line,
			End:   execStep.Line + 3,
			Label: "cache execution",
		})
	}

	// Build sink description
	sinkDescription := ""
	if execStep != nil {
		sinkDescription = fmt.Sprintf("Step: %s (line %d) - may execute code using poisoned cache", execStep.Name, execStep.Line)
		if execStep.Run != "" {
			firstLine := strings.Split(execStep.Run, "\n")[0]
			if len(firstLine) > 60 {
				firstLine = firstLine[:60] + "..."
			}
			sinkDescription += fmt.Sprintf("\n  Command: %s", firstLine)
		}
	}

	// Add metadata
	metadata := make(map[string]interface{})
	if sinkDescription != "" {
		metadata["sink"] = sinkDescription
	}

	return detections.Finding{
		Type:         detections.VulnCachePoisoning,
		Platform:     "github",
		Class:        detections.GetVulnerabilityClass(detections.VulnCachePoisoning),
		Severity:     detections.SeverityHigh,
		Confidence:   detections.ConfidenceMedium,
		Complexity:   detections.ComplexityHigh,
		Repository:   wf.RepoSlug,
		Workflow:     wf.Path, // Use path for matching
		WorkflowFile: wf.Path,
		Job:          jobName,
		Step:         execStep.Name,
		Line:         execStep.Line,
		Trigger:      trigger,
		Evidence:     evidence,
		Remediation:  "Avoid restoring caches in privileged workflow contexts (workflow_run, pull_request_target). If caching is necessary, use scope-restricted cache keys that prevent cross-branch poisoning, and never execute binaries or scripts directly from restored cache contents.",
		Details: &detections.FindingDetails{
			LineRanges:  lineRanges,
			AttackChain: attackChain,
			Metadata:    metadata,
		},
	}
}
