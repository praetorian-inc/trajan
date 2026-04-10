package artifact

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
	registry.RegisterDetection("github", "artifact-poisoning", func() detections.Detection {
		return New()
	})
}

type Detection struct {
	base.BaseDetection
}

func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("artifact-poisoning", "github", detections.SeverityHigh),
	}
}

func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	// Get all workflow_run triggered workflows
	workflowRunNodes := g.GetNodesByTag(graph.TagWorkflowRun)

	for _, wfNode := range workflowRunNodes {
		wf := wfNode.(*graph.WorkflowNode)

		// Track artifact download and subsequent execution
		var downloadStep *graph.StepNode
		var jobNode *graph.JobNode

		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			switch node.Type() {
			case graph.NodeTypeJob:
				jobNode = node.(*graph.JobNode)
				downloadStep = nil // Reset per job
			case graph.NodeTypeStep:
				step := node.(*graph.StepNode)

				// Found artifact download
				if step.HasTag(graph.TagArtifactDownload) {
					downloadStep = step
					return true
				}

				// If we found download and now see code execution (not just validation)
				if downloadStep != nil && step.Run != "" && detections.IsExecutionSink(step.Run) {
					findings = append(findings, createFinding(wf, jobNode, downloadStep, step))
					downloadStep = nil // Reset to avoid duplicates
				}
			}
			return true
		})
	}

	return findings, nil
}

func createFinding(wf *graph.WorkflowNode, job *graph.JobNode, downloadStep, execStep *graph.StepNode) detections.Finding {
	evidence := "workflow_run downloads artifact then executes code"
	if downloadStep.Uses != "" {
		evidence = "Workflow uses workflow_run trigger, downloads artifact via " + downloadStep.Uses + ", then executes code from artifact without validation."
	}

	jobName := ""
	if job != nil {
		jobName = job.Name
	}

	// Build attack chain for detailed view
	attackChain := detections.BuildChainFromNodes(
		wf,           // workflow_run trigger
		job,          // Job containing download
		downloadStep, // Artifact download step
		execStep,     // Execution step (sink)
	)

	// Create line ranges for the execution step
	var lineRanges []detections.LineRange
	if execStep != nil && execStep.Line > 0 {
		lineRanges = []detections.LineRange{
			{
				Start: execStep.Line,
				End:   execStep.Line + 3,
				Label: "artifact execution",
			},
		}
	}

	// Build sink description
	sinkDescription := ""
	if execStep != nil {
		sinkDescription = fmt.Sprintf("Step: %s (line %d) - executes artifact content without validation", execStep.Name, execStep.Line)
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
		Type:       detections.VulnArtifactPoison,
		Platform:   "github",
		Class:      detections.GetVulnerabilityClass(detections.VulnArtifactPoison),
		Severity:   detections.SeverityHigh,
		Confidence: detections.ConfidenceMedium,
		Complexity: detections.ComplexityHigh,
		Repository:   wf.RepoSlug,
		Workflow:     wf.Path, // Use path for matching
		WorkflowFile: wf.Path,
		Job:          jobName,
		Step:       execStep.Name,
		Line:       execStep.Line,
		Trigger:    "workflow_run",
		Evidence:   evidence,
		Details: &detections.FindingDetails{
			LineRanges:  lineRanges,
			AttackChain: attackChain,
			Metadata:    metadata,
		},
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	// Trim whitespace and newlines for cleaner output
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
