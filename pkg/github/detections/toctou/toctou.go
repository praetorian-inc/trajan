package toctou

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
)

// immutablePatterns are refs that point to specific commits (safe)
var immutablePatterns = []string{
	"github.sha",
	".head.sha",
	".merge_commit_sha",
	"inputs.sha",
	"inputs.commit",
	"inputs.pr_sha",     // PR SHA is immutable
	"inputs.commit_sha", // Commit SHA is immutable
}

// mutablePatterns suggest refs that can change (unsafe)
var mutablePatterns = []string{
	"refs/pull/",
	"inputs.pr",
	"inputs.ref",
	"inputs.branch",
	".head.ref",
}

var prInputPattern = regexp.MustCompile(`(?i)pr|pull|pull_request`)

func init() {
	registry.RegisterDetection("github", "dispatch-toctou", func() detections.Detection {
		return New()
	})
}

type Detection struct {
	base.BaseDetection
}

func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("dispatch-toctou", "github", detections.SeverityMedium),
	}
}

func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	dispatchNodes := g.GetNodesByTag(graph.TagWorkflowDispatch)

	for _, wfNode := range dispatchNodes {
		wf := wfNode.(*graph.WorkflowNode)

		var checkoutStep *graph.StepNode
		var jobNode *graph.JobNode
		var mutableRef string

		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			switch node.Type() {
			case graph.NodeTypeJob:
				jobNode = node.(*graph.JobNode)
				checkoutStep = nil // Reset checkout state for new job to prevent cross-job false positives
			case graph.NodeTypeStep:
				step := node.(*graph.StepNode)

				// Check for checkout with mutable ref
				if step.HasTag(graph.TagCheckout) && step.With != nil {
					if ref, ok := step.With["ref"]; ok {
						if isMutableRef(ref) {
							checkoutStep = step
							mutableRef = ref
							return true
						}
					}
				}

				// If we found mutable checkout and now see code execution
				if checkoutStep != nil && step.Run != "" {
					findings = append(findings, createFinding(wf, jobNode, checkoutStep, step, mutableRef))
					checkoutStep = nil
				}
			}
			return true
		})
	}

	return findings, nil
}

func isMutableRef(ref string) bool {
	// Check for immutable patterns first (safe)
	for _, pattern := range immutablePatterns {
		if strings.Contains(ref, pattern) {
			return false
		}
	}

	// Check for mutable patterns (unsafe)
	for _, pattern := range mutablePatterns {
		if strings.Contains(ref, pattern) {
			return true
		}
	}

	// Check for PR-related inputs
	if strings.Contains(ref, "inputs.") {
		// Extract input name
		inputMatch := prInputPattern.FindString(ref)
		if inputMatch != "" {
			return true
		}
	}

	return false
}

func createFinding(wf *graph.WorkflowNode, job *graph.JobNode, checkoutStep, execStep *graph.StepNode, mutableRef string) detections.Finding {
	jobName := ""
	if job != nil {
		jobName = job.Name
	}

	// Build attack chain
	attackChain := detections.BuildChainFromNodes(wf, job, checkoutStep, execStep)

	// Create line ranges for checkout step
	var lineRanges []detections.LineRange
	if checkoutStep != nil && checkoutStep.Line > 0 {
		lineRanges = []detections.LineRange{
			{
				Start: checkoutStep.Line,
				End:   checkoutStep.Line + 3,
				Label: "mutable ref checkout",
			},
		}
	}

	// Build sink description
	sinkDescription := ""
	if execStep != nil {
		sinkDescription = fmt.Sprintf("Step: %s (line %d) - executes code that may have changed during race window", execStep.Name, execStep.Line)
		if execStep.Run != "" {
			firstLine := strings.Split(execStep.Run, "\n")[0]
			if len(firstLine) > 60 {
				firstLine = firstLine[:60] + "..."
			}
			sinkDescription += fmt.Sprintf("\n  Command: %s", firstLine)
		}
	}

	metadata := make(map[string]interface{})
	if sinkDescription != "" {
		metadata["sink"] = sinkDescription
	}

	evidence := fmt.Sprintf("Workflow uses workflow_dispatch trigger with mutable ref (%s). Attacker can update the ref between dispatch and checkout, leading to code execution with different code than expected (TOCTOU race condition).", mutableRef)

	return detections.Finding{
		Type:       detections.VulnTOCTOU,
		Platform:   "github",
		Class:      detections.GetVulnerabilityClass(detections.VulnTOCTOU),
		Severity:   detections.SeverityMedium,
		Confidence: detections.ConfidenceHigh,
		Complexity: detections.ComplexityMedium,
		Repository: wf.RepoSlug,
		Workflow:   wf.Path, // Use path
		Job:        jobName,
		Step:       checkoutStep.Name,
		Line:       checkoutStep.Line,
		Trigger:    "workflow_dispatch",
		Evidence:   evidence,
		Details: &detections.FindingDetails{
			LineRanges:  lineRanges,
			AttackChain: attackChain,
			CheckoutRef: mutableRef,
			Metadata:    metadata,
		},
	}
}
