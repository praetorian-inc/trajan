package mrcheckout

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/gitlab/detections/common"
)

func init() {
	registry.RegisterDetection("gitlab", "merge-request-unsafe-checkout", func() detections.Detection {
		return New()
	})
}

type Detection struct {
	base.BaseDetection
}

func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection(
			"merge-request-unsafe-checkout",
			"gitlab",
			detections.SeverityCritical,
		),
	}
}

// Commands that execute checked-out code.
var executionSinks = []string{
	"npm install", "yarn install", "pnpm install",
	"pip install", "python setup.py install",
	"pytest", "npm test", "yarn test",
	"make", "cmake", "./configure",
	"cargo build", "go build",
	"./scripts/", "./script/",
}

func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

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

		if !common.HasMergeRequestTrigger(wf, g) {
			continue
		}

		var currentJob *graph.JobNode
		var checkoutStep *graph.StepNode
		var pathNodes []graph.Node

		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			switch n := node.(type) {
			case *graph.JobNode:
				currentJob = n
				pathNodes = []graph.Node{wf, currentJob}
				checkoutStep = nil // Reset for new job

			case *graph.StepNode:
				if n.Run == "" {
					return true
				}

				if hasUnsafeCheckout(n.Run) {
					checkoutStep = n
					pathNodes = append(pathNodes, checkoutStep)

					// Checkout and sink in the same script.
					if containsExecutionSink(n.Run) {
						finding := d.createFinding(g, checkoutStep, checkoutStep, currentJob, pathNodes)
						findings = append(findings, finding)
						checkoutStep = nil
						pathNodes = []graph.Node{wf, currentJob}
					}
					return true
				}

				if checkoutStep != nil && containsExecutionSink(n.Run) {
					pathNodes = append(pathNodes, n)
					finding := d.createFinding(g, checkoutStep, n, currentJob, pathNodes)
					findings = append(findings, finding)
					checkoutStep = nil
					pathNodes = []graph.Node{wf, currentJob}
				}
			}

			return true
		})
	}

	return findings, nil
}

func hasUnsafeCheckout(script string) bool {
	script = strings.ToLower(script)

	unsafePatterns := []string{
		"git checkout $ci_merge_request_source_branch_sha",
		"git checkout fetch_head",
		"git checkout $ci_commit_sha",
		"git merge $ci_merge_request_source_branch_sha",
	}

	for _, pattern := range unsafePatterns {
		if strings.Contains(script, pattern) {
			return true
		}
	}

	return false
}

func containsExecutionSink(script string) bool {
	script = strings.ToLower(script)
	for _, sink := range executionSinks {
		if strings.Contains(script, strings.ToLower(sink)) {
			return true
		}
	}
	return false
}

func (d *Detection) createFinding(g *graph.Graph, checkoutStep *graph.StepNode, sinkStep *graph.StepNode, job *graph.JobNode, pathNodes []graph.Node) detections.Finding {
	wf := common.GetJobParentWorkflow(g, job)
	if wf == nil {
		wf = &graph.WorkflowNode{}
	}
	// Detect carries job across DFS callbacks, so it is still nil for a step
	// reached before any job node.
	if job == nil {
		job = &graph.JobNode{}
	}
	checkoutRef := extractCheckoutRef(checkoutStep.Run)

	evidence := fmt.Sprintf("Workflow triggered by merge requests checks out untrusted code (ref: %s) and executes it", checkoutRef)
	if sinkStep != nil {
		evidence += fmt.Sprintf(". Execution sink found: %s. This allows attackers to run arbitrary code with CI_JOB_TOKEN permissions.", extractSinkCommand(sinkStep.Run))
	}

	attackChain := detections.BuildChainFromNodes(pathNodes...)

	// GitLab combines scripts, so step.Line is the "script:" line and commands start below it.
	var lineRanges []detections.LineRange
	if checkoutStep.Line > 0 {
		checkoutLineOffset := findCommandLineOffset(checkoutStep.Run, "git checkout")
		if checkoutLineOffset >= 0 {
			lineRanges = append(lineRanges, detections.LineRange{
				Start: checkoutStep.Line + checkoutLineOffset + 1,
				End:   checkoutStep.Line + checkoutLineOffset + 1,
				Label: "unsafe checkout",
			})
		}

		if checkoutStep == sinkStep {
			sinkLineOffset := findCommandLineOffset(checkoutStep.Run, extractSinkCommand(checkoutStep.Run))
			if sinkLineOffset >= 0 && sinkLineOffset != checkoutLineOffset {
				lineRanges = append(lineRanges, detections.LineRange{
					Start: checkoutStep.Line + sinkLineOffset + 1,
					End:   checkoutStep.Line + sinkLineOffset + 1,
					Label: "execution sink",
				})
			}
		} else if sinkStep != nil && sinkStep.Line > 0 {
			lineRanges = append(lineRanges, detections.LineRange{
				Start: sinkStep.Line + 1,
				End:   sinkStep.Line + 1,
				Label: "execution sink",
			})
		}
	}

	metadata := make(map[string]interface{})
	if sinkStep != nil {
		metadata["sink"] = extractSinkCommand(sinkStep.Run)
		metadata["checkoutRef"] = checkoutRef
	}

	return detections.Finding{
		Type:         detections.VulnMergeRequestUnsafeCheckout,
		Severity:     detections.SeverityCritical,
		Confidence:   detections.ConfidenceHigh,
		Complexity:   detections.ComplexityZeroClick,
		Platform:     "gitlab",
		Class:        detections.GetVulnerabilityClass(detections.VulnMergeRequestUnsafeCheckout),
		Repository:   wf.RepoSlug,
		Workflow:     wf.Path,
		WorkflowFile: wf.Path,
		Job:          job.Name,
		Step:         checkoutStep.Name,
		Line:         checkoutStep.Line,
		Evidence:     evidence,
		Remediation:  "Remove git checkout of merge request source branch, or restrict this job to protected branches only using 'rules: [{if: \"$CI_COMMIT_BRANCH == \\\"main\\\"\"}]'. Default checkout behavior is safe.",
		Details: &detections.FindingDetails{
			LineRanges:  lineRanges,
			AttackChain: attackChain,
			Metadata:    metadata,
		},
	}
}

func extractCheckoutRef(script string) string {
	if strings.Contains(script, "$CI_MERGE_REQUEST_SOURCE_BRANCH_SHA") {
		return "$CI_MERGE_REQUEST_SOURCE_BRANCH_SHA"
	}
	if strings.Contains(script, "$CI_COMMIT_SHA") {
		return "$CI_COMMIT_SHA"
	}
	if strings.Contains(script, "FETCH_HEAD") {
		return "FETCH_HEAD"
	}
	if strings.Contains(script, "$CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_SHA") {
		return "$CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_SHA"
	}
	return "unknown ref"
}

func extractSinkCommand(script string) string {
	script = strings.ToLower(script)
	for _, sink := range executionSinks {
		if strings.Contains(script, strings.ToLower(sink)) {
			return sink
		}
	}
	if detections.IsExecutionSink(script) {
		lines := strings.Split(script, "\n")
		if len(lines) > 0 {
			return strings.TrimSpace(lines[0])
		}
	}
	return "code execution"
}

// Returns a 0-indexed offset within the script, or -1.
func findCommandLineOffset(script string, pattern string) int {
	lines := strings.Split(script, "\n")
	pattern = strings.ToLower(pattern)

	for i, line := range lines {
		if strings.Contains(strings.ToLower(line), pattern) {
			return i
		}
	}
	return -1
}
