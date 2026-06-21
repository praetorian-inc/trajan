package review

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/github/detections/common"
)

// reviewContexts are contexts specific to PR review events
var reviewContexts = []string{
	"github.event.review.body",
	"github.event.review_comment.body",
}

// reviewTriggers are triggers that indicate PR review events
var reviewTriggers = []string{
	"pull_request_review",
	"pull_request_review_comment",
}

func init() {
	registry.RegisterDetection("github", "review-injection", func() detections.Detection {
		return New()
	})
}

type Detection struct {
	base.BaseDetection
}

func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("review-injection", "github", detections.SeverityHigh),
	}
}

func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)

	for _, wfNode := range workflows {
		wf, ok := wfNode.(*graph.WorkflowNode)
		if !ok {
			continue
		}

		// Filter to review triggers only
		if !hasReviewTrigger(wf.Triggers) {
			continue
		}

		var jobNode *graph.JobNode

		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			if node.Type() == graph.NodeTypeJob {
				job, ok := node.(*graph.JobNode)
				if !ok {
					return true
				}
				jobNode = job
				return true
			}

			if node.Type() != graph.NodeTypeStep {
				return true
			}

			step, ok := node.(*graph.StepNode)
			if !ok {
				return true
			}
			if step.Run == "" {
				return true
			}

			// Check for review-specific injectable contexts
			injectableContexts := findReviewContexts(step.Run)
			if len(injectableContexts) > 0 {
				// Create ONE finding per step with ALL contexts aggregated
				findings = append(findings, createFinding(wf, jobNode, step, injectableContexts))
			}

			return true
		})
	}

	return findings, nil
}

func hasReviewTrigger(triggers []string) bool {
	for _, t := range triggers {
		for _, rt := range reviewTriggers {
			if t == rt {
				return true
			}
		}
	}
	return false
}

func findReviewContexts(s string) []string {
	foundMap := make(map[string]bool) // Deduplicate
	matches := common.ExpressionRegex.FindAllString(s, -1)

	for _, match := range matches {
		for _, ctx := range reviewContexts {
			if strings.Contains(match, ctx) {
				foundMap[ctx] = true
				break
			}
		}
	}

	// Convert to slice
	found := make([]string, 0, len(foundMap))
	for ctx := range foundMap {
		found = append(found, ctx)
	}
	return found
}

func createFinding(wf *graph.WorkflowNode, job *graph.JobNode, step *graph.StepNode, injectableContexts []string) detections.Finding {
	jobName := ""
	if job != nil {
		jobName = job.Name
	}

	// Build attack chain
	attackChain := detections.BuildChainFromNodes(wf, job, step)

	// Create line ranges
	var lineRanges []detections.LineRange
	if step.Line > 0 {
		lineRanges = []detections.LineRange{
			{
				Start: step.Line,
				End:   step.Line + 4,
				Label: "review comment injection",
			},
		}
	}

	// Build evidence with all contexts
	contextList := strings.Join(injectableContexts, ", ")
	evidence := fmt.Sprintf("Workflow uses %s trigger and injects user-controllable review contexts (%s) into run command. This allows arbitrary command injection via PR review comments.", strings.Join(wf.Triggers, ", "), contextList)

	return detections.Finding{
		Type:         detections.VulnReviewInjection,
		Platform:     "github",
		Class:        detections.GetVulnerabilityClass(detections.VulnReviewInjection),
		Severity:     detections.SeverityHigh,
		Confidence:   detections.ConfidenceHigh,
		Complexity:   detections.ComplexityZeroClick,
		Repository:   wf.RepoSlug,
		Workflow:     wf.Path, // Use path for matching
		WorkflowFile: wf.Path,
		Job:          jobName,
		Step:         step.Name,
		Line:         step.Line,
		Trigger:      strings.Join(wf.Triggers, ", "),
		Evidence:     evidence,
		Remediation:  "Do not interpolate review comment bodies directly in run commands. Pass them through environment variables (env:) which are not subject to shell injection. For example, use 'env: COMMENT: ${{ github.event.review.body }}' and reference '$COMMENT' in the script.",
		Details: &detections.FindingDetails{
			LineRanges:         lineRanges,
			AttackChain:        attackChain,
			InjectableContexts: injectableContexts,
		},
	}
}
