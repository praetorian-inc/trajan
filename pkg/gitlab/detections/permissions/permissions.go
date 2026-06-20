package permissions

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
	registry.RegisterDetection("gitlab", "token-exposure", func() detections.Detection {
		return New()
	})
}

// Detection detects token and credential exposure in GitLab CI
type Detection struct {
	base.BaseDetection
}

// New creates a new token exposure detection
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("token-exposure", "gitlab", detections.SeverityHigh),
	}
}

// Detect finds token exposure vulnerabilities in the workflow graph
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)

	for _, wfNode := range workflows {
		wf := wfNode.(*graph.WorkflowNode)

		// Only DFS from root workflows to avoid duplicates
		if !common.IsRootWorkflow(g, wf) {
			continue
		}

		// Check if workflow has zero-click trigger
		hasDangerousTrigger := d.hasDangerousTrigger(wf)

		// Only check workflows with dangerous triggers
		if !hasDangerousTrigger {
			continue
		}

		// DFS through all steps
		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			if node.Type() == graph.NodeTypeStep {
				step := node.(*graph.StepNode)

				// Check for token exposure in scripts
				for _, token := range common.DangerousTokenVariables {
					if strings.Contains(step.Run, "$"+token) || strings.Contains(step.Run, "${"+token+"}") {
						findings = append(findings, d.createFinding(g, step, token))
					}
				}
			}
			return true
		})
	}

	return findings, nil
}

// hasDangerousTrigger checks if workflow is triggered by zero-click events
func (d *Detection) hasDangerousTrigger(wf *graph.WorkflowNode) bool {
	// Check tags first (for GitHub compatibility)
	for _, tag := range wf.Tags() {
		if common.ZeroClickTriggers[tag] {
			return true
		}
	}

	// For GitLab, check Triggers strings (tags not set by builder)
	for _, trigger := range wf.Triggers {
		triggerLower := strings.ToLower(trigger)
		if strings.Contains(triggerLower, "merge_request") ||
			strings.Contains(triggerLower, "external_pull_request") {
			return true
		}
	}

	return false
}

// createFinding creates a finding for token exposure
func (d *Detection) createFinding(g *graph.Graph, step *graph.StepNode, token string) detections.Finding {
	wf := common.GetStepParentWorkflow(g, step)
	if wf == nil {
		// Fallback to empty workflow info if parent not found
		wf = &graph.WorkflowNode{}
	}

	// Get parent job name (simplified for now)
	jobName := ""

	evidence := "Sensitive token $" + token + " exposed in script running on merge request trigger. External attackers can capture this token."
	attackChain := []detections.ChainNode{{NodeType: "step", Name: step.Name, Line: step.Line}}

	return detections.Finding{
		Type:        detections.VulnTokenExposure,
		Platform:    "gitlab",
		Class:       detections.GetVulnerabilityClass(detections.VulnTokenExposure),
		Severity:    detections.SeverityHigh,
		Confidence:  detections.ConfidenceHigh,
		Complexity:  detections.ComplexityZeroClick,
		Repository:   wf.RepoSlug,
		Workflow:     wf.Path,
		WorkflowFile: wf.Path,
		Job:          jobName,
		Step:        step.Name,
		Line:        step.Line,
		Evidence:    evidence,
		Remediation: "Do not expose $" + token + " in scripts on merge request triggers. Restrict job to protected branches.",
		Details: &detections.FindingDetails{
			LineRanges:  []detections.LineRange{{Start: step.Line, End: step.Line}},
			AttackChain: attackChain,
			Metadata:    map[string]interface{}{"exposedToken": "$" + token},
		},
	}
}
