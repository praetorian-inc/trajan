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

type Detection struct {
	base.BaseDetection
}

func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("token-exposure", "gitlab", detections.SeverityHigh),
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

		// Only DFS from root workflows to avoid duplicates
		if !common.IsRootWorkflow(g, wf) {
			continue
		}

		hasDangerousTrigger := d.hasDangerousTrigger(wf)

		if !hasDangerousTrigger {
			continue
		}

		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			if node.Type() == graph.NodeTypeStep {
				step, ok := node.(*graph.StepNode)
				if !ok {
					return true
				}

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

func (d *Detection) hasDangerousTrigger(wf *graph.WorkflowNode) bool {
	for _, tag := range wf.Tags() {
		if common.ZeroClickTriggers[tag] {
			return true
		}
	}

	// The GitLab builder does not set tags, so fall back to the trigger strings.
	for _, trigger := range wf.Triggers {
		triggerLower := strings.ToLower(trigger)
		if strings.Contains(triggerLower, "merge_request") ||
			strings.Contains(triggerLower, "external_pull_request") {
			return true
		}
	}

	return false
}

func (d *Detection) createFinding(g *graph.Graph, step *graph.StepNode, token string) detections.Finding {
	wf := common.GetStepParentWorkflow(g, step)
	if wf == nil {
		wf = &graph.WorkflowNode{}
	}

	jobName := ""

	evidence := "Sensitive token $" + token + " exposed in script running on merge request trigger. External attackers can capture this token."
	attackChain := []detections.ChainNode{{NodeType: "step", Name: step.Name, Line: step.Line}}

	return detections.Finding{
		Type:         detections.VulnTokenExposure,
		Platform:     "gitlab",
		Class:        detections.GetVulnerabilityClass(detections.VulnTokenExposure),
		Severity:     detections.SeverityHigh,
		Confidence:   detections.ConfidenceHigh,
		Complexity:   detections.ComplexityZeroClick,
		Repository:   wf.RepoSlug,
		Workflow:     wf.Path,
		WorkflowFile: wf.Path,
		Job:          jobName,
		Step:         step.Name,
		Line:         step.Line,
		Evidence:     evidence,
		Remediation:  "Do not expose $" + token + " in scripts on merge request triggers. Restrict job to protected branches.",
		Details: &detections.FindingDetails{
			LineRanges:  []detections.LineRange{{Start: step.Line, End: step.Line}},
			AttackChain: attackChain,
			Metadata:    map[string]interface{}{"exposedToken": "$" + token},
		},
	}
}
