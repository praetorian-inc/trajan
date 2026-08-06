package injection

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
	registry.RegisterDetection("gitlab", "script-injection", func() detections.Detection {
		return New()
	})
}

type Detection struct {
	base.BaseDetection
}

func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("script-injection", "gitlab", detections.SeverityHigh),
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

		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			if node.Type() == graph.NodeTypeStep {
				step, ok := node.(*graph.StepNode)
				if !ok {
					return true
				}

				if step.Run == "" {
					return true
				}

				var matched []string
				for _, injectable := range common.InjectableContexts {
					if strings.Contains(step.Run, "$"+injectable) ||
						strings.Contains(step.Run, "${"+injectable+"}") {
						matched = append(matched, injectable)
					}
				}
				if len(matched) > 0 {
					findings = append(findings, d.createFinding(g, step, matched))
				}
			}
			return true
		})
	}

	return findings, nil
}

func (d *Detection) createFinding(g *graph.Graph, step *graph.StepNode, injectables []string) detections.Finding {
	wf := common.GetStepParentWorkflow(g, step)
	if wf == nil {
		wf = &graph.WorkflowNode{}
	}

	varList := make([]string, len(injectables))
	ctxList := make([]string, len(injectables))
	for i, injectable := range injectables {
		varList[i] = "$" + injectable
		ctxList[i] = "$" + injectable
	}
	evidence := "Script uses user-controllable variable(s) " + strings.Join(varList, ", ") + " which can be manipulated by external attackers to inject commands. "
	evidence += "Attackers can craft malicious values (e.g., in merge request titles or commit messages) to execute arbitrary commands in the CI pipeline."

	attackChain := detections.BuildChainFromNodes(wf, step)

	var lineRanges []detections.LineRange
	if step.Line > 0 {
		lineRanges = append(lineRanges, detections.LineRange{
			Start: step.Line,
			End:   step.Line,
			Label: "injectable variable usage",
		})
	}

	metadata := make(map[string]interface{})
	metadata["injectableVariables"] = ctxList

	return detections.Finding{
		Type:         detections.VulnScriptInjection,
		Platform:     "gitlab",
		Class:        detections.GetVulnerabilityClass(detections.VulnScriptInjection),
		Severity:     detections.SeverityHigh,
		Confidence:   detections.ConfidenceHigh,
		Complexity:   detections.ComplexityZeroClick,
		Repository:   wf.RepoSlug,
		Workflow:     wf.Path,
		WorkflowFile: wf.Path,
		Step:         step.Name,
		Line:         step.Line,
		Evidence:     evidence,
		Remediation:  "Avoid using " + strings.Join(varList, ", ") + " directly in scripts. Sanitize the value or use GitLab's predefined CI/CD variables instead. Never execute user-controlled data as shell commands.",
		Details: &detections.FindingDetails{
			LineRanges:         lineRanges,
			AttackChain:        attackChain,
			InjectableContexts: ctxList,
			Metadata:           metadata,
		},
	}
}
