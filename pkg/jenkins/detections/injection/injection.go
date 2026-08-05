package injection

import (
	"context"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
)

func init() {
	registry.RegisterDetection("jenkins", "injection", func() detections.Detection {
		return New()
	})
}

// String interpolation in a shell step lets a user-controlled parameter inject
// arbitrary commands.
type Detection struct {
	base.BaseDetection
}

func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("injection", "jenkins", detections.SeverityHigh),
	}
}

// Unsafe parameter interpolation inside Jenkinsfile shell steps.
var injectablePatterns = []string{
	"${params.",
	"${env.",
	"${currentBuild.",
	"${BRANCH_NAME}",
	"${CHANGE_TITLE}",
	"${CHANGE_AUTHOR}",
	"${CHANGE_BRANCH}",
	"${GIT_BRANCH}",
	"${GIT_COMMIT}",
}

func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)

	for _, wfNode := range workflows {
		wf, ok := wfNode.(*graph.WorkflowNode)
		if !ok {
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
				for _, pattern := range injectablePatterns {
					if strings.Contains(step.Run, pattern) {
						matched = append(matched, pattern)
					}
				}
				if len(matched) > 0 {
					findings = append(findings, d.createFinding(wf, step, matched))
				}
			}
			return true
		})
	}

	return findings, nil
}

func (d *Detection) createFinding(wf *graph.WorkflowNode, step *graph.StepNode, patterns []string) detections.Finding {
	return detections.Finding{
		Type:        detections.VulnScriptInjection,
		Platform:    "jenkins",
		Class:       detections.ClassInjection,
		Severity:    detections.SeverityHigh,
		Confidence:  detections.ConfidenceHigh,
		Complexity:  detections.ComplexityLow,
		Repository:  wf.RepoSlug,
		Workflow:    wf.Name,
		Step:        step.Name,
		Line:        step.Line,
		Trigger:     strings.Join(wf.Triggers, ", "),
		Evidence:    step.Run,
		Remediation: "Avoid using Groovy string interpolation (" + strings.Join(patterns, ", ") + ") in sh/bat steps. Use single-quoted strings or pass values through environment variables with the withEnv block.",
		Details: &detections.FindingDetails{
			InjectableContexts: patterns,
		},
	}
}
