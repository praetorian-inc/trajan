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

// Detection detects script injection in Jenkins pipeline definitions.
// Jenkins pipelines using string interpolation in shell steps can allow
// attackers to inject arbitrary commands via user-controlled parameters.
type Detection struct {
	base.BaseDetection
}

// New creates a new Jenkins script injection detection
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("injection", "jenkins", detections.SeverityHigh),
	}
}

// injectablePatterns contains patterns that indicate unsafe parameter
// interpolation in Jenkinsfile shell steps.
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

// Detect finds script injection vulnerabilities in the workflow graph
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

// createFinding creates a finding for script injection with all matched patterns
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
