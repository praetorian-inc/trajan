package agents

import (
	"context"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
)

func init() {
	registry.RegisterDetection("jenkins", "agents", func() detections.Detection {
		return New()
	})
}

// Detection detects insecure agent configurations in Jenkins pipelines.
// Running builds on the Jenkins controller or with unrestricted agent labels
// can expose the controller to arbitrary code execution.
type Detection struct {
	base.BaseDetection
}

// New creates a new agent security detection
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("agents", "jenkins", detections.SeverityMedium),
	}
}

// insecureAgentLabels contains agent labels that indicate insecure configurations
var insecureAgentLabels = []string{
	"any",
	"master",
	"built-in",
	"controller",
}

// Detect finds insecure agent configurations in the workflow graph
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)

	for _, wfNode := range workflows {
		wf, ok := wfNode.(*graph.WorkflowNode)
		if !ok {
			continue
		}

		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			if node.Type() == graph.NodeTypeJob {
				job, ok := node.(*graph.JobNode)
				if !ok {
					return true
				}

				if d.isInsecureAgent(job.RunsOn) {
					findings = append(findings, d.createFinding(wf, job))
				}
			}
			return true
		})
	}

	return findings, nil
}

// isInsecureAgent checks if an agent label is insecure
func (d *Detection) isInsecureAgent(runsOn string) bool {
	label := strings.TrimSpace(strings.ToLower(runsOn))

	// Empty label means no agent restriction
	if label == "" {
		return true
	}

	for _, insecure := range insecureAgentLabels {
		if label == insecure {
			return true
		}
	}

	return false
}

// createFinding creates a finding for insecure agent configuration
func (d *Detection) createFinding(wf *graph.WorkflowNode, job *graph.JobNode) detections.Finding {
	evidence := job.RunsOn
	if evidence == "" {
		evidence = "(no agent label specified)"
	}

	return detections.Finding{
		Type:        detections.VulnSelfHostedRunner,
		Platform:    "jenkins",
		Class:       detections.ClassRunnerSecurity,
		Severity:    detections.SeverityMedium,
		Confidence:  detections.ConfidenceMedium,
		Complexity:  detections.ComplexityMedium,
		Repository:  wf.RepoSlug,
		Workflow:    wf.Name,
		Job:         job.Name,
		Line:        job.Line,
		Trigger:     strings.Join(wf.Triggers, ", "),
		Evidence:    evidence,
		Remediation: "Avoid running builds on the Jenkins controller. Use dedicated agent labels and restrict which agents can run sensitive pipelines.",
	}
}
