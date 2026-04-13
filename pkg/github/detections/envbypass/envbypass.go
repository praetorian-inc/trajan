package envbypass

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
	registry.RegisterDetection("github", "environment-bypass", func() detections.Detection {
		return New()
	})
}

type Detection struct {
	base.BaseDetection
}

func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("environment-bypass", "github", detections.SeverityLow),
	}
}

func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	deploymentKeywords := []string{"deploy", "release", "publish", "production", "staging"}

	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)
	for _, wfNode := range workflows {
		wf := wfNode.(*graph.WorkflowNode)

		hasUntrustedTrigger := false
		for _, trigger := range wf.Triggers {
			if trigger == "workflow_dispatch" || trigger == "schedule" {
				hasUntrustedTrigger = true
				break
			}
		}

		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			if node.Type() == graph.NodeTypeJob {
				job := node.(*graph.JobNode)
				isDeploymentJob := false

				if containsKeyword(job.Name, deploymentKeywords) || containsKeyword(job.RunsOn, deploymentKeywords) {
					isDeploymentJob = true
				}

				graph.DFS(g, job.ID(), func(stepNode graph.Node) bool {
					if stepNode.Type() == graph.NodeTypeStep {
						step := stepNode.(*graph.StepNode)
						if step.Run != "" && containsKeyword(step.Run, deploymentKeywords) {
							isDeploymentJob = true
						}
					}
					return true
				})

				if isDeploymentJob {
					hasEnvironment := job.Environment != ""

					if !hasEnvironment {
						// Create line range for the job definition
						var lineRanges []detections.LineRange
						if job.Line > 0 {
							lineRanges = []detections.LineRange{
								{
									Start: job.Line,
									End:   job.Line + 5, // Job definition typically spans several lines
									Label: "deployment job without protection",
								},
							}
						}

						findings = append(findings, detections.Finding{
							Type:       detections.VulnEnvironmentBypass,
							Platform:   "github",
							Class:      detections.GetVulnerabilityClass(detections.VulnEnvironmentBypass),
							Severity:   detections.SeverityLow,
							Confidence: detections.ConfidenceMedium,
							Repository: wf.RepoSlug,
							Workflow:   wf.Path, // Use path for matching
							Job:        job.Name,
							Line:       job.Line,
							Evidence:   fmt.Sprintf("Deployment job '%s' lacks environment protection. This allows deployments without required approvals.", getJobDisplayName(job)),
							Details: &detections.FindingDetails{
								LineRanges: lineRanges,
							},
						})
					}

					if hasUntrustedTrigger {
						// Create line range for the job
						var lineRanges []detections.LineRange
						if job.Line > 0 {
							lineRanges = []detections.LineRange{
								{
									Start: job.Line,
									End:   job.Line + 5,
									Label: "deployment job with manual trigger",
								},
							}
						}

						trigger := ""
						for _, t := range wf.Triggers {
							if t == "workflow_dispatch" || t == "schedule" {
								trigger = t
								break
							}
						}

						findings = append(findings, detections.Finding{
							Type:       detections.VulnEnvironmentBypass,
							Platform:   "github",
							Class:      detections.GetVulnerabilityClass(detections.VulnEnvironmentBypass),
							Severity:   detections.SeverityMedium,
							Confidence: detections.ConfidenceMedium,
							Repository: wf.RepoSlug,
							Workflow:   wf.Path, // Use path for matching
							Job:        job.Name,
							Line:       job.Line,
							Trigger:    trigger,
							Evidence:   fmt.Sprintf("Deployment job '%s' uses %s trigger which bypasses PR review. Environment protection may not prevent unauthorized deployments.", getJobDisplayName(job), trigger),
							Details: &detections.FindingDetails{
								LineRanges: lineRanges,
							},
						})
					}
				}
			}
			return true
		})
	}

	return findings, nil
}

func containsKeyword(text string, keywords []string) bool {
	lower := strings.ToLower(text)
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func getJobDisplayName(job *graph.JobNode) string {
	if job.Name != "" {
		return job.Name
	}
	// Extract just the job name from full ID path (e.g., "repo:job:deploy" → "deploy")
	parts := strings.Split(job.ID(), ":job:")
	if len(parts) > 1 {
		return parts[1]
	}
	return job.ID() // Fallback to full ID
}
