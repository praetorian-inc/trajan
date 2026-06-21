package pipelineaccesscontrol

import (
	"context"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/azuredevops/detections/common"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func init() {
	registry.RegisterDetection(platforms.PlatformAzureDevOps, "pipeline-access-control", func() detections.Detection {
		return New()
	})
}

// Detection detects pipeline access control issues including excessive job permissions,
// variable group scope risks, and missing environment approval gates.
type Detection struct {
	base.BaseDetection
}

// New creates a new pipeline access control detection
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection(
			"pipeline-access-control",
			platforms.PlatformAzureDevOps,
			detections.SeverityLow,
		),
	}
}

// Detect analyzes the graph for pipeline access control vulnerabilities
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding
	for _, node := range g.GetNodesByType(graph.NodeTypeWorkflow) {
		wf, ok := node.(*graph.WorkflowNode)
		if !ok {
			continue
		}
		findings = append(findings, checkJobPermissions(wf, g)...)
		findings = append(findings, checkVariableGroupScope(wf, g)...)
		findings = append(findings, checkEnvironmentGates(wf, g)...)
	}
	return findings, nil
}

// checkJobPermissions checks for jobs running with elevated build/release admin permissions.
func checkJobPermissions(wf *graph.WorkflowNode, g *graph.Graph) []detections.Finding {
	var findings []detections.Finding

	graph.DFS(g, wf.ID(), func(node graph.Node) bool {
		if node.Type() == graph.NodeTypeJob {
			job, ok := node.(*graph.JobNode)
			if !ok {
				return true
			}

			if job.Permissions != nil {
				for perm, level := range job.Permissions {
					permLower := strings.ToLower(perm)
					levelLower := strings.ToLower(level)

					if (permLower == "build" || permLower == "release") && levelLower == "admin" {
						findings = append(findings, detections.Finding{
							Type:        detections.VulnExcessiveJobPermissions,
							Severity:    detections.SeverityLow,
							Confidence:  detections.ConfidenceHigh,
							Complexity:  detections.ComplexityLow,
							Platform:    platforms.PlatformAzureDevOps,
							Class:       detections.ClassPrivilegeEscalation,
							Repository:  wf.RepoSlug,
							Workflow:    wf.Name,
							Job:         job.Name,
							Line:        job.Line,
							Evidence:    "Pipeline running with elevated permissions: " + perm + "=" + level,
							Remediation: "Apply principle of least privilege. Use specific permissions only where needed. Consider using approval gates for sensitive operations.",
							Details: &detections.FindingDetails{
								LineRanges: []detections.LineRange{{
									Start: job.Line,
									End:   job.Line,
									Label: "elevated permissions",
								}},
							},
						})
					}
				}
			}
		}
		return true
	})

	return findings
}

// checkVariableGroupScope checks for variable group references exposed in step environment variables.
func checkVariableGroupScope(wf *graph.WorkflowNode, g *graph.Graph) []detections.Finding {
	var findings []detections.Finding

	graph.DFS(g, wf.ID(), func(node graph.Node) bool {
		if node.Type() == graph.NodeTypeStep {
			step, ok := node.(*graph.StepNode)
			if !ok {
				return true
			}

			for envKey, envValue := range step.Env {
				envValueLower := strings.ToLower(envValue)

				if strings.Contains(envValueLower, "variablegroups") {
					vgLine := common.LineForKey(step.EnvLines, envKey, step.Line)
					findings = append(findings, detections.Finding{
						Type:        detections.VulnSecretScopeRisk,
						Severity:    detections.SeverityLow,
						Confidence:  detections.ConfidenceMedium,
						Complexity:  detections.ComplexityLow,
						Platform:    platforms.PlatformAzureDevOps,
						Class:       detections.ClassPrivilegeEscalation,
						Repository:  wf.RepoSlug,
						Workflow:    wf.Name,
						Step:        step.Name,
						Line:        vgLine,
						Evidence:    "Variable group accessible in environment variables",
						Remediation: "Restrict variable group access. Ensure variable groups are not marked as 'accessible to all pipelines'. Link variable groups explicitly to specific pipelines only.",
						Details: &detections.FindingDetails{
							LineRanges: []detections.LineRange{{
								Start: vgLine,
								End:   vgLine,
								Label: "variable group in env",
							}},
						},
					})
				}
			}
		}
		return true
	})

	return findings
}

// checkEnvironmentGates checks for environment references in steps that lack approval gates.
func checkEnvironmentGates(wf *graph.WorkflowNode, g *graph.Graph) []detections.Finding {
	var findings []detections.Finding

	graph.DFS(g, wf.ID(), func(node graph.Node) bool {
		if node.Type() == graph.NodeTypeStep {
			step, ok := node.(*graph.StepNode)
			if !ok {
				return true
			}

			// Check step.With for environment references (case-insensitive)
			for key := range step.With {
				keyLower := strings.ToLower(key)
				if strings.Contains(keyLower, "environment") {
					eLine := common.LineForKey(step.WithLines, key, step.Line)
					findings = append(findings, detections.Finding{
						Type:        detections.VulnEnvironmentBypass,
						Platform:    platforms.PlatformAzureDevOps,
						Class:       detections.ClassPrivilegeEscalation,
						Severity:    detections.SeverityLow,
						Confidence:  detections.ConfidenceMedium,
						Complexity:  detections.ComplexityLow,
						Repository:  wf.RepoSlug,
						Workflow:    wf.Name,
						Step:        step.Name,
						Line:        eLine,
						Evidence:    "Step references environment without approval gates: " + key,
						Remediation: "Configure approval gates for environments. Add required approvers in Azure DevOps Environment settings to prevent unauthorized deployments.",
						Details: &detections.FindingDetails{
							LineRanges: []detections.LineRange{{
								Start: eLine,
								End:   eLine,
								Label: "environment without gates",
							}},
						},
					})
					break // Only report once per step
				}
			}

			// Check step.Run for environment: YAML patterns
			if step.Run != "" && strings.Contains(strings.ToLower(step.Run), "environment:") {
				envLine := common.ScriptLineForPattern(step, "environment:", false)
				findings = append(findings, detections.Finding{
					Type:        detections.VulnEnvironmentBypass,
					Platform:    platforms.PlatformAzureDevOps,
					Class:       detections.ClassPrivilegeEscalation,
					Severity:    detections.SeverityLow,
					Confidence:  detections.ConfidenceMedium,
					Complexity:  detections.ComplexityLow,
					Repository:  wf.RepoSlug,
					Workflow:    wf.Name,
					Step:        step.Name,
					Line:        envLine,
					Evidence:    "Step contains environment YAML pattern in Run command",
					Remediation: "Configure approval gates for environments. Add required approvers in Azure DevOps Environment settings to prevent unauthorized deployments.",
					Details: &detections.FindingDetails{
						LineRanges: []detections.LineRange{{
							Start: envLine,
							End:   envLine,
							Label: "environment without gates",
						}},
					},
				})
			}
		}
		return true
	})

	return findings
}
