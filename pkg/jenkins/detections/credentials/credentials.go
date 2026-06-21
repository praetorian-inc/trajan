package credentials

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/detections/shared/secrets"
)

func init() {
	registry.RegisterDetection("jenkins", "credentials", func() detections.Detection {
		return New()
	})
}

// Detection detects hardcoded credentials in Jenkins pipeline definitions
type Detection struct {
	base.BaseDetection
	structural *secrets.Detector
}

// New creates a new credentials detection
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("credentials", "jenkins", detections.SeverityHigh),
		structural:    secrets.New(),
	}
}

var (
	// secretPatterns detects hardcoded secrets in pipeline config
	secretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*['"][\w!@#$%^&*()+\-=\[\]{};:,.<>?]{8,}['"]`),
		regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*['"][\w-]{20,}['"]`),
		regexp.MustCompile(`(?i)(secret|token)\s*[=:]\s*['"][\w-]{20,}['"]`),
		regexp.MustCompile(`(?i)(access[_-]?key)\s*[=:]\s*['"][A-Z0-9]{16,}['"]`),
	}
)

// Detect finds hardcoded credentials in the workflow graph
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

				// Check run commands — keyword patterns first, then structural
				if step.Run != "" {
					if containsHardcodedSecret(step.Run) {
						findings = append(findings, d.createFinding(wf, step, step.Run))
					} else {
						findings = append(findings, d.detectStructural(wf, step, step.Run, "run command")...)
					}
				}

				// Check environment variables
				for key, value := range step.Env {
					if containsHardcodedSecret(value) {
						findings = append(findings, d.createEnvFinding(wf, step, key, value))
					} else {
						findings = append(findings, d.detectStructural(wf, step, value, key)...)
					}
				}

				// Check With parameters
				for key, value := range step.With {
					if containsHardcodedSecret(value) {
						findings = append(findings, d.createWithFinding(wf, step, key, value))
					} else {
						findings = append(findings, d.detectStructural(wf, step, value, key)...)
					}
				}
			}
			return true
		})
	}

	return findings, nil
}

// containsHardcodedSecret checks if a string contains hardcoded secret patterns
func containsHardcodedSecret(s string) bool {
	for _, pattern := range secretPatterns {
		if pattern.MatchString(s) {
			return true
		}
	}
	return false
}

// detectStructural runs the shared secrets detector on a value and returns findings
// for high-confidence structural matches only.
func (d *Detection) detectStructural(wf *graph.WorkflowNode, step *graph.StepNode, value, source string) []detections.Finding {
	var findings []detections.Finding
	matches := d.structural.DetectSecretPattern(value)
	for _, m := range matches {
		if m.Confidence != detections.ConfidenceHigh {
			continue // Skip medium/low confidence to avoid false positives
		}
		findings = append(findings, detections.Finding{
			Type:        detections.VulnHardcodedContainerCreds,
			Platform:    "jenkins",
			Class:       detections.ClassSecretsExposure,
			Severity:    detections.SeverityHigh,
			Confidence:  m.Confidence,
			Complexity:  detections.ComplexityLow,
			Repository:  wf.RepoSlug,
			Workflow:    wf.Name,
			Step:        step.Name,
			Line:        step.Line,
			Trigger:     strings.Join(wf.Triggers, ", "),
			Evidence:    m.Location,
			Remediation: fmt.Sprintf("Remove hardcoded %s from %s in Jenkinsfile. Use Jenkins credentials plugin with credentials() binding or withCredentials block.", m.Pattern, source),
		})
	}
	return findings
}

// createFinding creates a finding for hardcoded secret in run command
func (d *Detection) createFinding(wf *graph.WorkflowNode, step *graph.StepNode, evidence string) detections.Finding {
	return detections.Finding{
		Type:        detections.VulnHardcodedContainerCreds,
		Platform:    "jenkins",
		Class:       detections.ClassSecretsExposure,
		Severity:    detections.SeverityHigh,
		Confidence:  detections.ConfidenceHigh,
		Complexity:  detections.ComplexityLow,
		Repository:  wf.RepoSlug,
		Workflow:    wf.Name,
		Step:        step.Name,
		Line:        step.Line,
		Trigger:     strings.Join(wf.Triggers, ", "),
		Evidence:    evidence,
		Remediation: "Remove hardcoded credentials from Jenkinsfile. Use Jenkins credentials plugin with credentials() binding or withCredentials block.",
	}
}

// createEnvFinding creates a finding for hardcoded secret in environment variable
func (d *Detection) createEnvFinding(wf *graph.WorkflowNode, step *graph.StepNode, key, value string) detections.Finding {
	return detections.Finding{
		Type:        detections.VulnHardcodedContainerCreds,
		Platform:    "jenkins",
		Class:       detections.ClassSecretsExposure,
		Severity:    detections.SeverityHigh,
		Confidence:  detections.ConfidenceHigh,
		Complexity:  detections.ComplexityLow,
		Repository:  wf.RepoSlug,
		Workflow:    wf.Name,
		Step:        step.Name,
		Line:        step.Line,
		Trigger:     strings.Join(wf.Triggers, ", "),
		Evidence:    key + "=" + value,
		Remediation: "Remove hardcoded secret from environment variable '" + key + "'. Use Jenkins credentials plugin with credentials() binding.",
	}
}

// createWithFinding creates a finding for hardcoded secret in with parameter
func (d *Detection) createWithFinding(wf *graph.WorkflowNode, step *graph.StepNode, key, value string) detections.Finding {
	return detections.Finding{
		Type:        detections.VulnHardcodedContainerCreds,
		Platform:    "jenkins",
		Class:       detections.ClassSecretsExposure,
		Severity:    detections.SeverityHigh,
		Confidence:  detections.ConfidenceHigh,
		Complexity:  detections.ComplexityLow,
		Repository:  wf.RepoSlug,
		Workflow:    wf.Name,
		Step:        step.Name,
		Line:        step.Line,
		Trigger:     strings.Join(wf.Triggers, ", "),
		Evidence:    key + "=" + value,
		Remediation: "Remove hardcoded secret from parameter '" + key + "'. Use Jenkins credentials plugin with credentials() binding.",
	}
}
