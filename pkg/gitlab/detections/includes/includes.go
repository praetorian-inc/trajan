package includes

import (
	"context"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/gitlab/detections/common"
)

func init() {
	registry.RegisterDetection("gitlab", "include-injection", func() detections.Detection {
		return New()
	})
}

// Detection detects include injection vulnerabilities in GitLab CI
type Detection struct {
	base.BaseDetection
}

// New creates a new include injection detection
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("include-injection", "gitlab", detections.SeverityHigh),
	}
}

// Detect analyzes the graph for include injection vulnerabilities
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	// Get all workflow nodes
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)

	for _, wfNode := range workflows {
		wf := wfNode.(*graph.WorkflowNode)

		// Only process root workflows to avoid duplicates
		if !common.IsRootWorkflow(g, wf) {
			continue
		}

		// Analyze each include for security issues
		for _, inc := range wf.Includes {
			// Check for variable interpolation first (most critical)
			// If found, only report that and skip other checks
			if d.hasVariableInterpolation(inc) {
				evidence := d.getVariableInterpolationEvidence(inc) + ". "
				evidence += "Attacker-controlled variables (e.g., $CI_MERGE_REQUEST_SOURCE_PROJECT_PATH) can load malicious CI templates from attacker-controlled repositories."

				metadata := make(map[string]interface{})
				metadata["includeType"] = inc.Type
				if inc.Project != "" {
					metadata["project"] = inc.Project
				}
				if inc.Remote != "" {
					metadata["remote"] = inc.Remote
				}

				findings = append(findings, detections.Finding{
					Type:        detections.VulnIncludeInjection,
					Platform:    "gitlab",
					Class:       detections.GetVulnerabilityClass(detections.VulnIncludeInjection),
					Severity:    detections.SeverityCritical,
					Confidence:  detections.ConfidenceHigh,
					Repository:   wf.RepoSlug,
					Workflow:     wf.Name,
					WorkflowFile: wf.Path,
					Line:         1,
					Evidence:     evidence,
					Remediation:  "Never use CI variables in include paths. Use static paths only. Variables like $CI_MERGE_REQUEST_* can be controlled by attackers to load malicious CI configurations from their own projects.",
					Details: &detections.FindingDetails{
						LineRanges: []detections.LineRange{{Start: 1, End: 5, Label: "variable interpolation in include"}},
						Metadata:   metadata,
					},
				})
				continue // Skip other checks for this include
			}

			// Check type-specific issues only if no variable interpolation
			switch inc.Type {
			case "remote":
				// CRITICAL: Remote includes from external URLs
				findings = append(findings, detections.Finding{
					Type:        detections.VulnIncludeInjection,
					Platform:    "gitlab",
					Class:       detections.GetVulnerabilityClass(detections.VulnIncludeInjection),
					Severity:    detections.SeverityHigh,
					Confidence:  detections.ConfidenceHigh,
					Repository:  wf.RepoSlug,
					Workflow:    wf.Name,
					Evidence:    "Remote include from: " + inc.Remote,
					Remediation: "Use local or project includes instead of remote URLs. If remote is required, pin to a specific commit hash.",
				})

			case "project":
				// HIGH: Cross-project includes without pinned ref
				if inc.Ref == "" {
					findings = append(findings, detections.Finding{
						Type:        detections.VulnIncludeInjection,
						Platform:    "gitlab",
						Class:       detections.GetVulnerabilityClass(detections.VulnIncludeInjection),
						Severity:    detections.SeverityHigh,
						Confidence:  detections.ConfidenceMedium,
						Repository:  wf.RepoSlug,
						Workflow:    wf.Name,
						Evidence:    "Cross-project include from " + inc.Project + " without pinned ref",
						Remediation: "Pin the include to a specific ref (commit SHA, tag) to prevent supply chain attacks.",
					})
				}
			}
		}
	}

	return findings, nil
}

// hasVariableInterpolation checks if an include uses variable interpolation
func (d *Detection) hasVariableInterpolation(inc graph.Include) bool {
	// Check for $VARIABLE or ${VARIABLE} patterns
	fields := []string{inc.Remote, inc.Path, inc.Project, inc.Template}
	for _, field := range fields {
		if containsVariable(field) {
			return true
		}
	}
	return false
}

// containsVariable checks if a string contains GitLab CI variable syntax
func containsVariable(s string) bool {
	// Check for $VARIABLE pattern
	for i := 0; i < len(s); i++ {
		if s[i] == '$' {
			// Check if followed by uppercase letter or underscore
			if i+1 < len(s) && (isUpperOrUnderscore(s[i+1])) {
				return true
			}
			// Check for ${VARIABLE} pattern
			if i+1 < len(s) && s[i+1] == '{' {
				return true
			}
		}
	}
	return false
}

// isUpperOrUnderscore checks if a byte is an uppercase letter or underscore
func isUpperOrUnderscore(b byte) bool {
	return (b >= 'A' && b <= 'Z') || b == '_'
}

// getVariableInterpolationEvidence returns the evidence string for variable interpolation
func (d *Detection) getVariableInterpolationEvidence(inc graph.Include) string {
	switch inc.Type {
	case "remote":
		return "Variable interpolation in remote include: " + inc.Remote
	case "project":
		return "Variable interpolation in project include: " + inc.Project + "/" + inc.Path
	case "local":
		return "Variable interpolation in local include: " + inc.Path
	case "template":
		return "Variable interpolation in template include: " + inc.Template
	default:
		return "Variable interpolation detected in include"
	}
}
