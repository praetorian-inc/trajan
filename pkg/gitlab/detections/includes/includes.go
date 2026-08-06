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

type Detection struct {
	base.BaseDetection
}

func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("include-injection", "gitlab", detections.SeverityHigh),
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

		// Only process root workflows to avoid duplicates
		if !common.IsRootWorkflow(g, wf) {
			continue
		}

		for _, inc := range wf.Includes {
			// Variable interpolation outranks the type-specific checks below.
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
					Type:         detections.VulnIncludeInjection,
					Platform:     "gitlab",
					Class:        detections.GetVulnerabilityClass(detections.VulnIncludeInjection),
					Severity:     detections.SeverityCritical,
					Confidence:   detections.ConfidenceHigh,
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
				continue
			}

			switch inc.Type {
			case "remote":
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

func (d *Detection) hasVariableInterpolation(inc graph.Include) bool {
	fields := []string{inc.Remote, inc.Path, inc.Project, inc.Template}
	for _, field := range fields {
		if containsVariable(field) {
			return true
		}
	}
	return false
}

func containsVariable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '$' {
			if i+1 < len(s) && (isUpperOrUnderscore(s[i+1])) {
				return true
			}
			if i+1 < len(s) && s[i+1] == '{' {
				return true
			}
		}
	}
	return false
}

func isUpperOrUnderscore(b byte) bool {
	return (b >= 'A' && b <= 'Z') || b == '_'
}

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
