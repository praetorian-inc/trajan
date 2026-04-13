package ai

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/azuredevops/detections/common"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/aipatterns"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func init() {
	registry.RegisterDetection(platforms.PlatformAzureDevOps, "ai-risk", func() detections.Detection {
		return New()
	})
}

// Detection is the AI risk detection for Azure DevOps Pipelines.
type Detection struct {
	base.BaseDetection
}

// New creates a new AI risk detection for Azure DevOps.
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("ai-risk", platforms.PlatformAzureDevOps, detections.SeverityMedium),
	}
}

// Detect walks each workflow graph and runs AI checks on every step.
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)

	for _, wfNode := range workflows {
		wf := wfNode.(*graph.WorkflowNode)

		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			if node.Type() != graph.NodeTypeStep {
				return true
			}
			step := node.(*graph.StepNode)
			if !aipatterns.IsAIStep(step) {
				return true
			}
			findings = append(findings, checkTokenExfiltration(wf, step)...)
			findings = append(findings, checkCodeInjection(wf, step)...)
			findings = append(findings, checkMCPAbuse(wf, step)...)
			return true
		})
	}
	return findings, nil
}

// ---------------------------------------------------------------------------
// Check 1: Token Exfiltration
// ---------------------------------------------------------------------------

func checkTokenExfiltration(wf *graph.WorkflowNode, step *graph.StepNode) []detections.Finding {
	if !common.HasDangerousTrigger(wf.Triggers) {
		return nil
	}
	if !hasTokenAccess(step) {
		return nil
	}
	if !hasUntrustedInput(step) {
		return nil
	}

	return []detections.Finding{{
		Type:        detections.VulnAITokenExfiltration,
		Platform:    platforms.PlatformAzureDevOps,
		Class:       detections.GetVulnerabilityClass(detections.VulnAITokenExfiltration),
		Severity:    detections.SeverityMedium,
		Confidence:  detections.ConfidenceHigh,
		Complexity:  detections.ComplexityLow,
		Repository:  wf.RepoSlug,
		Workflow:    wf.Name,
		Step:        step.Name,
		Line:        step.Line,
		Trigger:     aipatterns.GetTriggerString(wf),
		Evidence:    fmt.Sprintf("AI step '%s' with SYSTEM_ACCESSTOKEN/PAT access and untrusted input on PR trigger", step.Name),
		Remediation: "Avoid passing untrusted input (Build.SourceVersionMessage, etc.) to AI tasks with token access. Use separate trusted pipelines or remove token access from AI tasks.",
		Details: &detections.FindingDetails{
			LineRanges: []detections.LineRange{{
				Start: step.Line,
				End:   step.Line,
				Label: "AI step with token access",
			}},
		},
	}}
}

// ---------------------------------------------------------------------------
// Check 2: Code Injection
// ---------------------------------------------------------------------------

func checkCodeInjection(wf *graph.WorkflowNode, step *graph.StepNode) []detections.Finding {
	if !hasUntrustedInput(step) {
		return nil
	}

	return []detections.Finding{{
		Type:        detections.VulnAICodeInjection,
		Platform:    platforms.PlatformAzureDevOps,
		Class:       detections.GetVulnerabilityClass(detections.VulnAICodeInjection),
		Severity:    detections.SeverityMedium,
		Confidence:  detections.ConfidenceHigh,
		Complexity:  detections.ComplexityLow,
		Repository:  wf.RepoSlug,
		Workflow:    wf.Name,
		Step:        step.Name,
		Line:        step.Line,
		Trigger:     aipatterns.GetTriggerString(wf),
		Evidence:    fmt.Sprintf("AI step '%s' receives untrusted input", step.Name),
		Remediation: "Avoid passing user-controlled input directly to AI tasks. Validate and sanitize input before use.",
		Details: &detections.FindingDetails{
			LineRanges: []detections.LineRange{{
				Start: step.Line,
				End:   step.Line,
				Label: "AI step with untrusted input",
			}},
		},
	}}
}

// ---------------------------------------------------------------------------
// Check 3: MCP Abuse
// ---------------------------------------------------------------------------

func checkMCPAbuse(wf *graph.WorkflowNode, step *graph.StepNode) []detections.Finding {
	if !aipatterns.CheckMCPIndicators(step) {
		return nil
	}

	hasToken := hasTokenAccess(step)
	hasUntrusted := hasUntrustedInput(step)

	if !hasToken && !hasUntrusted {
		return nil
	}

	severity := detections.SeverityLow
	confidence := detections.ConfidenceMedium
	evidence := "AI task with MCP indicators"

	if hasToken && hasUntrusted {
		severity = detections.SeverityMedium
		confidence = detections.ConfidenceHigh
		evidence = "AI task with MCP enabled, token access, and untrusted input"
	} else if hasToken {
		severity = detections.SeverityLow
		confidence = detections.ConfidenceHigh
		evidence = "AI task with MCP enabled and token access"
	}

	return []detections.Finding{{
		Type:        detections.VulnAIMCPAbuse,
		Platform:    platforms.PlatformAzureDevOps,
		Class:       detections.GetVulnerabilityClass(detections.VulnAIMCPAbuse),
		Severity:    severity,
		Confidence:  confidence,
		Complexity:  detections.ComplexityLow,
		Repository:  wf.RepoSlug,
		Workflow:    wf.Name,
		Step:        step.Name,
		Line:        step.Line,
		Trigger:     aipatterns.GetTriggerString(wf),
		Evidence:    evidence,
		Remediation: "Disable MCP functionality in AI tasks or ensure pipeline tokens are not provided. If MCP is necessary, restrict to trusted inputs only.",
		Details: &detections.FindingDetails{
			LineRanges: []detections.LineRange{{
				Start: step.Line,
				End:   step.Line,
				Label: "AI step with MCP indicators",
			}},
		},
	}}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func hasTokenAccess(step *graph.StepNode) bool {
	if step.Run != "" && common.ContainsDangerousToken(step.Run) {
		return true
	}
	if step.Env != nil {
		for _, val := range step.Env {
			if common.ContainsDangerousToken(val) {
				return true
			}
		}
	}
	return false
}

func hasUntrustedInput(step *graph.StepNode) bool {
	if step.Run != "" && common.ContainsInjectableContext(step.Run) {
		return true
	}
	if step.Env != nil {
		for _, val := range step.Env {
			if common.ContainsInjectableContext(val) {
				return true
			}
		}
	}
	return false
}
