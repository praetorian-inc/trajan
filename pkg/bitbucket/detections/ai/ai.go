package ai

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/bitbucket/detections/common"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/aipatterns"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
)

func init() {
	registry.RegisterDetection("bitbucket", "ai-risk", func() detections.Detection {
		return New()
	})
}

// Detection is the AI risk detection for Bitbucket Pipelines.
type Detection struct {
	base.BaseDetection
}

// New creates a new AI risk detection for Bitbucket Pipelines.
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("ai-risk", "bitbucket", detections.SeverityMedium),
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
	if !hasZeroClickTrigger(wf) {
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
		Platform:    "bitbucket",
		Class:       detections.GetVulnerabilityClass(detections.VulnAITokenExfiltration),
		Severity:    detections.SeverityMedium,
		Confidence:  detections.ConfidenceHigh,
		Complexity:  detections.ComplexityLow,
		Repository:  wf.RepoSlug,
		Workflow:    wf.Name,
		Step:        step.Name,
		Line:        step.Line,
		Trigger:     aipatterns.GetTriggerString(wf),
		Evidence:    fmt.Sprintf("AI step '%s' with token access and untrusted input on pull_request trigger", step.Name),
		Remediation: "Avoid passing untrusted input (BITBUCKET_PR_TITLE, etc.) to AI steps with token access. Use separate trusted pipelines or remove token access from AI steps.",
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
		Platform:    "bitbucket",
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
		Remediation: "Avoid passing user-controlled input directly to AI pipes. Validate and sanitize input before use.",
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
	evidence := "AI pipe with MCP indicators"

	if hasToken && hasUntrusted {
		severity = detections.SeverityMedium
		confidence = detections.ConfidenceHigh
		evidence = "AI pipe with MCP enabled, token access, and untrusted input"
	} else if hasToken {
		severity = detections.SeverityLow
		confidence = detections.ConfidenceHigh
		evidence = "AI pipe with MCP enabled and token access"
	}

	return []detections.Finding{{
		Type:        detections.VulnAIMCPAbuse,
		Platform:    "bitbucket",
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
		Remediation: "Disable MCP functionality in AI pipes or ensure access tokens are not provided. If MCP is necessary, restrict to trusted inputs only.",
	}}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func hasZeroClickTrigger(wf *graph.WorkflowNode) bool {
	for _, tag := range wf.Tags() {
		if common.ZeroClickTriggers[tag] {
			return true
		}
	}
	return false
}

func hasTokenAccess(step *graph.StepNode) bool {
	for _, token := range common.DangerousVariables {
		if step.Run != "" && (strings.Contains(step.Run, "$"+token) || strings.Contains(step.Run, "${"+token+"}")) {
			return true
		}
		if step.Env != nil {
			for _, val := range step.Env {
				if strings.Contains(val, "$"+token) || strings.Contains(val, "${"+token+"}") || strings.Contains(val, token) {
					return true
				}
			}
		}
		if step.With != nil {
			for _, val := range step.With {
				if strings.Contains(val, "$"+token) || strings.Contains(val, "${"+token+"}") || strings.Contains(val, token) {
					return true
				}
			}
		}
	}
	return false
}

func hasUntrustedInput(step *graph.StepNode) bool {
	for _, ctx := range common.InjectableContexts {
		if step.Run != "" && (strings.Contains(step.Run, "$"+ctx) || strings.Contains(step.Run, "${"+ctx+"}")) {
			return true
		}
		if step.Env != nil {
			for _, val := range step.Env {
				if strings.Contains(val, "$"+ctx) || strings.Contains(val, "${"+ctx+"}") {
					return true
				}
			}
		}
		if step.With != nil {
			for _, val := range step.With {
				if strings.Contains(val, "$"+ctx) || strings.Contains(val, "${"+ctx+"}") {
					return true
				}
			}
		}
	}
	return false
}
