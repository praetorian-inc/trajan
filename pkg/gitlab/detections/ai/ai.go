package ai

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/aipatterns"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/gitlab/detections/common"
)

func init() {
	registry.RegisterDetection("gitlab", "ai-risk", func() detections.Detection {
		return New()
	})
}

// Detection is the AI risk detection for GitLab CI.
type Detection struct {
	base.BaseDetection
}

// New creates a new AI risk detection for GitLab CI.
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("ai-risk", "gitlab", detections.SeverityMedium),
	}
}

// Detect walks each workflow graph and runs AI checks on every step.
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)

	for _, wfNode := range workflows {
		wf := wfNode.(*graph.WorkflowNode)

		// Only DFS from root workflows to avoid duplicates
		if !common.IsRootWorkflow(g, wf) {
			continue
		}

		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			if node.Type() != graph.NodeTypeStep {
				return true
			}
			step := node.(*graph.StepNode)
			if !aipatterns.IsAIStep(step) {
				return true
			}
			findings = append(findings, checkTokenExfiltration(g, step)...)
			findings = append(findings, checkCodeInjection(g, step)...)
			findings = append(findings, checkMCPAbuse(g, step)...)
			return true
		})
	}
	return findings, nil
}

// ---------------------------------------------------------------------------
// Check 1: Token Exfiltration
// ---------------------------------------------------------------------------

func checkTokenExfiltration(g *graph.Graph, step *graph.StepNode) []detections.Finding {
	wf := common.GetStepParentWorkflow(g, step)
	if wf == nil {
		return nil
	}

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
		Platform:    "gitlab",
		Class:       detections.GetVulnerabilityClass(detections.VulnAITokenExfiltration),
		Severity:    detections.SeverityMedium,
		Confidence:  detections.ConfidenceHigh,
		Complexity:  detections.ComplexityLow,
		Repository:  wf.RepoSlug,
		Workflow:    wf.Name,
		Step:        step.Name,
		Line:        step.Line,
		Trigger:     aipatterns.GetTriggerString(wf),
		Evidence:    fmt.Sprintf("AI step '%s' with token access and untrusted input", step.Name),
		Remediation: "Avoid passing untrusted input (CI_MERGE_REQUEST_TITLE, etc.) to AI steps with token access. Use separate trusted pipelines or remove token access from AI steps.",
	}}
}

// ---------------------------------------------------------------------------
// Check 2: Code Injection
// ---------------------------------------------------------------------------

func checkCodeInjection(g *graph.Graph, step *graph.StepNode) []detections.Finding {
	wf := common.GetStepParentWorkflow(g, step)
	if wf == nil {
		return nil
	}

	if !hasUntrustedInput(step) {
		return nil
	}

	return []detections.Finding{{
		Type:        detections.VulnAICodeInjection,
		Platform:    "gitlab",
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
		Remediation: "Avoid passing user-controlled input directly to AI steps. Validate and sanitize input before use.",
	}}
}

// ---------------------------------------------------------------------------
// Check 3: MCP Abuse
// ---------------------------------------------------------------------------

func checkMCPAbuse(g *graph.Graph, step *graph.StepNode) []detections.Finding {
	wf := common.GetStepParentWorkflow(g, step)
	if wf == nil {
		return nil
	}

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
	evidence := "AI step with MCP indicators"

	if hasToken && hasUntrusted {
		severity = detections.SeverityMedium
		confidence = detections.ConfidenceHigh
		evidence = "AI step with MCP enabled, token access, and untrusted input"
	} else if hasToken {
		severity = detections.SeverityLow
		confidence = detections.ConfidenceHigh
		evidence = "AI step with MCP enabled and token access"
	}

	return []detections.Finding{{
		Type:        detections.VulnAIMCPAbuse,
		Platform:    "gitlab",
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
		Remediation: "Disable MCP functionality in AI steps or ensure CI tokens are not provided. If MCP is necessary, restrict to trusted inputs only.",
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
	for _, token := range common.DangerousTokenVariables {
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
	}
	return false
}
