// Package ai provides a consolidated AI risk detection for GitHub Actions workflows.
// It combines 7 AI-related security checks into a single detection that walks the
// workflow graph once per workflow: token exfiltration, code injection, supply chain
// poisoning, privilege escalation, workflow sabotage, unsafe user access, and MCP abuse.
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
	"github.com/praetorian-inc/trajan/pkg/github/detections/common"
)

func init() {
	registry.RegisterDetection("github", "ai-risk", func() detections.Detection {
		return New()
	})
}

// Detection is the consolidated AI risk detection for GitHub Actions.
type Detection struct {
	base.BaseDetection
}

// New creates a new consolidated AI risk detection.
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("ai-risk", "github", detections.SeverityMedium),
	}
}

// Detect walks each workflow graph once via DFS and runs all 7 AI checks on every
// step that references an AI action.
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)

	for _, wfNode := range workflows {
		wf := wfNode.(*graph.WorkflowNode)
		var currentJob *graph.JobNode

		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			switch node.Type() {
			case graph.NodeTypeJob:
				currentJob = node.(*graph.JobNode)
			case graph.NodeTypeStep:
				if currentJob == nil {
					return true
				}
				step := node.(*graph.StepNode)
				if !aipatterns.IsAIStep(step) {
					return true
				}
				// Run all checks
				findings = append(findings, checkTokenExfiltration(wf, currentJob, step)...)
				findings = append(findings, checkCodeInjection(wf, currentJob, step)...)
				findings = append(findings, checkSupplyChainPoisoning(wf, currentJob, step)...)
				findings = append(findings, checkPrivilegeEscalation(wf, currentJob, step)...)
				findings = append(findings, checkWorkflowSabotage(wf, currentJob, step)...)
				findings = append(findings, checkUnsafeUserAccess(wf, currentJob, step)...)
				findings = append(findings, checkMCPAbuse(wf, step)...)
			}
			return true
		})
	}
	return findings, nil
}

// ---------------------------------------------------------------------------
// Check 1: Token Exfiltration (from aitoken)
// ---------------------------------------------------------------------------

func checkTokenExfiltration(wf *graph.WorkflowNode, job *graph.JobNode, step *graph.StepNode) []detections.Finding {
	// Condition 1: workflow must have AI trigger
	if !hasAITrigger(wf) {
		return nil
	}
	// Condition 2: step must have secret access
	if !hasSecretAccess(step) {
		return nil
	}
	// Condition 3: step must receive untrusted input
	if !hasUntrustedInput(step) {
		return nil
	}

	return []detections.Finding{{
		Type:        detections.VulnAITokenExfiltration,
		Platform:    "github",
		Class:       detections.GetVulnerabilityClass(detections.VulnAITokenExfiltration),
		Severity:    detections.SeverityMedium,
		Confidence:  detections.ConfidenceHigh,
		Complexity:  detections.ComplexityLow,
		Repository:  wf.RepoSlug,
		Workflow:    wf.Name,
		Step:        step.Name,
		Trigger:     aipatterns.GetTriggerString(wf),
		Evidence:    fmt.Sprintf("AI action (%s) with secret access and untrusted input", step.Uses),
		Remediation: "Avoid passing untrusted input (github.event.*.body) to AI actions. Use separate trusted workflows with workflow_run triggers or remove secret access from AI actions.",
	}}
}

// ---------------------------------------------------------------------------
// Check 2: Code Injection (from aicode)
// ---------------------------------------------------------------------------

func checkCodeInjection(wf *graph.WorkflowNode, job *graph.JobNode, step *graph.StepNode) []detections.Finding {
	// Get write permission severity (empty string means no dangerous perms)
	severity := getWritePermissionSeverity(job)
	if severity == detections.Severity("") {
		return nil
	}

	// Check for untrusted input in with/run
	evidence := ""
	if step.With != nil {
		for key, value := range step.With {
			if common.ContainsUntrustedInput(value) {
				evidence = fmt.Sprintf("%s %s with parameter '%s': %s", step.Uses, job.Name, key, value)
				break
			}
		}
	}
	if evidence == "" && step.Run != "" && common.ContainsUntrustedInput(step.Run) {
		evidence = fmt.Sprintf("%s %s run: %s", step.Uses, job.Name, step.Run)
	}
	if evidence == "" {
		return nil
	}

	return []detections.Finding{{
		Type:        detections.VulnAICodeInjection,
		Platform:    "github",
		Class:       detections.GetVulnerabilityClass(detections.VulnAICodeInjection),
		Severity:    severity,
		Confidence:  detections.ConfidenceHigh,
		Complexity:  detections.ComplexityLow,
		Repository:  wf.RepoSlug,
		Workflow:    wf.Name,
		Job:         job.Name,
		Step:        step.Name,
		Line:        step.Line,
		Trigger:     aipatterns.GetTriggerString(wf),
		Evidence:    evidence,
		Remediation: "Avoid passing user-controlled input directly to AI actions. Validate and sanitize input, or use read-only permissions.",
	}}
}

// ---------------------------------------------------------------------------
// Check 3: Supply Chain Poisoning (from aisupply, with bug fix)
// ---------------------------------------------------------------------------

func checkSupplyChainPoisoning(wf *graph.WorkflowNode, job *graph.JobNode, step *graph.StepNode) []detections.Finding {
	// Check for dangerous permissions
	if !hasSupplyChainPermissions(job) {
		return nil
	}

	// Check for untrusted input in step
	if !hasUntrustedInput(step) {
		return nil
	}

	return []detections.Finding{{
		Type:        detections.VulnAISupplyChainPoisoning,
		Platform:    "github",
		Class:       detections.GetVulnerabilityClass(detections.VulnAISupplyChainPoisoning),
		Severity:    detections.SeverityMedium,
		Confidence:  detections.ConfidenceHigh,
		Complexity:  detections.ComplexityZeroClick,
		Repository:  wf.RepoSlug,
		Workflow:    wf.Name,
		Job:         job.Name,
		Step:        step.Name,
		Line:        step.Line,
		Trigger:     aipatterns.GetTriggerString(wf),
		Evidence:    "AI action with write permissions and untrusted input in prompt",
		Remediation: "Remove AI/LLM actions from workflows with write permissions. If needed, use read-only permissions only. Never pass untrusted GitHub contexts (PR body, issue title, comments) to AI actions.",
	}}
}

// hasSupplyChainPermissions checks for packages:write or contents:write.
// BUG FIX: nil permissions now treated as dangerous (GitHub defaults to read+write).
func hasSupplyChainPermissions(job *graph.JobNode) bool {
	if job.Permissions == nil {
		return true // BUG FIX: missing permissions block = dangerous defaults
	}
	for perm, level := range job.Permissions {
		if strings.ToLower(level) != "write" {
			continue
		}
		if perm == "packages" || perm == "contents" {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Check 4: Privilege Escalation (from aipriv)
// ---------------------------------------------------------------------------

func checkPrivilegeEscalation(wf *graph.WorkflowNode, job *graph.JobNode, step *graph.StepNode) []detections.Finding {
	// Must have AI trigger
	if !hasAITrigger(wf) {
		return nil
	}

	// If permissions are nil, there are no explicit admin perms to detect
	if job.Permissions == nil {
		return nil
	}

	// Check for dangerous admin permissions
	dangerousPermissions := map[string]bool{
		"members":                     true,
		"administration":              true,
		"organization_administration": true,
	}

	for perm, level := range job.Permissions {
		if level != "write" {
			continue
		}
		if dangerousPermissions[perm] {
			return []detections.Finding{{
				Type:        detections.VulnAIPrivilegeEscalation,
				Platform:    "github",
				Class:       detections.GetVulnerabilityClass(detections.VulnAIPrivilegeEscalation),
				Severity:    detections.SeverityMedium,
				Confidence:  detections.ConfidenceHigh,
				Complexity:  detections.ComplexityLow,
				Repository:  wf.RepoSlug,
				Workflow:    wf.Name,
				Job:         job.Name,
				Trigger:     aipatterns.GetTriggerString(wf),
				Evidence:    fmt.Sprintf("%s: write on %s trigger with AI action", perm, aipatterns.GetTriggerString(wf)),
				Remediation: fmt.Sprintf("Remove %s: write permission or avoid using AI actions on untrusted triggers (issue_comment, pull_request_target, etc)", perm),
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Check 5: Workflow Sabotage (from aiworkflow)
// ---------------------------------------------------------------------------

func checkWorkflowSabotage(wf *graph.WorkflowNode, job *graph.JobNode, step *graph.StepNode) []detections.Finding {
	// Must have AI trigger
	if !hasAITrigger(wf) {
		return nil
	}

	// Check for actions:write permission
	hasActionsWrite := false
	if job.Permissions == nil {
		hasActionsWrite = true // Missing permissions = dangerous defaults
	} else if perm, ok := job.Permissions["actions"]; ok && perm == "write" {
		hasActionsWrite = true
	}

	if !hasActionsWrite {
		return nil
	}

	// Determine severity by trigger
	trigger := aipatterns.GetTriggerString(wf)
	severity := detections.SeverityLow
	remediation := "Restrict AI action permissions or use more restrictive trigger"

	for _, t := range wf.Triggers {
		if t == "issue_comment" {
			severity = detections.SeverityMedium
			remediation = "Set permissions to read-only: 'permissions: { actions: read }' or use external approval mechanism"
			break
		}
	}

	return []detections.Finding{{
		Type:        detections.VulnAIWorkflowSabotage,
		Platform:    "github",
		Class:       detections.GetVulnerabilityClass(detections.VulnAIWorkflowSabotage),
		Severity:    severity,
		Confidence:  detections.ConfidenceHigh,
		Complexity:  detections.ComplexityLow,
		Repository:  wf.RepoSlug,
		Workflow:    wf.Name,
		Job:         job.Name,
		Step:        step.Name,
		Line:        step.Line,
		Trigger:     trigger,
		Evidence:    fmt.Sprintf("AI action '%s' with actions:write permission on %s trigger", step.Uses, trigger),
		Remediation: remediation,
	}}
}

// ---------------------------------------------------------------------------
// Check 6: Unsafe User Access (Clinejection-style)
// ---------------------------------------------------------------------------

// checkUnsafeUserAccess detects AI actions configured to allow any user to trigger them.
// The Clinejection attack (Feb 2026) exploited allowed_non_write_users: "*" to let
// any GitHub user trigger an AI workflow with full tool access.
func checkUnsafeUserAccess(wf *graph.WorkflowNode, job *graph.JobNode, step *graph.StepNode) []detections.Finding {
	if step.With == nil {
		return nil
	}

	for key, value := range step.With {
		keyLower := strings.ToLower(key)
		// Look for "allowed" + "user" patterns (e.g., allowed_non_write_users, allowed-users)
		if strings.Contains(keyLower, "allowed") && strings.Contains(keyLower, "user") {
			if strings.TrimSpace(value) == "*" {
				return []detections.Finding{{
					Type:        detections.VulnAIWorkflowSabotage,
					Platform:    "github",
					Class:       detections.GetVulnerabilityClass(detections.VulnAIWorkflowSabotage),
					Severity:    detections.SeverityMedium,
					Confidence:  detections.ConfidenceHigh,
					Complexity:  detections.ComplexityZeroClick,
					Repository:  wf.RepoSlug,
					Workflow:    wf.Name,
					Job:         job.Name,
					Step:        step.Name,
					Line:        step.Line,
					Trigger:     aipatterns.GetTriggerString(wf),
					Evidence:    fmt.Sprintf("AI action '%s' configured with %s: \"*\" allowing any user to trigger", step.Uses, key),
					Remediation: "Remove wildcard user access. Restrict AI action triggers to repository collaborators with write permission.",
				}}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Check 7: MCP Abuse (from aimcp)
// ---------------------------------------------------------------------------

func checkMCPAbuse(wf *graph.WorkflowNode, step *graph.StepNode) []detections.Finding {
	// Check for MCP indicators
	if !aipatterns.CheckMCPIndicators(step) {
		return nil
	}

	hasGitHubToken := checkGitHubToken(step)
	hasUntrusted := hasUntrustedInput(step)

	if !hasGitHubToken && !hasUntrusted {
		return nil
	}

	severity := detections.SeverityLow
	confidence := detections.ConfidenceMedium
	evidence := "AI action with MCP indicators"

	if hasGitHubToken && hasUntrusted {
		severity = detections.SeverityMedium
		confidence = detections.ConfidenceHigh
		evidence = "AI action with MCP enabled, GITHUB_TOKEN, and untrusted input"
	} else if hasGitHubToken {
		severity = detections.SeverityLow
		confidence = detections.ConfidenceHigh
		evidence = "AI action with MCP enabled and GITHUB_TOKEN"
	}

	return []detections.Finding{{
		Type:        detections.VulnAIMCPAbuse,
		Platform:    "github",
		Class:       detections.GetVulnerabilityClass(detections.VulnAIMCPAbuse),
		Severity:    severity,
		Confidence:  confidence,
		Complexity:  detections.ComplexityLow,
		Repository:  wf.RepoSlug,
		Workflow:    wf.Name,
		Step:        step.Name,
		Line:        step.Line,
		Trigger:     strings.Join(wf.Triggers, ", "),
		Evidence:    evidence,
		Remediation: "Disable MCP functionality in AI actions or ensure GITHUB_TOKEN is not provided. If MCP is necessary, restrict to trusted inputs only.",
	}}
}

// ---------------------------------------------------------------------------
// Shared helper functions
// ---------------------------------------------------------------------------

// hasAITrigger checks if any workflow trigger allows untrusted input.
func hasAITrigger(wf *graph.WorkflowNode) bool {
	for _, trigger := range wf.Triggers {
		if common.IsAITrigger(trigger) {
			return true
		}
	}
	return false
}

// hasSecretAccess checks if step has access to secrets or tokens.
func hasSecretAccess(step *graph.StepNode) bool {
	if step.Env != nil {
		for _, val := range step.Env {
			if containsSecret(val) {
				return true
			}
		}
	}
	if step.With != nil {
		for _, val := range step.With {
			if containsSecret(val) {
				return true
			}
		}
	}
	return false
}

// containsSecret checks if a value references secrets or GITHUB_TOKEN.
func containsSecret(val string) bool {
	lower := strings.ToLower(val)
	return strings.Contains(lower, "secrets.") || strings.Contains(lower, "github_token")
}

// hasUntrustedInput checks if step receives untrusted input via with/env/run.
func hasUntrustedInput(step *graph.StepNode) bool {
	if step.With != nil {
		for _, val := range step.With {
			if common.ContainsUntrustedInput(val) {
				return true
			}
		}
	}
	if step.Env != nil {
		for _, val := range step.Env {
			if common.ContainsUntrustedInput(val) {
				return true
			}
		}
	}
	if step.Run != "" && common.ContainsUntrustedInput(step.Run) {
		return true
	}
	return false
}

// getWritePermissionSeverity returns severity based on write permissions.
// Returns empty Severity if no dangerous write permissions found.
// Nil permissions = MEDIUM (GitHub defaults to read+write).
func getWritePermissionSeverity(job *graph.JobNode) detections.Severity {
	if job.Permissions == nil {
		return detections.SeverityMedium
	}
	var hasContentsWrite, hasPullRequestsWrite bool
	for perm, level := range job.Permissions {
		if level == "write" {
			switch perm {
			case "contents":
				hasContentsWrite = true
			case "pull-requests":
				hasPullRequestsWrite = true
			}
		}
	}
	if hasContentsWrite {
		return detections.SeverityMedium
	}
	if hasPullRequestsWrite {
		return detections.SeverityMedium
	}
	return ""
}

// checkGitHubToken checks if GITHUB_TOKEN is provided in step env.
func checkGitHubToken(step *graph.StepNode) bool {
	if step.Env == nil {
		return false
	}
	for key, value := range step.Env {
		if strings.ToUpper(key) == "GITHUB_TOKEN" {
			if strings.Contains(value, "secrets.GITHUB_TOKEN") ||
				strings.Contains(value, "github.token") ||
				strings.HasPrefix(value, "$") {
				return true
			}
		}
	}
	return false
}
