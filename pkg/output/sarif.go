// Package output provides output formatting for scan results
package output

import (
	"bytes"
	"fmt"

	"github.com/owenrumney/go-sarif/v3/pkg/report"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	"github.com/praetorian-inc/trajan/pkg/detections"
)

const (
	toolName    = "trajan"
	toolVersion = "0.1.0"
	toolInfoURI = "https://github.com/praetorian-inc/trajan"
)

// severityToLevel converts Trajan severity to SARIF level
func severityToLevel(s detections.Severity) string {
	switch s {
	case detections.SeverityCritical, detections.SeverityHigh:
		return "error"
	case detections.SeverityMedium:
		return "warning"
	case detections.SeverityLow, detections.SeverityInfo:
		return "note"
	default:
		return "warning"
	}
}

// vulnTypeToRuleID maps vulnerability types to stable SARIF rule IDs with platform prefix
func vulnTypeToRuleID(vt detections.VulnerabilityType, platform string) string {
	// Default to github if platform is empty
	if platform == "" {
		platform = "github"
	}

	ruleIDs := map[detections.VulnerabilityType]string{
		detections.VulnActionsInjection:              "TRAJAN001",
		detections.VulnPwnRequest:                    "TRAJAN002",
		detections.VulnReviewInjection:               "TRAJAN003",
		detections.VulnTOCTOU:                        "TRAJAN004",
		detections.VulnArtifactPoison:                "TRAJAN005",
		detections.VulnCachePoisoning:                "TRAJAN006",
		detections.VulnSelfHostedRunner:              "TRAJAN007",
		detections.VulnSelfHostedAgent:               "TRAJAN007",
		detections.VulnUnpinnedAction:                "TRAJAN008",
		detections.VulnExcessivePermissions:          "TRAJAN009",
		detections.VulnIncludeInjection:              "TRAJAN016",
		detections.VulnAITokenExfiltration:           "TRAJAN010",
		detections.VulnAICodeInjection:               "TRAJAN011",
		detections.VulnAIWorkflowSabotage:            "TRAJAN012",
		detections.VulnAIMCPAbuse:                    "TRAJAN013",
		detections.VulnAIPrivilegeEscalation:         "TRAJAN014",
		detections.VulnAISupplyChainPoisoning:        "TRAJAN015",
		detections.VulnScriptInjection:               "TRAJAN017",
		detections.VulnTriggerExploitation:           "TRAJAN018",
		detections.VulnServiceConnectionHijacking:    "TRAJAN019",
		detections.VulnOverexposedServiceConnections: "TRAJAN020",
		detections.VulnExcessiveJobPermissions:       "TRAJAN021",
		detections.VulnSecretScopeRisk:               "TRAJAN022",
		detections.VulnEnvironmentBypass:             "TRAJAN023",
		detections.VulnDynamicTemplateInjection:      "TRAJAN024",
		detections.VulnPullRequestSecretsExposure:    "TRAJAN025",
	}

	baseID := "TRAJAN000" // Unknown
	if id, ok := ruleIDs[vt]; ok {
		baseID = id
	}

	return platform + "/" + baseID
}

// getRuleDescription returns human-readable description for rule
func getRuleDescription(vt detections.VulnerabilityType) string {
	descriptions := map[detections.VulnerabilityType]string{
		detections.VulnActionsInjection:              "Command injection via GitHub Actions expression context",
		detections.VulnPwnRequest:                    "Dangerous pull_request_target workflow with unsafe checkout",
		detections.VulnReviewInjection:               "Code review trigger enabling malicious code execution",
		detections.VulnTOCTOU:                        "Time-of-check/time-of-use race condition in workflow",
		detections.VulnArtifactPoison:                "Artifact poisoning allowing supply chain attacks",
		detections.VulnCachePoisoning:                "Cache poisoning enabling persistent compromise",
		detections.VulnSelfHostedRunner:              "Self-hosted runner exposure to untrusted code",
		detections.VulnSelfHostedAgent:               "Self-hosted agent exposure to untrusted code",
		detections.VulnUnpinnedAction:                "Unpinned action reference vulnerable to tag hijacking",
		detections.VulnExcessivePermissions:          "Excessive or missing permissions declaration",
		detections.VulnIncludeInjection:              "GitLab include directive vulnerable to injection attacks",
		detections.VulnAITokenExfiltration:           "AI-assisted token exfiltration via prompt injection",
		detections.VulnAICodeInjection:               "AI code generation vulnerable to injection attacks",
		detections.VulnAIWorkflowSabotage:            "AI-enabled workflow sabotage risk",
		detections.VulnAIMCPAbuse:                    "Model Context Protocol abuse vulnerability",
		detections.VulnAIPrivilegeEscalation:         "AI-assisted privilege escalation pathway",
		detections.VulnAISupplyChainPoisoning:        "AI supply chain poisoning via malicious training data",
		detections.VulnScriptInjection:               "Pipeline script injection via parameter or variable",
		detections.VulnTriggerExploitation:           "Exploitable pipeline trigger configuration",
		detections.VulnServiceConnectionHijacking:    "Service connection accessible to untrusted pipelines",
		detections.VulnOverexposedServiceConnections: "Service connection granted access to all pipelines",
		detections.VulnExcessiveJobPermissions:       "Excessive job-level permissions in pipeline",
		detections.VulnSecretScopeRisk:               "Secrets accessible beyond required pipeline scope",
		detections.VulnEnvironmentBypass:             "Environment protection rules bypassed in pipeline",
		detections.VulnDynamicTemplateInjection:      "Dynamic template reference vulnerable to injection",
		detections.VulnPullRequestSecretsExposure:    "Secrets accessible in pull request pipeline context",
	}
	if desc, ok := descriptions[vt]; ok {
		return desc
	}
	return string(vt)
}

// GenerateSARIF converts findings to SARIF format
func GenerateSARIF(findings []detections.Finding) ([]byte, error) {
	rep := report.NewV210Report()
	run := sarif.NewRunWithInformationURI(toolName, toolInfoURI)

	// Register all rules upfront (using platform+type combination as key)
	type ruleKey struct {
		platform string
		vulnType detections.VulnerabilityType
	}
	registeredRules := make(map[ruleKey]bool)

	for _, f := range findings {
		key := ruleKey{platform: f.Platform, vulnType: f.Type}
		if !registeredRules[key] {
			ruleID := vulnTypeToRuleID(f.Type, f.Platform)
			run.AddRule(ruleID).
				WithDescription(getRuleDescription(f.Type)).
				WithHelpURI(toolInfoURI + "/docs/rules/" + ruleID)
			registeredRules[key] = true
		}
	}

	// Add results
	for _, f := range findings {
		ruleID := vulnTypeToRuleID(f.Type, f.Platform)
		level := severityToLevel(f.Severity)

		// Build artifact URI: repo/workflow
		artifactURI := f.Repository + "/" + f.Workflow

		run.AddDistinctArtifact(artifactURI)

		result := run.CreateResultForRule(ruleID).
			WithLevel(level).
			WithMessage(sarif.NewTextMessage(f.Evidence))

		// Add location if we have line info
		if f.Line > 0 {
			result.AddLocation(
				sarif.NewLocationWithPhysicalLocation(
					sarif.NewPhysicalLocation().
						WithArtifactLocation(
							sarif.NewSimpleArtifactLocation(artifactURI),
						).WithRegion(
						sarif.NewSimpleRegion(f.Line, f.Line),
					),
				),
			)
		}

		// Add properties for confidence and complexity
		pb := sarif.NewPropertyBag()
		if f.Confidence != "" {
			pb.Add("confidence", string(f.Confidence))
		}
		if f.Complexity != "" {
			pb.Add("complexity", string(f.Complexity))
		}
		if f.Job != "" {
			pb.Add("job", f.Job)
		}
		if f.Step != "" {
			pb.Add("step", f.Step)
		}
		if f.Remediation != "" {
			pb.Add("remediation", f.Remediation)
		}
		result.WithProperties(pb)
	}

	rep.AddRun(run)

	// Validate before returning
	if err := rep.Validate(); err != nil {
		return nil, fmt.Errorf("SARIF validation failed: %w", err)
	}

	// Write to bytes buffer
	var buf bytes.Buffer
	if err := rep.Write(&buf); err != nil {
		return nil, fmt.Errorf("failed to write SARIF: %w", err)
	}

	return buf.Bytes(), nil
}
