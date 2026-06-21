package output

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestSeverityToLevel(t *testing.T) {
	tests := []struct {
		name     string
		severity detections.Severity
		expected string
	}{
		{"critical maps to error", detections.SeverityCritical, "error"},
		{"high maps to error", detections.SeverityHigh, "error"},
		{"medium maps to warning", detections.SeverityMedium, "warning"},
		{"low maps to note", detections.SeverityLow, "note"},
		{"info maps to note", detections.SeverityInfo, "note"},
		{"unknown defaults to warning", detections.Severity("unknown"), "warning"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := severityToLevel(tt.severity)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVulnTypeToRuleID(t *testing.T) {
	tests := []struct {
		name     string
		vulnType detections.VulnerabilityType
		platform string
		expected string
	}{
		{"actions_injection_github", detections.VulnActionsInjection, "github", "github/TRAJAN001"},
		{"pwn_request_github", detections.VulnPwnRequest, "github", "github/TRAJAN002"},
		{"review_injection_gitlab", detections.VulnReviewInjection, "gitlab", "gitlab/TRAJAN003"},
		{"toctou_bitbucket", detections.VulnTOCTOU, "bitbucket", "bitbucket/TRAJAN004"},
		{"artifact_poisoning_azuredevops", detections.VulnArtifactPoison, "azuredevops", "azuredevops/TRAJAN005"},
		{"cache_poisoning_github", detections.VulnCachePoisoning, "github", "github/TRAJAN006"},
		{"self_hosted_runner_gitlab", detections.VulnSelfHostedRunner, "gitlab", "gitlab/TRAJAN007"},
		{"self_hosted_agent_azuredevops", detections.VulnSelfHostedAgent, "azuredevops", "azuredevops/TRAJAN007"},
		{"unpinned_action_github", detections.VulnUnpinnedAction, "github", "github/TRAJAN008"},
		{"excessive_permissions_azuredevops", detections.VulnExcessivePermissions, "azuredevops", "azuredevops/TRAJAN009"},
		{"ai_token_exfiltration_github", detections.VulnAITokenExfiltration, "github", "github/TRAJAN010"},
		{"ai_code_injection_gitlab", detections.VulnAICodeInjection, "gitlab", "gitlab/TRAJAN011"},
		{"ai_workflow_sabotage_github", detections.VulnAIWorkflowSabotage, "github", "github/TRAJAN012"},
		{"ai_mcp_abuse_bitbucket", detections.VulnAIMCPAbuse, "bitbucket", "bitbucket/TRAJAN013"},
		{"ai_privilege_escalation_github", detections.VulnAIPrivilegeEscalation, "github", "github/TRAJAN014"},
		{"ai_supply_chain_poisoning_azuredevops", detections.VulnAISupplyChainPoisoning, "azuredevops", "azuredevops/TRAJAN015"},
		{"empty_platform_defaults_to_github", detections.VulnActionsInjection, "", "github/TRAJAN001"},
		{"script_injection_azuredevops", detections.VulnScriptInjection, "azuredevops", "azuredevops/TRAJAN017"},
		{"trigger_exploitation_azuredevops", detections.VulnTriggerExploitation, "azuredevops", "azuredevops/TRAJAN018"},
		{"service_connection_hijacking_azuredevops", detections.VulnServiceConnectionHijacking, "azuredevops", "azuredevops/TRAJAN019"},
		{"overexposed_service_connections_azuredevops", detections.VulnOverexposedServiceConnections, "azuredevops", "azuredevops/TRAJAN020"},
		{"excessive_job_permissions_azuredevops", detections.VulnExcessiveJobPermissions, "azuredevops", "azuredevops/TRAJAN021"},
		{"secret_scope_risk_azuredevops", detections.VulnSecretScopeRisk, "azuredevops", "azuredevops/TRAJAN022"},
		{"environment_bypass_azuredevops", detections.VulnEnvironmentBypass, "azuredevops", "azuredevops/TRAJAN023"},
		{"dynamic_template_injection_azuredevops", detections.VulnDynamicTemplateInjection, "azuredevops", "azuredevops/TRAJAN024"},
		{"pull_request_secrets_exposure_azuredevops", detections.VulnPullRequestSecretsExposure, "azuredevops", "azuredevops/TRAJAN025"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vulnTypeToRuleID(tt.vulnType, tt.platform)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetRuleDescription(t *testing.T) {
	desc := getRuleDescription(detections.VulnActionsInjection)
	assert.Contains(t, desc, "injection")
	assert.NotEmpty(t, desc)
}

func TestGenerateSARIF_EmptyFindings(t *testing.T) {
	findings := []detections.Finding{}

	result, err := GenerateSARIF(findings)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Verify it's valid JSON
	var parsed map[string]interface{}
	err = json.Unmarshal(result, &parsed)
	assert.NoError(t, err)

	// Check SARIF version
	assert.Equal(t, "2.1.0", parsed["version"])

	// Check runs array exists
	runs, ok := parsed["runs"].([]interface{})
	assert.True(t, ok)
	assert.Len(t, runs, 1)
}

func TestGenerateSARIF_SingleFinding(t *testing.T) {
	findings := []detections.Finding{
		{
			Type:        detections.VulnActionsInjection,
			Severity:    detections.SeverityHigh,
			Confidence:  detections.ConfidenceHigh,
			Platform:    "github",
			Repository:  "owner/repo",
			Workflow:    ".github/workflows/ci.yml",
			Job:         "build",
			Step:        "Run tests",
			Line:        42,
			Evidence:    "echo ${{ github.event.issue.title }}",
			Remediation: "Sanitize user input before use in shell commands",
		},
	}

	result, err := GenerateSARIF(findings)
	assert.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(result, &parsed)
	assert.NoError(t, err)

	// Verify tool information
	runs := parsed["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	assert.Equal(t, "trajan", driver["name"])

	// Verify results
	results := run["results"].([]interface{})
	assert.Len(t, results, 1)

	result0 := results[0].(map[string]interface{})
	assert.Equal(t, "github/TRAJAN001", result0["ruleId"])
	assert.Equal(t, "error", result0["level"])
}

func TestGenerateSARIF_MultipleRepositories(t *testing.T) {
	findings := []detections.Finding{
		{
			Type:       detections.VulnActionsInjection,
			Severity:   detections.SeverityHigh,
			Platform:   "github",
			Repository: "owner/repo1",
			Workflow:   ".github/workflows/ci.yml",
			Line:       10,
			Evidence:   "test",
		},
		{
			Type:       detections.VulnPwnRequest,
			Severity:   detections.SeverityCritical,
			Platform:   "github",
			Repository: "owner/repo2",
			Workflow:   ".github/workflows/build.yml",
			Line:       20,
			Evidence:   "test",
		},
	}

	result, err := GenerateSARIF(findings)
	assert.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(result, &parsed)
	assert.NoError(t, err)

	runs := parsed["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})

	// Both findings should be in single run
	assert.Len(t, results, 2)
}

func TestGenerateSARIF_WithProperties(t *testing.T) {
	findings := []detections.Finding{
		{
			Type:       detections.VulnActionsInjection,
			Severity:   detections.SeverityHigh,
			Confidence: detections.ConfidenceHigh,
			Complexity: detections.ComplexityLow,
			Platform:   "github",
			Repository: "owner/repo",
			Workflow:   ".github/workflows/ci.yml",
			Line:       42,
			Evidence:   "test",
		},
	}

	result, err := GenerateSARIF(findings)
	assert.NoError(t, err)

	// Parse and check properties
	var parsed map[string]interface{}
	json.Unmarshal(result, &parsed)

	runs := parsed["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	result0 := results[0].(map[string]interface{})

	props, ok := result0["properties"].(map[string]interface{})
	assert.True(t, ok, "properties should exist")
	assert.Equal(t, "high", props["confidence"])
	assert.Equal(t, "low", props["complexity"])
}

func TestGenerateSARIF_ValidatesSchema(t *testing.T) {
	findings := []detections.Finding{
		{
			Type:       detections.VulnActionsInjection,
			Severity:   detections.SeverityHigh,
			Platform:   "github",
			Repository: "owner/repo",
			Workflow:   ".github/workflows/ci.yml",
			Line:       42,
			Evidence:   "test",
		},
	}

	// GenerateSARIF should validate before returning
	result, err := GenerateSARIF(findings)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestGenerateSARIF_GitHubPlatformPrefix(t *testing.T) {
	findings := []detections.Finding{
		{
			Type:       detections.VulnActionsInjection,
			Severity:   detections.SeverityHigh,
			Platform:   "github",
			Repository: "owner/repo",
			Workflow:   ".github/workflows/ci.yml",
			Line:       10,
			Evidence:   "test",
		},
	}

	result, err := GenerateSARIF(findings)
	assert.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(result, &parsed)
	assert.NoError(t, err)

	runs := parsed["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	result0 := results[0].(map[string]interface{})

	// Rule ID should be prefixed with platform
	assert.Equal(t, "github/TRAJAN001", result0["ruleId"])
}

func TestGenerateSARIF_GitLabPlatformPrefix(t *testing.T) {
	findings := []detections.Finding{
		{
			Type:       detections.VulnIncludeInjection,
			Severity:   detections.SeverityHigh,
			Platform:   "gitlab",
			Repository: "group/project",
			Workflow:   ".gitlab-ci.yml",
			Line:       5,
			Evidence:   "test include injection",
		},
	}

	result, err := GenerateSARIF(findings)
	assert.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(result, &parsed)
	assert.NoError(t, err)

	runs := parsed["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	result0 := results[0].(map[string]interface{})

	// Rule ID should be prefixed with platform
	assert.Equal(t, "gitlab/TRAJAN016", result0["ruleId"])
}

func TestGenerateSARIF_MultiPlatformFindings(t *testing.T) {
	findings := []detections.Finding{
		{
			Type:       detections.VulnActionsInjection,
			Severity:   detections.SeverityHigh,
			Platform:   "github",
			Repository: "owner/repo",
			Workflow:   ".github/workflows/ci.yml",
			Line:       10,
			Evidence:   "github test",
		},
		{
			Type:       detections.VulnIncludeInjection,
			Severity:   detections.SeverityHigh,
			Platform:   "gitlab",
			Repository: "group/project",
			Workflow:   ".gitlab-ci.yml",
			Line:       5,
			Evidence:   "gitlab test",
		},
		{
			Type:       detections.VulnActionsInjection,
			Severity:   detections.SeverityHigh,
			Platform:   "bitbucket",
			Repository: "workspace/repo",
			Workflow:   "bitbucket-pipelines.yml",
			Line:       15,
			Evidence:   "bitbucket test",
		},
		{
			Type:       detections.VulnActionsInjection,
			Severity:   detections.SeverityHigh,
			Platform:   "azuredevops",
			Repository: "project/repo",
			Workflow:   "azure-pipelines.yml",
			Line:       20,
			Evidence:   "azure test",
		},
	}

	result, err := GenerateSARIF(findings)
	assert.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(result, &parsed)
	assert.NoError(t, err)

	runs := parsed["runs"].([]interface{})
	run := runs[0].(map[string]interface{})

	// Should have separate rules for each platform+type combination
	rules := run["tool"].(map[string]interface{})["driver"].(map[string]interface{})["rules"].([]interface{})
	assert.GreaterOrEqual(t, len(rules), 4, "Should have rules for each platform+type")

	results := run["results"].([]interface{})
	assert.Len(t, results, 4)

	// Verify each result has correct platform prefix
	ruleIDs := make([]string, len(results))
	for i, r := range results {
		result := r.(map[string]interface{})
		ruleIDs[i] = result["ruleId"].(string)
	}

	assert.Contains(t, ruleIDs, "github/TRAJAN001")
	assert.Contains(t, ruleIDs, "gitlab/TRAJAN016")
	assert.Contains(t, ruleIDs, "bitbucket/TRAJAN001")
	assert.Contains(t, ruleIDs, "azuredevops/TRAJAN001")
}

func TestGenerateSARIF_EmptyPlatformDefaultsToGitHub(t *testing.T) {
	findings := []detections.Finding{
		{
			Type:       detections.VulnActionsInjection,
			Severity:   detections.SeverityHigh,
			Platform:   "", // Empty platform
			Repository: "owner/repo",
			Workflow:   ".github/workflows/ci.yml",
			Line:       10,
			Evidence:   "test",
		},
	}

	result, err := GenerateSARIF(findings)
	assert.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(result, &parsed)
	assert.NoError(t, err)

	runs := parsed["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	result0 := results[0].(map[string]interface{})

	// Empty platform should default to github
	assert.Equal(t, "github/TRAJAN001", result0["ruleId"])
}
