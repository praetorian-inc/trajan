package cmdutil

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/detections"
	outputpkg "github.com/praetorian-inc/trajan/pkg/output"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// OutputFindingsJSON outputs scan results with findings as JSON.
func OutputFindingsJSON(result *platforms.ScanResult, findings []detections.Finding) error {
	output := struct {
		Summary struct {
			Repositories int `json:"repositories"`
			Workflows    int `json:"workflows"`
			Findings     int `json:"findings"`
			Errors       int `json:"errors"`
		} `json:"summary"`
		Findings []detections.Finding `json:"findings"`
	}{
		Findings: findings,
	}

	output.Summary.Repositories = len(result.Repositories)
	for _, wfs := range result.Workflows {
		output.Summary.Workflows += len(wfs)
	}
	output.Summary.Findings = len(findings)
	output.Summary.Errors = len(result.Errors)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

// OutputFindingsSARIF outputs scan results in SARIF format.
func OutputFindingsSARIF(result *platforms.ScanResult, findings []detections.Finding) error {
	sarifBytes, err := outputpkg.GenerateSARIF(findings)
	if err != nil {
		return fmt.Errorf("generating SARIF: %w", err)
	}

	_, err = os.Stdout.Write(sarifBytes)
	return err
}

// OutputFindingsHTML outputs scan results in HTML format.
func OutputFindingsHTML(result *platforms.ScanResult, findings []detections.Finding) error {
	htmlBytes, err := outputpkg.GenerateHTML(result, findings)
	if err != nil {
		return fmt.Errorf("generating HTML report: %w", err)
	}
	_, err = os.Stdout.Write(htmlBytes)
	return err
}

// OutputFindingsConsole outputs scan results with findings in table format.
func OutputFindingsConsole(result *platforms.ScanResult, findings []detections.Finding) error {
	fmt.Printf("=== trajan Scan Results ===\n")
	fmt.Printf("Repositories scanned: %d\n", len(result.Repositories))

	workflowCount := 0
	for _, wfs := range result.Workflows {
		workflowCount += len(wfs)
	}
	fmt.Printf("Workflows analyzed: %d\n", workflowCount)
	fmt.Printf("Findings: %d\n", len(findings))

	if len(result.Errors) > 0 {
		fmt.Printf("Errors: %d\n", len(result.Errors))
	}

	if len(findings) == 0 {
		fmt.Println("\nNo vulnerabilities found.")
		return nil
	}

	aggregated := outputpkg.AggregateByRepoWithAllTypes(findings)

	repos := make([]string, 0, len(aggregated))
	for repo := range aggregated {
		repos = append(repos, repo)
	}
	sort.Strings(repos)

	for _, repo := range repos {
		label := repo
		if label == "" {
			label = "(organization-wide)"
		}
		fmt.Printf("\n%s\n", label)
		outputpkg.RenderTable(os.Stdout, aggregated[repo])
	}

	return nil
}

// CountWorkflows returns the total number of workflows across all repositories.
func CountWorkflows(workflows map[string][]platforms.Workflow) int {
	count := 0
	for _, wfs := range workflows {
		count += len(wfs)
	}
	return count
}

// FilterFindingsBySeverity filters findings by exact severity levels.
// Accepts comma-separated severity values (e.g., "critical,high").
func FilterFindingsBySeverity(findings []detections.Finding, severitySpec string) ([]detections.Finding, error) {
	if severitySpec == "" {
		return findings, nil
	}

	severityStrs := strings.Split(severitySpec, ",")
	allowedSeverities := make(map[detections.Severity]bool)

	for _, s := range severityStrs {
		s = strings.TrimSpace(s)
		var sev detections.Severity
		switch s {
		case "critical":
			sev = detections.SeverityCritical
		case "high":
			sev = detections.SeverityHigh
		case "medium":
			sev = detections.SeverityMedium
		case "low":
			sev = detections.SeverityLow
		case "info":
			sev = detections.SeverityInfo
		default:
			return nil, fmt.Errorf("invalid severity level: %s (must be one of: critical, high, medium, low, info)", s)
		}
		allowedSeverities[sev] = true
	}

	filtered := make([]detections.Finding, 0)
	for _, f := range findings {
		if allowedSeverities[f.Severity] {
			filtered = append(filtered, f)
		}
	}

	return filtered, nil
}

// ADOPluginVulnTypes maps each ADO plugin name (as shown by --list) to the
// VulnerabilityType strings that plugin emits. Multiple plugins may share the
// same VulnerabilityType; this map lets --capabilities resolve by plugin name.
var ADOPluginVulnTypes = map[string][]detections.VulnerabilityType{
	"pipeline-injection":      {detections.VulnScriptInjection, detections.VulnTriggerExploitation, detections.VulnDynamicTemplateInjection},
	"secrets-exposure":        {detections.VulnUnredactedSecrets, detections.VulnTokenExposure, detections.VulnPullRequestSecretsExposure},
	"pipeline-access-control": {detections.VulnExcessiveJobPermissions, detections.VulnSecretScopeRisk, detections.VulnEnvironmentBypass},
	"service-connections":     {detections.VulnServiceConnectionHijacking, detections.VulnOverexposedServiceConnections},
	"agent-security":          {detections.VulnSelfHostedAgent},
	"ai-risk":                 {detections.VulnAITokenExfiltration, detections.VulnAICodeInjection, detections.VulnAIMCPAbuse},
}

// GitLabPluginVulnTypes maps each GitLab plugin name (as shown by --list) to the
// VulnerabilityType strings that plugin emits.
var GitLabPluginVulnTypes = map[string][]detections.VulnerabilityType{
	"ai-risk": {detections.VulnAITokenExfiltration, detections.VulnAICodeInjection, detections.VulnAIMCPAbuse},
}

// FilterFindingsByADOCapabilities filters ADO scan findings by capability name.
// Each capability name is resolved to one or more VulnerabilityTypes via
// ADOPluginVulnTypes; as a fallback the spec is also compared directly against
// the finding's Type string so plain VulnerabilityType names still work.
func FilterFindingsByADOCapabilities(findings []detections.Finding, capabilitiesSpec string) ([]detections.Finding, error) {
	if capabilitiesSpec == "" {
		return findings, nil
	}

	allowedTypes := make(map[detections.VulnerabilityType]bool)

	for _, cap := range strings.Split(capabilitiesSpec, ",") {
		cap = strings.TrimSpace(cap)
		if vulnTypes, ok := ADOPluginVulnTypes[cap]; ok {
			for _, vt := range vulnTypes {
				allowedTypes[vt] = true
			}
		} else {
			// Fallback: treat as a direct VulnerabilityType string.
			allowedTypes[detections.VulnerabilityType(cap)] = true
		}
	}

	filtered := make([]detections.Finding, 0)
	for _, f := range findings {
		if allowedTypes[f.Type] {
			filtered = append(filtered, f)
		}
	}

	return filtered, nil
}

// FilterFindingsByCapabilities filters findings by detection type.
// Accepts comma-separated vulnerability type names or plugin names (for GitLab).
func FilterFindingsByCapabilities(findings []detections.Finding, capabilitiesSpec string) ([]detections.Finding, error) {
	if capabilitiesSpec == "" {
		return findings, nil
	}

	capList := strings.Split(capabilitiesSpec, ",")
	allowedCaps := make(map[detections.VulnerabilityType]bool)

	for _, cap := range capList {
		cap = strings.TrimSpace(cap)

		// Check if this is a GitLab plugin name (like "ai-risk")
		if vulnTypes, ok := GitLabPluginVulnTypes[cap]; ok {
			for _, vt := range vulnTypes {
				allowedCaps[vt] = true
			}
		} else {
			// Fallback: treat as a direct VulnerabilityType string
			allowedCaps[detections.VulnerabilityType(cap)] = true
		}
	}

	filtered := make([]detections.Finding, 0)
	for _, f := range findings {
		if allowedCaps[f.Type] {
			filtered = append(filtered, f)
		}
	}

	return filtered, nil
}
