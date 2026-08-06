// Package output provides output formatting for scan results
package output

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/olekukonko/tablewriter"

	"github.com/praetorian-inc/trajan/pkg/detections"
)

type AggregatedFinding struct {
	Type        detections.VulnerabilityType
	Severity    detections.Severity
	Title       string
	Description string
	Count       int
}

var typeDescriptions = map[detections.VulnerabilityType]string{
	detections.VulnUnpinnedAction:                "Actions using version tags instead of SHA",
	detections.VulnExcessivePermissions:          "Missing or excessive permissions block",
	detections.VulnActionsInjection:              "Potential command injection via context",
	detections.VulnPwnRequest:                    "Pull request target with unsafe checkout",
	detections.VulnReviewInjection:               "Code review trigger with unsafe operations",
	detections.VulnTOCTOU:                        "Time-of-check/time-of-use vulnerability",
	detections.VulnArtifactPoison:                "Artifact poisoning vulnerability",
	detections.VulnCachePoisoning:                "Cache poisoning vulnerability",
	detections.VulnSelfHostedRunner:              "Self-hosted runner security risk",
	detections.VulnSelfHostedAgent:               "Self-hosted agent security risk",
	detections.VulnIncludeInjection:              "GitLab include injection vulnerability",
	detections.VulnMergeRequestUnsafeCheckout:    "Merge request with unsafe code checkout and execution",
	detections.VulnMergeRequestSecretsExposure:   "Secrets accessible in merge request pipelines",
	detections.VulnPullRequestSecretsExposure:    "Secrets accessible in pull request pipelines",
	detections.VulnTokenExposure:                 "Pipeline tokens exposed in untrusted pipeline contexts",
	detections.VulnAITokenExfiltration:           "AI token exfiltration risk",
	detections.VulnAICodeInjection:               "AI code injection vulnerability",
	detections.VulnAIWorkflowSabotage:            "AI workflow sabotage risk",
	detections.VulnAIMCPAbuse:                    "AI MCP abuse vulnerability",
	detections.VulnAIPrivilegeEscalation:         "AI privilege escalation risk",
	detections.VulnAISupplyChainPoisoning:        "AI supply chain poisoning risk",
	detections.VulnOverprovisionedSecrets:        "Job has broader secret access than needed",
	detections.VulnGitHubEnv:                     "Unsafe write to GITHUB_ENV file",
	detections.VulnHardcodedContainerCreds:       "Hardcoded credentials in container config",
	detections.VulnArtipacked:                    "Artifact upload may leak credentials",
	detections.VulnKnownVulnerableActions:        "Action with known security vulnerability",
	detections.VulnImpostorCommit:                "Commit impersonation risk via actions",
	detections.VulnUnsoundContains:               "Unsafe use of contains() in conditions",
	detections.VulnUnsoundCondition:              "Unsound conditional security check",
	detections.VulnUnredactedSecrets:             "Potential secret values exposed in logs",
	detections.VulnSecretsInherit:                "Broad secret inheritance in reusable workflow",
	detections.VulnRefVersionMismatch:            "Git ref and version tag mismatch",
	detections.VulnRefConfusion:                  "Ambiguous git ref resolution risk",
	detections.VulnBotConditions:                 "Insufficient bot actor filtering",
	detections.VulnArchivedUses:                  "Usage of archived/unmaintained action",
	detections.VulnAnonymousDefinition:           "Workflow with missing or anonymous name",
	detections.VulnUseTrustedPublishing:          "Should use trusted publishing for releases",
	detections.VulnUnpinnedImages:                "Container image without digest pin",
	detections.VulnUndocumentedPermissions:       "Permissions not explicitly documented",
	detections.VulnStaleActionRefs:               "Action reference to outdated version",
	detections.VulnObfuscation:                   "Obfuscated or encoded content in workflow",
	detections.VulnMisfeature:                    "Usage of dangerous workflow features",
	detections.VulnInsecureCommands:              "Use of deprecated insecure commands",
	detections.VulnForbiddenUses:                 "Usage of forbidden/blocked actions",
	detections.VulnConcurrencyLimits:             "Missing concurrency limits on workflow",
	detections.VulnSecretScopeRisk:               "Secret accessible beyond intended scope",
	detections.VulnEnvironmentBypass:             "Environment protection bypass risk",
	detections.VulnCompositeActionRisk:           "Composite action with security risk",
	detections.VulnDynamicTemplateInjection:      "Dynamic template injection risk",
	detections.VulnReusableWorkflowRisk:          "Reusable workflow trust boundary risk",
	detections.VulnJenkinsScriptConsole:          "Jenkins script console accessible (RCE risk)",
	detections.VulnJenkinsAnonymousAccess:        "Jenkins allows unauthenticated access",
	detections.VulnJenkinsCSRFDisabled:           "Jenkins CSRF protection is disabled",
	detections.VulnScriptInjection:               "Pipeline script injection via parameter or variable",
	detections.VulnTriggerExploitation:           "Exploitable pipeline trigger configuration",
	detections.VulnExcessiveJobPermissions:       "Job configured with elevated admin permissions",
	detections.VulnServiceConnectionHijacking:    "Dynamic service connection reference allows hijacking",
	detections.VulnOverexposedServiceConnections: "Service connection accessible to all pipelines",
}

func init() {
	for _, vt := range detections.AllVulnerabilityTypes {
		if _, ok := typeDescriptions[vt]; !ok {
			panic(fmt.Sprintf("typeDescriptions missing entry for %s", vt))
		}
	}
}

func getDescription(vulnType detections.VulnerabilityType) string {
	if desc, ok := typeDescriptions[vulnType]; ok {
		return desc
	}
	return string(vulnType)
}

// Lower rank sorts first: critical is 0.
func severityRank(s detections.Severity) int {
	switch s {
	case detections.SeverityCritical:
		return 0
	case detections.SeverityHigh:
		return 1
	case detections.SeverityMedium:
		return 2
	case detections.SeverityLow:
		return 3
	case detections.SeverityInfo:
		return 4
	default:
		return 5
	}
}

func severityColor(s detections.Severity) int {
	switch s {
	case detections.SeverityCritical:
		return tablewriter.FgHiRedColor
	case detections.SeverityHigh:
		return tablewriter.FgRedColor
	case detections.SeverityMedium:
		return tablewriter.FgYellowColor
	case detections.SeverityLow:
		return tablewriter.FgCyanColor
	case detections.SeverityInfo:
		return tablewriter.FgWhiteColor
	default:
		return tablewriter.FgWhiteColor
	}
}

type typeSeverityKey struct {
	Type     detections.VulnerabilityType
	Severity detections.Severity
}

// One row per (type, severity) pair, so a type can appear more than once.
// Despite the name, only types that actually have findings are included.
func AggregateByRepoWithAllTypes(findings []detections.Finding) map[string][]AggregatedFinding {
	byRepo := make(map[string]map[typeSeverityKey][]detections.Finding)
	repos := make(map[string]bool)

	for _, f := range findings {
		repos[f.Repository] = true
		if byRepo[f.Repository] == nil {
			byRepo[f.Repository] = make(map[typeSeverityKey][]detections.Finding)
		}
		key := typeSeverityKey{Type: f.Type, Severity: f.Severity}
		byRepo[f.Repository][key] = append(byRepo[f.Repository][key], f)
	}

	result := make(map[string][]AggregatedFinding)

	for repo := range repos {
		tsMap := byRepo[repo]

		for key, fs := range tsMap {
			result[repo] = append(result[repo], AggregatedFinding{
				Type:        key.Type,
				Severity:    key.Severity,
				Title:       string(key.Type),
				Description: getDescription(key.Type),
				Count:       len(fs),
			})
		}

		sort.Slice(result[repo], func(i, j int) bool {
			ri, rj := severityRank(result[repo][i].Severity), severityRank(result[repo][j].Severity)
			if ri != rj {
				return ri < rj
			}
			return result[repo][i].Title < result[repo][j].Title
		})
	}

	return result
}

func RenderTable(w io.Writer, aggregated []AggregatedFinding) {
	table := tablewriter.NewWriter(w)
	table.SetHeader([]string{"Severity", "Title", "Description", "Count"})

	table.SetBorder(true)
	table.SetRowLine(false)
	table.SetHeaderLine(true)
	table.SetCenterSeparator("+")
	table.SetColumnSeparator("|")
	table.SetRowSeparator("-")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	table.SetColWidth(45)

	table.SetAutoWrapText(false)

	for _, agg := range aggregated {
		color := severityColor(agg.Severity)
		table.Rich([]string{
			strings.ToUpper(string(agg.Severity)),
			agg.Title,
			agg.Description,
			strconv.Itoa(agg.Count),
		}, []tablewriter.Colors{
			{color, tablewriter.Bold},
			{},
			{},
			{},
		})
	}

	table.Render()
}
