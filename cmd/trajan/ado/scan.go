package ado

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/detections"
	outputpkg "github.com/praetorian-inc/trajan/pkg/output"
	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/praetorian-inc/trajan/pkg/scanner"

	_ "github.com/praetorian-inc/trajan/pkg/detections/all"
	_ "github.com/praetorian-inc/trajan/pkg/platforms/all"
)

var (
	scanRepo        string
	scanOrg         string
	scanConcurrency int
	severity        string
	detailed        bool
	listDetections  bool
	capabilities    string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan Azure DevOps repositories for CI/CD vulnerabilities",
	Long: `Trajan - Azure DevOps - Scan

Scan Azure DevOps Pipelines CI/CD configurations for security vulnerabilities.

Authentication:
  Tokens can be provided via --token flag or environment variables:
    AZURE_DEVOPS_PAT, AZDO_PAT

Targets:
  --org     Azure DevOps organization name or URL
  --repo    Specific repository (project/repo)`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().SortFlags = false
	scanCmd.Flags().StringVar(&scanRepo, "repo", "", "repository to scan (project/repo)")
	scanCmd.Flags().StringVar(&scanOrg, "org", "", "Azure DevOps organization name or URL (e.g., myorg or https://dev.azure.com/myorg)")
	scanCmd.Flags().IntVar(&scanConcurrency, "concurrency", 10, "number of concurrent operations")
	scanCmd.Flags().StringVar(&severity, "severity", "", "comma-separated severity levels to show (critical, high, medium, low, info)")
	scanCmd.Flags().StringVar(&capabilities, "capabilities", "", "comma-separated detection types to run (e.g., pipeline-injection,secrets-exposure)")
	scanCmd.Flags().BoolVar(&detailed, "detailed", false, "show detailed evidence for each finding")
	scanCmd.Flags().BoolVar(&listDetections, "list", false, "list active detection capabilities and exit")
}

func runScan(cmd *cobra.Command, args []string) error {
	if listDetections {
		return listActiveDetections()
	}

	t := getToken(cmd)
	bt := getBearerToken(cmd)
	if t == "" && bt == "" {
		return fmt.Errorf("no token provided (use --token, --azure-bearer-token, or set AZURE_DEVOPS_PAT/AZURE_BEARER_TOKEN)")
	}

	if scanOrg == "" {
		return fmt.Errorf("--org is required")
	}

	// Derive org name and base URL (accept short name or full URL)
	orgName := scanOrg
	var baseURL string
	if strings.HasPrefix(orgName, "https://") || strings.HasPrefix(orgName, "http://") {
		baseURL = orgName
		// Extract short name from URL tail for use as target value
		parts := strings.Split(strings.TrimRight(orgName, "/"), "/")
		orgName = parts[len(parts)-1]
	} else {
		baseURL = fmt.Sprintf("https://dev.azure.com/%s", orgName)
	}

	var target platforms.Target
	switch {
	case scanRepo != "":
		target = platforms.Target{Type: platforms.TargetRepo, Value: scanRepo}
	default:
		target = platforms.Target{Type: platforms.TargetOrg, Value: orgName}
	}

	ctx := context.Background()

	platform, err := registry.GetPlatform("azuredevops")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	config := platforms.Config{
		Token:       t,
		Concurrency: scanConcurrency,
		BaseURL:     baseURL,
		AzureDevOps: &platforms.AzureDevOpsAuth{
			PAT:          t,
			BearerToken:  bt,
			Organization: orgName,
		},
	}
	cmdutil.ApplyProxyFlags(cmd, &config)

	if err := platform.Init(ctx, config); err != nil {
		return fmt.Errorf("initializing platform: %w", err)
	}

	verbose := cmdutil.GetVerbose(cmd)
	if verbose {
		fmt.Fprintf(os.Stderr, "Scanning %s %s...\n", target.Type, target.Value)
	}

	result, err := platform.Scan(ctx, target)
	if err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Found %d repositories, %d workflows\n", len(result.Repositories), cmdutil.CountWorkflows(result.Workflows))

	allPlugins := registry.GetDetections("azuredevops")

	if verbose && len(allPlugins) == 0 {
		fmt.Fprintf(os.Stderr, "Warning: no plugins registered for azuredevops\n")
	}

	fmt.Fprintf(os.Stderr, "Running %d detectors...\n", len(allPlugins))

	executor := scanner.NewDetectionExecutor(allPlugins, scanConcurrency)
	executor.SetMetadata("platform", "azuredevops")
	execResult, err := executor.Execute(ctx, result.Workflows)
	if err != nil {
		return fmt.Errorf("executing plugins: %w", err)
	}

	findings := execResult.Findings

	// Filter findings by capabilities if specified (resolves plugin names to VulnerabilityTypes)
	if capabilities != "" {
		filteredFindings, err := cmdutil.FilterFindingsByADOCapabilities(execResult.Findings, capabilities)
		if err != nil {
			return fmt.Errorf("filtering by capabilities: %w", err)
		}
		findings = filteredFindings
	}

	// Filter findings by severity if specified
	if severity != "" {
		filteredFindings, err := cmdutil.FilterFindingsBySeverity(findings, severity)
		if err != nil {
			return fmt.Errorf("filtering by severity: %w", err)
		}
		findings = filteredFindings
	}

	fmt.Fprintf(os.Stderr, "Analysis complete: %d findings\n", len(findings))

	if len(execResult.Errors) > 0 && verbose {
		fmt.Fprintf(os.Stderr, "Warning: %d errors during plugin execution\n", len(execResult.Errors))
		for _, execErr := range execResult.Errors {
			fmt.Fprintf(os.Stderr, "  - %v\n", execErr)
		}
	}

	output := cmdutil.GetOutput(cmd)
	switch output {
	case "json":
		return cmdutil.OutputFindingsJSON(result, findings)
	case "sarif":
		return cmdutil.OutputFindingsSARIF(result, findings)
	case "html":
		return cmdutil.OutputFindingsHTML(result, findings)
	default:
		if detailed {
			outputpkg.RenderDetailed(os.Stdout, result, findings)
			return nil
		}
		return cmdutil.OutputFindingsConsole(result, findings)
	}
}

// listActiveDetections lists all active detection capabilities
func listActiveDetections() error {
	allPlugins := registry.GetDetections("azuredevops")

	fmt.Printf("Active Azure DevOps Detection Capabilities (%d total):\n\n", len(allPlugins))

	bySeverity := make(map[detections.Severity][]detections.Detection)
	for _, plugin := range allPlugins {
		bySeverity[plugin.Severity()] = append(bySeverity[plugin.Severity()], plugin)
	}

	severities := []detections.Severity{
		detections.SeverityCritical,
		detections.SeverityHigh,
		detections.SeverityMedium,
		detections.SeverityLow,
		detections.SeverityInfo,
	}

	for _, sev := range severities {
		plugins := bySeverity[sev]
		if len(plugins) == 0 {
			continue
		}

		fmt.Printf("[%s] (%d detections)\n", strings.ToUpper(string(sev)), len(plugins))
		for _, p := range plugins {
			fmt.Printf("  • %s\n", p.Name())
		}
		fmt.Println()
	}

	fmt.Println("Usage:")
	fmt.Println("  trajan ado scan --org myorg")
	fmt.Println("  trajan ado scan --org myorg --capabilities pipeline-injection,secrets-exposure")
	fmt.Println("  trajan ado scan --org myorg --severity critical,high")

	return nil
}
