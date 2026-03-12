package github

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/github"
	outputpkg "github.com/praetorian-inc/trajan/pkg/output"
	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/praetorian-inc/trajan/pkg/scanner"

	// Import all platforms to trigger init() registration
	_ "github.com/praetorian-inc/trajan/pkg/platforms/all"

	// All detections (triggers init() registration)
	_ "github.com/praetorian-inc/trajan/pkg/detections/all"
)

var (
	scanRepo        string
	scanOrg         string
	scanUser        string
	scanConcurrency int
	severity        string
	detailed        bool
	listDetections  bool
	capabilities    string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan GitHub repositories for CI/CD vulnerabilities",
	Long: `Trajan - GitHub - Scan

Scan GitHub Actions CI/CD configurations for security vulnerabilities.
Analyzes workflow files across a repository, organization, or user for attack
patterns including pwn requests, artifact poisoning, and secrets exfiltration.`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().SortFlags = false
	scanCmd.Flags().StringVar(&scanRepo, "repo", "", "repository to scan (owner/repo)")
	scanCmd.Flags().StringVar(&scanOrg, "org", "", "organization to scan")
	scanCmd.Flags().StringVar(&scanUser, "user", "", "user to scan")
	scanCmd.Flags().IntVar(&scanConcurrency, "concurrency", 10, "number of concurrent workers")
	scanCmd.Flags().StringVar(&severity, "severity", "", "comma-separated severity levels to show (critical, high, medium, low, info)")
	scanCmd.Flags().StringVar(&capabilities, "capabilities", "", "comma-separated detection types to run (e.g., pwn_request,artifact_poisoning)")
	scanCmd.Flags().BoolVar(&detailed, "detailed", false, "show detailed evidence for each finding")
	scanCmd.Flags().BoolVar(&listDetections, "list", false, "list active detection capabilities and exit")
}

func runScan(cmd *cobra.Command, args []string) error {
	// Handle --list flag (list detections and exit)
	if listDetections {
		return listActiveDetections()
	}

	t := getToken(cmd)
	if t == "" {
		return fmt.Errorf("no token provided (use --token or set GH_TOKEN/GITHUB_TOKEN env var)")
	}

	verbose := cmdutil.GetVerbose(cmd)
	output := cmdutil.GetOutput(cmd)

	// Determine target
	var target platforms.Target
	switch {
	case scanRepo != "":
		target = platforms.Target{Type: platforms.TargetRepo, Value: scanRepo}
	case scanOrg != "":
		target = platforms.Target{Type: platforms.TargetOrg, Value: scanOrg}
	case scanUser != "":
		target = platforms.Target{Type: platforms.TargetUser, Value: scanUser}
	default:
		return fmt.Errorf("must specify --repo, --org, or --user")
	}

	ctx := context.Background()

	platform, err := registry.GetPlatform("github")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	config := buildPlatformConfig(t)
	cmdutil.ApplyProxyFlags(cmd, &config)

	if err := platform.Init(ctx, config); err != nil {
		return fmt.Errorf("initializing platform: %w", err)
	}

	return executeScanAndOutput(ctx, platform, target, verbose, output, scanConcurrency)
}

// buildPlatformConfig constructs GitHub platform configuration.
func buildPlatformConfig(token string) platforms.Config {
	return platforms.Config{
		Token:       token,
		Concurrency: scanConcurrency,
	}
}

// listActiveDetections lists all active detection capabilities
func listActiveDetections() error {
	allPlugins := registry.GetDetections("github")

	// Separate AI from core detections
	var corePlugins []detections.Detection
	var aiPlugins []detections.Detection

	for _, plugin := range allPlugins {
		if strings.HasPrefix(plugin.Name(), "ai-") {
			aiPlugins = append(aiPlugins, plugin)
		} else {
			corePlugins = append(corePlugins, plugin)
		}
	}

	fmt.Printf("Active GitHub Detection Capabilities (%d total):\n\n", len(allPlugins))

	// Display core detections by severity
	fmt.Println("=== Core Security Detections ===")

	bySeverity := make(map[detections.Severity][]detections.Detection)
	for _, plugin := range corePlugins {
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

	// Display AI detections separately
	if len(aiPlugins) > 0 {
		fmt.Println("=== AI Security Detections ===")
		fmt.Printf("(%d detections)\n", len(aiPlugins))
		for _, p := range aiPlugins {
			fmt.Printf("  • %s (%s)\n", p.Name(), p.Severity())
		}
		fmt.Println()
	}

	fmt.Println("Usage:")
	fmt.Println("  trajan github scan --repo owner/repo")
	fmt.Println("  trajan github scan --repo owner/repo --capabilities pwn_request,artifact_poisoning")
	fmt.Println("  trajan github scan --repo owner/repo --severity critical,high")

	return nil
}

// executeScanAndOutput performs vulnerability scan and outputs results.
func executeScanAndOutput(ctx context.Context, platform platforms.Platform, target platforms.Target, verbose bool, output string, concurrency int) error {
	if verbose {
		fmt.Fprintf(os.Stderr, "Scanning %s %s...\n", target.Type, target.Value)
	}

	result, err := platform.Scan(ctx, target)
	if err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Found %d repositories, %d workflows\n", len(result.Repositories), cmdutil.CountWorkflows(result.Workflows))

	allPlugins := registry.GetDetections("github")
	if verbose && len(allPlugins) == 0 {
		fmt.Fprintf(os.Stderr, "Warning: no plugins registered for github\n")
	}

	// Create executor
	executor := scanner.NewDetectionExecutor(allPlugins, concurrency)

	// Pass all workflows to executor for cross-workflow analysis (reusable workflow calls)
	executor.SetMetadata("all_workflows", result.Workflows)

	// Enumerate self-hosted runners for double-layer detection
	if ghPlatform, ok := platform.(*github.Platform); ok {
		executor.SetMetadata("github_client", ghPlatform.Client())
		if runnerResult, err := ghPlatform.ScanRunners(ctx, target); err == nil {
			executor.SetMetadata("runners", runnerResult)
		}
		// If enumeration fails, continue without runner metadata
	}

	fmt.Fprintf(os.Stderr, "Running %d detectors...\n", len(allPlugins))
	execResult, err := executor.Execute(ctx, result.Workflows)
	if err != nil {
		return fmt.Errorf("executing plugins: %w", err)
	}

	// Filter findings by capabilities if specified
	findings := execResult.Findings
	if capabilities != "" {
		filteredFindings, err := cmdutil.FilterFindingsByCapabilities(execResult.Findings, capabilities)
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
		fmt.Fprintf(os.Stderr, "Warning: %d errors occurred during plugin execution\n", len(execResult.Errors))
		for _, execErr := range execResult.Errors {
			fmt.Fprintf(os.Stderr, "  - %v\n", execErr)
		}
	}

	// Print rate limit summary
	if ghPlatform, ok := platform.(*github.Platform); ok {
		client := ghPlatform.Client()
		if client != nil {
			rl := client.RateLimiter()
			remaining := rl.Remaining()
			limit := rl.Limit()
			requestsMade := limit - remaining
			fmt.Fprintf(os.Stderr, "\nAPI usage: %d requests made, %d/%d remaining\n", requestsMade, remaining, limit)
		}
	}

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
		return cmdutil.OutputFindingsConsole(result, findings, true)
	}
}
