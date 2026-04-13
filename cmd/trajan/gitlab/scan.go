package gitlab

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/detections"
	gitlab "github.com/praetorian-inc/trajan/pkg/gitlab"
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
	Short: "Scan GitLab repositories for CI/CD vulnerabilities",
	Long: `Trajan - GitLab CI - Scan

Targets:
  --project   Scan a single project (group/project)
  --group     Scan all projects in a group
  --user      Scan all projects for a user

Authentication:
  Tokens can be provided via --token flag or environment variables:
    GITLAB_TOKEN, GL_TOKEN`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().SortFlags = false
	scanCmd.Flags().StringVar(&scanRepo, "project", "", "project to scan (group/project)")
	scanCmd.Flags().StringVar(&scanRepo, "repo", "", "alias for --project")
	_ = scanCmd.Flags().MarkHidden("repo")
	scanCmd.Flags().StringVar(&scanOrg, "group", "", "group to scan")
	scanCmd.Flags().StringVar(&scanOrg, "org", "", "alias for --group")
	_ = scanCmd.Flags().MarkHidden("org")
	scanCmd.Flags().StringVar(&scanUser, "user", "", "user to scan (all user's projects)")
	scanCmd.Flags().IntVar(&scanConcurrency, "concurrency", 10, "number of concurrent workers")
	scanCmd.Flags().StringVar(&severity, "severity", "", "comma-separated severity levels to show (critical, high, medium, low, info)")
	scanCmd.Flags().StringVar(&capabilities, "capabilities", "", "comma-separated detection types to run (e.g., script_injection,token_exposure)")
	scanCmd.Flags().BoolVar(&detailed, "detailed", false, "show detailed evidence for each finding")
	scanCmd.Flags().BoolVar(&listDetections, "list", false, "list active detection capabilities and exit")
	// NOTE: --url is inherited from the gitlab root command as a persistent flag.
	// Do not redefine it here.
}

func runScan(cmd *cobra.Command, args []string) error {
	// Handle --list flag (list detections and exit)
	if listDetections {
		return listActiveDetections()
	}

	t := getToken(cmd)
	if t == "" {
		return fmt.Errorf("no token provided (use --token or set GITLAB_TOKEN/GL_TOKEN env var)")
	}

	verbose := cmdutil.GetVerbose(cmd)
	output := cmdutil.GetOutput(cmd)

	var target platforms.Target
	switch {
	case scanRepo != "":
		target = platforms.Target{Type: platforms.TargetRepo, Value: scanRepo}
	case scanOrg != "":
		target = platforms.Target{Type: platforms.TargetOrg, Value: scanOrg}
	case scanUser != "":
		target = platforms.Target{Type: platforms.TargetUser, Value: scanUser}
	default:
		return fmt.Errorf("must specify --project, --group, or --user (aliases: --repo, --org)")
	}

	ctx := context.Background()

	platform, err := registry.GetPlatform("gitlab")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	config := platforms.Config{
		Token:       t,
		Concurrency: scanConcurrency,
		GitLab: &platforms.GitLabAuth{
			Token: t,
		},
	}
	if url, _ := cmd.Flags().GetString("url"); url != "" {
		config.BaseURL = url
	}
	cmdutil.ApplyProxyFlags(cmd, &config)

	if err := platform.Init(ctx, config); err != nil {
		return fmt.Errorf("initializing platform: %w", err)
	}

	return executeScanAndOutput(ctx, platform, target, verbose, output, scanConcurrency)
}

// listActiveDetections lists all active detection capabilities
func listActiveDetections() error {
	allPlugins := registry.GetDetections("gitlab")

	fmt.Printf("Active GitLab Detection Capabilities (%d total):\n\n", len(allPlugins))

	// Display detections by severity
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
	fmt.Println("  trajan gitlab scan --repo group/project")
	fmt.Println("  trajan gitlab scan --repo group/project --capabilities script_injection,token_exposure")
	fmt.Println("  trajan gitlab scan --repo group/project --severity critical,high")

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

	allPlugins := registry.GetDetections("gitlab")
	if verbose && len(allPlugins) == 0 {
		fmt.Fprintf(os.Stderr, "Warning: no plugins registered for gitlab\n")
	}

	fmt.Fprintf(os.Stderr, "Running %d detectors...\n", len(allPlugins))

	executor := scanner.NewDetectionExecutor(allPlugins, concurrency)
	executor.SetMetadata("all_workflows", result.Workflows)

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
	if glPlatform, ok := platform.(*gitlab.Platform); ok {
		client := glPlatform.Client()
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
		return cmdutil.OutputFindingsConsole(result, findings)
	}
}
