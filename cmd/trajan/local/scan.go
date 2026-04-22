package local

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/praetorian-inc/trajan/pkg/scanner"

	// Import all platforms to trigger init() registration
	_ "github.com/praetorian-inc/trajan/pkg/platforms/all"

	// All detections (triggers init() registration)
	_ "github.com/praetorian-inc/trajan/pkg/detections/all"
)

var (
	scanPath        string
	scanConcurrency int
	severity        string
	capabilities    string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a local filesystem path for CI/CD workflow vulnerabilities",
	Long: `Trajan - Local - Scan

Scan local CI/CD workflow files for security vulnerabilities.
Walks the filesystem path and auto-detects the CI platform (GitHub Actions,
GitLab CI, Jenkins, Azure Pipelines) based on file naming conventions.`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().SortFlags = false
	scanCmd.Flags().StringVar(&scanPath, "path", "", "filesystem path to scan (file or directory)")
	scanCmd.Flags().IntVar(&scanConcurrency, "concurrency", 10, "number of concurrent workers")
	scanCmd.Flags().StringVar(&severity, "severity", "", "comma-separated severity levels to show (critical, high, medium, low, info)")
	scanCmd.Flags().StringVar(&capabilities, "capabilities", "", "comma-separated detection types to run (e.g., pwn_request,artifact_poisoning)")
}

func runScan(cmd *cobra.Command, args []string) error {
	if scanPath == "" {
		return fmt.Errorf("must specify --path")
	}

	verbose := cmdutil.GetVerbose(cmd)
	output := cmdutil.GetOutput(cmd)

	ctx := context.Background()

	platform, err := registry.GetPlatform("local")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	config := platforms.Config{
		Concurrency: scanConcurrency,
	}
	cmdutil.ApplyProxyFlags(cmd, &config)

	if err := platform.Init(ctx, config); err != nil {
		return fmt.Errorf("initializing platform: %w", err)
	}

	target := platforms.Target{Type: platforms.TargetLocal, Value: scanPath}

	return executeScanAndOutput(ctx, platform, target, verbose, output)
}

// executeScanAndOutput performs vulnerability scan and outputs results.
func executeScanAndOutput(ctx context.Context, platform platforms.Platform, target platforms.Target, verbose bool, output string) error {
	result, err := platform.Scan(ctx, target)
	if err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Found %d repositories, %d workflows\n", len(result.Repositories), cmdutil.CountWorkflows(result.Workflows))

	// Aggregate detections from all registered detection platforms so every
	// discovered workflow file gets the right plugins.
	var allPlugins []detections.Detection
	for _, p := range registry.ListDetectionPlatforms() {
		allPlugins = append(allPlugins, registry.GetDetections(p)...)
	}

	if verbose && len(allPlugins) == 0 {
		fmt.Fprintf(os.Stderr, "Warning: no plugins registered\n")
	}

	fmt.Fprintf(os.Stderr, "Running %d detectors...\n", len(allPlugins))

	executor := scanner.NewDetectionExecutor(allPlugins, scanConcurrency)
	executor.SetMetadata("all_workflows", result.Workflows)

	execResult, err := executor.Execute(ctx, result.Workflows)
	if err != nil {
		return fmt.Errorf("executing plugins: %w", err)
	}

	findings := execResult.Findings
	if capabilities != "" {
		filteredFindings, filterErr := cmdutil.FilterFindingsByCapabilities(execResult.Findings, capabilities)
		if filterErr != nil {
			return fmt.Errorf("filtering by capabilities: %w", filterErr)
		}
		findings = filteredFindings
	}

	if severity != "" {
		filteredFindings, filterErr := cmdutil.FilterFindingsBySeverity(findings, severity)
		if filterErr != nil {
			return fmt.Errorf("filtering by severity: %w", filterErr)
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

	switch output {
	case "json":
		return cmdutil.OutputFindingsJSON(result, findings)
	case "sarif":
		return cmdutil.OutputFindingsSARIF(result, findings)
	case "html":
		return cmdutil.OutputFindingsHTML(result, findings)
	default:
		return cmdutil.OutputFindingsConsole(result, findings)
	}
}
