package jenkins

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/jenkins"
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
	scanConcurrency int
	jenkinsURL      string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan Jenkins pipelines for security vulnerabilities",
	Long: `Trajan - Jenkins - Scan

Scan Jenkins pipeline definitions for security vulnerabilities.
Checks for script injection, hardcoded credentials, excessive permissions,
insecure agent configurations, and CSRF/anonymous access issues.
Scans a single job (--repo) or all jobs in an instance (default).`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().SortFlags = false
	scanCmd.Flags().StringVar(&scanRepo, "repo", "", "Jenkins job to scan")
	scanCmd.Flags().StringVar(&scanOrg, "org", "", "Jenkins folder/organization to scan")
	scanCmd.Flags().IntVar(&scanConcurrency, "concurrency", 10, "number of concurrent workers")
	scanCmd.Flags().StringVar(&jenkinsURL, "url", "", "Jenkins instance URL (e.g., https://jenkins.example.com)")
}

func runScan(cmd *cobra.Command, args []string) error {
	t := getToken(cmd)
	username := getUsername(cmd)

	// Anonymous access is allowed (no token required)

	if jenkinsURL == "" {
		return fmt.Errorf("must specify --url")
	}

	verbose := cmdutil.GetVerbose(cmd)
	output := cmdutil.GetOutput(cmd)

	var target platforms.Target
	switch {
	case scanRepo != "":
		target = platforms.Target{Type: platforms.TargetRepo, Value: scanRepo}
	case scanOrg != "":
		target = platforms.Target{Type: platforms.TargetOrg, Value: scanOrg}
	default:
		// Default to scanning the entire Jenkins instance
		target = platforms.Target{Type: platforms.TargetOrg, Value: "/"}
	}

	ctx := context.Background()

	platform, err := registry.GetPlatform("jenkins")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	config := platforms.Config{
		Token:       t,
		Concurrency: scanConcurrency,
		Jenkins:     &platforms.JenkinsAuth{Username: username},
	}
	if jenkinsURL != "" {
		config.BaseURL = jenkinsURL
	}
	cmdutil.ApplyProxyFlags(cmd, &config)

	if err := platform.Init(ctx, config); err != nil {
		return fmt.Errorf("initializing platform: %w", err)
	}

	return executeScanAndOutput(ctx, platform, target, verbose, output)
}

// executeScanAndOutput performs vulnerability scan and outputs results.
func executeScanAndOutput(ctx context.Context, platform platforms.Platform, target platforms.Target, verbose bool, output string) error {
	if verbose {
		fmt.Fprintf(os.Stderr, "Scanning %s %s...\n", target.Type, target.Value)
	}

	result, err := platform.Scan(ctx, target)
	if err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Found %d repositories, %d workflows\n", len(result.Repositories), cmdutil.CountWorkflows(result.Workflows))

	allPlugins := registry.GetDetections("jenkins")
	if verbose && len(allPlugins) == 0 {
		fmt.Fprintf(os.Stderr, "Warning: no plugins registered for jenkins\n")
	}

	fmt.Fprintf(os.Stderr, "Running %d detectors...\n", len(allPlugins))

	executor := scanner.NewDetectionExecutor(allPlugins, scanConcurrency)

	// Pass Jenkins client as metadata for live detections
	if jPlatform, ok := platform.(*jenkins.Platform); ok {
		executor.SetInstanceMetadata("jenkins_client", jPlatform.Client())
	}

	execResult, err := executor.Execute(ctx, result.Workflows)
	if err != nil {
		return fmt.Errorf("executing plugins: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Analysis complete: %d findings\n", len(execResult.Findings))

	if len(execResult.Errors) > 0 && verbose {
		fmt.Fprintf(os.Stderr, "Warning: %d errors occurred during plugin execution\n", len(execResult.Errors))
		for _, execErr := range execResult.Errors {
			fmt.Fprintf(os.Stderr, "  - %v\n", execErr)
		}
	}

	switch output {
	case "json":
		return cmdutil.OutputFindingsJSON(result, execResult.Findings)
	case "sarif":
		return cmdutil.OutputFindingsSARIF(result, execResult.Findings)
	case "html":
		return cmdutil.OutputFindingsHTML(result, execResult.Findings)
	default:
		return cmdutil.OutputFindingsConsole(result, execResult.Findings)
	}
}
