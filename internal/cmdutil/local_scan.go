package cmdutil

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/localwalk"
	outputpkg "github.com/praetorian-inc/trajan/pkg/output"
	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/praetorian-inc/trajan/pkg/scanner"
)

// LocalScanConfig drives RunLocalScan. All fields are caller-supplied; the helper
// encapsulates the common Walk → Partition → Execute → Filter → Output flow used by
// every platform's `--local --path` invocation.
type LocalScanConfig struct {
	Platform         string                                                                         // platforms.PlatformGitHub, etc.
	Path             string                                                                         // user-supplied --path value
	Concurrency      int                                                                            // worker count
	Timeout          time.Duration                                                                  // 0 = no timeout (use context.Background())
	Capabilities     string                                                                         // --capabilities flag value
	Severity         string                                                                         // --severity flag value
	Detailed         bool                                                                           // --detailed flag value
	Verbose          bool                                                                           // resolved via GetVerbose
	Output           string                                                                         // resolved via GetOutput ("json"|"sarif"|"html"|"")
	PlatformLabel    string                                                                         // optional executor metadata key value, e.g. "azuredevops"; empty = don't set
	CapabilityFilter func(findings []detections.Finding, spec string) ([]detections.Finding, error) // platform-specific capability filter
	WorkflowLabel    string                                                                         // human-readable noun for the verbose log line, e.g. "GitHub workflow", "Jenkins pipeline"
}

// RunLocalScan executes the local-mode scan flow used by every platform CLI:
//  1. localwalk.Walk
//  2. registry.GetDetectionsForPlatform + detections.PartitionByAPIRequirement
//  3. NewDetectionExecutor + SetMetadata
//  4. Execute
//  5. capability filter (if Capabilities != "")
//  6. severity filter (if Severity != "")
//  7. output dispatch (json/sarif/html/default with --detailed branch)
//
// Returns the same error semantics as the original per-platform runLocalScan
// helpers it replaces (LAB-2079 follow-up).
func RunLocalScan(cfg LocalScanConfig) error {
	repoSlug := "local:" + filepath.Base(cfg.Path)
	workflows, err := localwalk.Walk(cfg.Platform, cfg.Path, repoSlug)
	if err != nil {
		return fmt.Errorf("walking local path: %w", err)
	}

	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "Found %d local %s(s) in %s\n", len(workflows), cfg.WorkflowLabel, cfg.Path)
	}

	allPlugins := registry.GetDetectionsForPlatform(cfg.Platform)
	localRunnable, apiOnly := detections.PartitionByAPIRequirement(allPlugins)

	if len(apiOnly) > 0 {
		fmt.Fprintf(os.Stderr, "local mode: skipped %d API-only detection(s): %s\n",
			len(apiOnly), detections.APIOnlyNames(apiOnly))
	}

	workflowsMap := map[string][]platforms.Workflow{repoSlug: workflows}

	fmt.Fprintf(os.Stderr, "Running %d detectors...\n", len(localRunnable))

	executor := scanner.NewDetectionExecutor(localRunnable, cfg.Concurrency)
	if cfg.PlatformLabel != "" {
		executor.SetMetadata("platform", cfg.PlatformLabel)
	}
	executor.SetMetadata("all_workflows", workflowsMap)

	var ctx context.Context
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), cfg.Timeout)
		defer cancel()
	} else {
		ctx = context.Background()
	}

	execResult, err := executor.Execute(ctx, workflowsMap)
	if err != nil {
		return fmt.Errorf("executing plugins: %w", err)
	}

	findings := execResult.Findings

	if cfg.Capabilities != "" && cfg.CapabilityFilter != nil {
		filteredFindings, err := cfg.CapabilityFilter(findings, cfg.Capabilities)
		if err != nil {
			return fmt.Errorf("filtering by capabilities: %w", err)
		}
		findings = filteredFindings
	}

	if cfg.Severity != "" {
		filteredFindings, err := FilterFindingsBySeverity(findings, cfg.Severity)
		if err != nil {
			return fmt.Errorf("filtering by severity: %w", err)
		}
		findings = filteredFindings
	}

	fmt.Fprintf(os.Stderr, "Analysis complete: %d findings\n", len(findings))

	if len(execResult.Errors) > 0 && cfg.Verbose {
		fmt.Fprintf(os.Stderr, "Warning: %d errors during plugin execution\n", len(execResult.Errors))
		for _, execErr := range execResult.Errors {
			fmt.Fprintf(os.Stderr, "  - %v\n", execErr)
		}
	}

	result := &platforms.ScanResult{Workflows: workflowsMap}

	switch cfg.Output {
	case "json":
		return OutputFindingsJSON(result, findings)
	case "sarif":
		return OutputFindingsSARIF(result, findings)
	case "html":
		return OutputFindingsHTML(result, findings)
	default:
		if cfg.Detailed {
			outputpkg.RenderDetailed(os.Stdout, result, findings)
			return nil
		}
		return OutputFindingsConsole(result, findings)
	}
}
