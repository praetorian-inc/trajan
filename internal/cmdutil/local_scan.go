package cmdutil

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/lib"
	outputpkg "github.com/praetorian-inc/trajan/pkg/output"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// LocalScanConfig drives RunLocalScan. All fields are caller-supplied; the helper
// encapsulates the common lib.Scan → Filter → Output flow used by every
// platform's --path invocation.
type LocalScanConfig struct {
	Platform         string                                                                         // platforms.PlatformGitHub, etc.
	Path             string                                                                         // user-supplied --path value
	Concurrency      int                                                                            // worker count
	Timeout          time.Duration                                                                  // 0 = 5m default (via lib.applyDefaults)
	Capabilities     string                                                                         // --capabilities flag value
	Severity         string                                                                         // --severity flag value
	Detailed         bool                                                                           // --detailed flag value
	Verbose          bool                                                                           // resolved via GetVerbose
	Output           string                                                                         // resolved via GetOutput ("json"|"sarif"|"html"|"")
	CapabilityFilter func(findings []detections.Finding, spec string) ([]detections.Finding, error) // platform-specific capability filter
	WorkflowLabel    string                                                                         // human-readable noun for the verbose log line, e.g. "GitHub workflow", "Jenkins pipeline"
}

// RunLocalScan executes the local-mode scan flow used by every platform CLI:
//  1. lib.Scan (handles Walk → Partition → SetMetadata → Execute internally)
//  2. capability filter (if Capabilities != "")
//  3. severity filter (if Severity != "")
//  4. output dispatch (json/sarif/html/default with --detailed branch)
func RunLocalScan(cfg LocalScanConfig) error {
	result, err := lib.Scan(context.Background(), lib.ScanConfig{
		Platform:    cfg.Platform,
		LocalPath:   cfg.Path,
		Concurrency: cfg.Concurrency,
		Timeout:     cfg.Timeout,
	})
	if err != nil {
		return err
	}

	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "Found %d local %s(s) in %s\n", len(result.Workflows), cfg.WorkflowLabel, cfg.Path)
	}

	if len(result.SkippedDetections) > 0 {
		fmt.Fprintf(os.Stderr, "local mode: skipped %d API-only detection(s): %s\n",
			len(result.SkippedDetections), strings.Join(result.SkippedDetections, ", "))
	}

	findings := result.Findings

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

	if len(result.Errors) > 0 && cfg.Verbose {
		fmt.Fprintf(os.Stderr, "Warning: %d errors during plugin execution\n", len(result.Errors))
		for _, execErr := range result.Errors {
			fmt.Fprintf(os.Stderr, "  - %v\n", execErr)
		}
	}

	pResult := &platforms.ScanResult{
		Workflows: map[string][]platforms.Workflow{"local:" + filepath.Base(cfg.Path): result.Workflows},
		Errors:    result.Errors,
	}

	switch cfg.Output {
	case "json":
		return OutputFindingsJSON(pResult, findings)
	case "sarif":
		return OutputFindingsSARIF(pResult, findings)
	case "html":
		return OutputFindingsHTML(pResult, findings)
	default:
		if cfg.Detailed {
			outputpkg.RenderDetailed(os.Stdout, pResult, findings)
			return nil
		}
		return OutputFindingsConsole(pResult, findings)
	}
}
