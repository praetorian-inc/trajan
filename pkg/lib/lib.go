// Package lib is the Trajan SDK for embedding CI/CD security scanning: platform
// initialization, workflow discovery, and detection execution.
package lib

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/localwalk"
	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/praetorian-inc/trajan/pkg/scanner"

	_ "github.com/praetorian-inc/trajan/pkg/platforms/all"

	_ "github.com/praetorian-inc/trajan/pkg/detections/all"
)

// ScanConfig holds the configuration for a Scan call.
type ScanConfig struct {
	// Platform is the CI/CD platform name (e.g., "github", "gitlab", "jenkins").
	Platform string

	// Token is the authentication token for the platform API.
	Token string

	// BaseURL is an optional custom base URL for self-hosted instances.
	BaseURL string

	// Org is the organization or owner name.
	Org string

	// Repo is the repository name. If empty, scans all repos in the org.
	Repo string

	// Concurrency controls parallel detection execution (default: 10).
	Concurrency int

	// Timeout is the maximum duration for the scan (default: 5 minutes).
	Timeout time.Duration

	// LocalPath, if set, scans this filesystem path for the Platform's workflow
	// files instead of the platform API; Org/Repo/Token/BaseURL are ignored.
	LocalPath string
}

// ScanResult contains the complete results of a Trajan scan.
type ScanResult struct {
	// Findings are the security vulnerabilities detected.
	Findings []detections.Finding

	// Workflows are the CI/CD workflow files discovered.
	Workflows []platforms.Workflow

	// Errors are non-fatal errors encountered during scanning.
	Errors []error

	// SkippedDetections names the API-requiring detections a LocalPath scan could
	// not run. Always empty in API-mode scans.
	SkippedDetections []string
}

func applyDefaults(cfg ScanConfig) ScanConfig {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Minute
	}
	return cfg
}

// Scan performs a complete CI/CD security scan: platform initialization,
// workflow discovery, and detection execution. With cfg.LocalPath set it reads
// the filesystem instead of the platform API and skips API-only detections.
func Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	cfg = applyDefaults(cfg)

	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	if cfg.LocalPath != "" {
		return scanLocal(ctx, cfg)
	}

	p, err := registry.GetPlatform(cfg.Platform)
	if err != nil {
		return nil, fmt.Errorf("getting platform %s: %w", cfg.Platform, err)
	}

	platCfg := platforms.Config{
		Token:       cfg.Token,
		BaseURL:     cfg.BaseURL,
		Concurrency: cfg.Concurrency,
		Timeout:     cfg.Timeout,
	}
	if err := p.Init(ctx, platCfg); err != nil {
		return nil, fmt.Errorf("initializing platform %s: %w", cfg.Platform, err)
	}

	target := platforms.Target{
		Type:  platforms.TargetRepo,
		Value: cfg.Org + "/" + cfg.Repo,
	}
	if cfg.Repo == "" {
		target.Type = platforms.TargetOrg
		target.Value = cfg.Org
	}

	scanResult, err := p.Scan(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("scanning %s: %w", target.Value, err)
	}

	dets := registry.GetDetectionsForPlatform(cfg.Platform)
	executor := scanner.NewDetectionExecutor(dets, cfg.Concurrency)
	execResult, err := executor.Execute(ctx, scanResult.Workflows)
	if err != nil {
		return nil, fmt.Errorf("executing detections: %w", err)
	}

	var workflows []platforms.Workflow
	for _, wfs := range scanResult.Workflows {
		workflows = append(workflows, wfs...)
	}

	result := &ScanResult{
		Findings:  execResult.Findings,
		Workflows: workflows,
		Errors:    scanResult.Errors,
	}
	result.Errors = append(result.Errors, execResult.Errors...)

	return result, nil
}

func scanLocal(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	if cfg.Platform == "" {
		return nil, fmt.Errorf("local scan requires Platform to be set")
	}
	if !localwalk.IsSupported(cfg.Platform) {
		supported := localwalk.SupportedPlatforms()
		return nil, fmt.Errorf("local scanning not supported for platform %q (supported: %s)",
			cfg.Platform, strings.Join(supported, ", "))
	}

	repoSlug := "local:" + filepath.Base(cfg.LocalPath)
	workflows, err := localwalk.Walk(cfg.Platform, cfg.LocalPath, repoSlug)
	if err != nil {
		return nil, fmt.Errorf("walking local path: %w", err)
	}

	allPlugins := registry.GetDetectionsForPlatform(cfg.Platform)
	localRunnable, apiOnly := detections.PartitionByAPIRequirement(allPlugins)

	workflowsMap := map[string][]platforms.Workflow{repoSlug: workflows}

	executor := scanner.NewDetectionExecutor(localRunnable, cfg.Concurrency)
	executor.SetMetadata("platform", cfg.Platform)
	executor.SetMetadata("all_workflows", workflowsMap)
	execResult, err := executor.Execute(ctx, workflowsMap)
	if err != nil {
		return nil, fmt.Errorf("executing detections: %w", err)
	}

	skippedNames := make([]string, len(apiOnly))
	for i, d := range apiOnly {
		skippedNames[i] = d.Name()
	}

	result := &ScanResult{
		Findings:          execResult.Findings,
		Workflows:         workflows,
		SkippedDetections: skippedNames,
	}
	result.Errors = append(result.Errors, execResult.Errors...)

	slog.Debug("trajan: local scan complete",
		"platform", cfg.Platform,
		"path", cfg.LocalPath,
		"workflows", len(workflows),
		"findings", len(result.Findings))

	return result, nil
}

// GetPlatform returns a new instance of the named platform adapter.
// Valid names: "github", "gitlab", "azuredevops", "bitbucket", "jenkins", "jfrog".
func GetPlatform(name string) (platforms.Platform, error) {
	return registry.GetPlatform(name)
}

// ListPlatforms returns all registered platform names.
func ListPlatforms() []string {
	return registry.ListPlatforms()
}

// GetDetections returns detection instances for a specific platform.
func GetDetections(platform string) []detections.Detection {
	return registry.GetDetections(platform)
}

// GetDetectionsForPlatform returns detections for a platform plus
// cross-platform ("all") detections.
func GetDetectionsForPlatform(platform string) []detections.Detection {
	return registry.GetDetectionsForPlatform(platform)
}

// ListDetectionPlatforms returns all platforms with registered detections.
func ListDetectionPlatforms() []string {
	return registry.ListDetectionPlatforms()
}
