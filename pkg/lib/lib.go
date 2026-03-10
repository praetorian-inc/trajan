// Package lib provides the Trajan SDK for embedding CI/CD security scanning
// as a library. It exposes platform initialization, workflow scanning, and
// detection execution through a public API.
//
// Usage:
//
//	import "github.com/praetorian-inc/trajan/pkg/lib"
//
//	// High-level scan
//	result, err := lib.Scan(ctx, lib.ScanConfig{
//	    Platform:    "github",
//	    Token:       token,
//	    Org:         "myorg",
//	    Repo:        "myrepo",
//	    Concurrency: 10,
//	})
//
//	// Low-level access
//	platform, err := lib.GetPlatform("github")
//	detections := lib.GetDetectionsForPlatform("github")
package lib

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/praetorian-inc/trajan/pkg/scanner"

	// Trigger all platform registrations
	_ "github.com/praetorian-inc/trajan/pkg/platforms/all"

	// Trigger all detection registrations
	_ "github.com/praetorian-inc/trajan/pkg/detections/all"

	// Trigger all attack plugin registrations
	_ "github.com/praetorian-inc/trajan/pkg/attacks/all"
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
}

// ScanResult contains the complete results of a Trajan scan.
type ScanResult struct {
	// Findings are the security vulnerabilities detected.
	Findings []detections.Finding

	// Workflows are the CI/CD workflow files discovered.
	Workflows []platforms.Workflow

	// Errors are non-fatal errors encountered during scanning.
	Errors []error
}

// applyDefaults fills in zero-value fields of cfg with their defaults.
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
// workflow discovery, and detection execution.
func Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	cfg = applyDefaults(cfg)

	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	// Get the platform adapter
	p, err := registry.GetPlatform(cfg.Platform)
	if err != nil {
		return nil, fmt.Errorf("getting platform %s: %w", cfg.Platform, err)
	}

	// Initialize with credentials
	platCfg := platforms.Config{
		Token:       cfg.Token,
		BaseURL:     cfg.BaseURL,
		Concurrency: cfg.Concurrency,
		Timeout:     cfg.Timeout,
	}
	if err := p.Init(ctx, platCfg); err != nil {
		return nil, fmt.Errorf("initializing platform %s: %w", cfg.Platform, err)
	}

	// Build target
	target := platforms.Target{
		Type:  platforms.TargetRepo,
		Value: cfg.Org + "/" + cfg.Repo,
	}
	if cfg.Repo == "" {
		target.Type = platforms.TargetOrg
		target.Value = cfg.Org
	}

	// Scan for workflows
	scanResult, err := p.Scan(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("scanning %s: %w", target.Value, err)
	}

	// Execute detections against the workflow map
	dets := registry.GetDetectionsForPlatform(cfg.Platform)
	executor := scanner.NewDetectionExecutor(dets, cfg.Concurrency)
	execResult, err := executor.Execute(ctx, scanResult.Workflows)
	if err != nil {
		return nil, fmt.Errorf("executing detections: %w", err)
	}

	// Flatten workflows for the result
	var workflows []platforms.Workflow
	for _, wfs := range scanResult.Workflows {
		workflows = append(workflows, wfs...)
	}

	result := &ScanResult{
		Findings:  execResult.Findings,
		Workflows: workflows,
		Errors:    scanResult.Errors,
	}
	// Merge non-fatal detection errors
	result.Errors = append(result.Errors, execResult.Errors...)

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

// AttackConfig holds the configuration for an Attack call.
type AttackConfig struct {
	// Platform is the CI/CD platform name (e.g., "github", "gitlab").
	Platform string

	// Token is the authentication token for the platform API.
	Token string

	// BaseURL is an optional custom base URL for self-hosted instances.
	BaseURL string

	// Org is the organization or owner name.
	Org string

	// Repo is the repository name.
	Repo string

	// Plugins is the list of attack plugin names to execute.
	Plugins []string

	// DryRun simulates attacks without making changes.
	DryRun bool

	// Timeout is the maximum duration for attack execution.
	Timeout time.Duration

	// ExtraOpts contains plugin-specific options (e.g., c2_repo, target_os).
	ExtraOpts map[string]string
}

// AttackResult contains the results of attack plugin execution.
type AttackResult struct {
	Results []attacks.AttackResult
	Errors  []error
}

// Attack executes the specified attack plugins against a CI/CD target.
// It initializes the platform, runs a detection scan to provide findings
// context, then executes each requested plugin.
func Attack(ctx context.Context, cfg AttackConfig) (*AttackResult, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Minute
	}

	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	// Initialize platform
	p, err := registry.GetPlatform(cfg.Platform)
	if err != nil {
		return nil, fmt.Errorf("getting platform %s: %w", cfg.Platform, err)
	}

	platCfg := platforms.Config{
		Token:       cfg.Token,
		BaseURL:     cfg.BaseURL,
		Concurrency: 10,
		Timeout:     cfg.Timeout,
	}
	if err := p.Init(ctx, platCfg); err != nil {
		return nil, fmt.Errorf("initializing platform %s: %w", cfg.Platform, err)
	}

	// Build target
	target := platforms.Target{
		Type:  platforms.TargetRepo,
		Value: cfg.Org + "/" + cfg.Repo,
	}

	// Run detection scan to provide findings context to attack plugins
	scanResult, err := p.Scan(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("scanning %s for attack context: %w", target.Value, err)
	}

	dets := registry.GetDetectionsForPlatform(cfg.Platform)
	executor := scanner.NewDetectionExecutor(dets, 10)
	execResult, err := executor.Execute(ctx, scanResult.Workflows)
	if err != nil {
		return nil, fmt.Errorf("executing detections for attack context: %w", err)
	}

	// Execute each requested attack plugin
	result := &AttackResult{}
	for _, pluginName := range cfg.Plugins {
		plugin, err := registry.GetAttackPluginByName(pluginName)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("plugin %s: %w", pluginName, err))
			continue
		}

		slog.Info("trajan: executing attack plugin",
			"plugin", pluginName,
			"repo", target.Value,
			"dry_run", cfg.DryRun)

		attackResult, err := plugin.Execute(ctx, attacks.AttackOptions{
			Target:    target,
			Platform:  p,
			Findings:  execResult.Findings,
			DryRun:    cfg.DryRun,
			Timeout:   cfg.Timeout,
			ExtraOpts: cfg.ExtraOpts,
		})
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("plugin %s execute: %w", pluginName, err))
			continue
		}

		result.Results = append(result.Results, *attackResult)
	}

	return result, nil
}
