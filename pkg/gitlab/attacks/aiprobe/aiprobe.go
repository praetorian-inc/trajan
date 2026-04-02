package aiprobe

import (
	"context"
	"fmt"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/audit"
	"github.com/praetorian-inc/trajan/pkg/attacks/base"
	sharedaiprobe "github.com/praetorian-inc/trajan/pkg/attacks/shared/aiprobe"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/gitlab"
	"github.com/praetorian-inc/trajan/pkg/gitlab/attacks/common"
)

func init() {
	registry.RegisterAttackPlugin("gitlab", "ai-probe", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements AI service endpoint probing for GitLab repositories.
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new AI probe attack plugin for GitLab.
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"ai-probe",
			"Probe AI service endpoints discovered in GitLab CI/CD pipelines",
			"gitlab",
			attacks.CategoryRecon,
		),
	}
}

// aiVulnTypes lists all AI-related vulnerability types that trigger this plugin.
// Uses shared constant to stay consistent with other platforms and future-proof
// for additional GitLab AI detection types.
var aiVulnTypes = detections.AIVulnTypes

// CanAttack returns true if any AI-related vulnerability was found.
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	for _, vt := range aiVulnTypes {
		if common.FindingHasType(findings, vt) {
			return true
		}
	}
	return false
}

// Execute fetches pipeline YAML, extracts AI endpoints, and probes them with Julius.
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	audit.LogAttackStart(opts.SessionID, p.Name(), opts.Target, opts.DryRun)

	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
		Repo:      opts.Target.Value,
	}

	// Get GitLab client
	glPlatform, ok := opts.Platform.(*gitlab.Platform)
	if !ok {
		result.Success = false
		result.Message = "platform is not GitLab"
		return result, fmt.Errorf("invalid platform type")
	}
	client := glPlatform.Client()

	// Parse project path from target
	projectPath := opts.Target.Value

	// Get project metadata
	project, err := client.GetProject(ctx, projectPath)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get project: %v", err)
		return result, err
	}

	projectID := project.ID
	defaultBranch := project.DefaultBranch
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	// Fetch .gitlab-ci.yml
	content, err := client.GetWorkflowFile(ctx, projectID, ".gitlab-ci.yml", defaultBranch)
	if err != nil {
		// 404 is not an error - just means no CI file exists
		if gitlab.IsNotFoundError(err) {
			result.Success = true
			result.Message = "[DRY RUN] Discovered 0 AI service endpoint(s) across 0 CI file(s)"
			result.Data = &sharedaiprobe.ScanResults{
				Endpoints: []sharedaiprobe.DiscoveredEndpoint{},
				Summary: sharedaiprobe.ScanSummary{
					EndpointsDiscovered: 0,
				},
			}
			return result, nil
		}
		result.Success = false
		result.Message = fmt.Sprintf("failed to fetch .gitlab-ci.yml: %v", err)
		return result, err
	}

	// Extract AI endpoints
	endpoints := sharedaiprobe.ExtractEndpoints(content, ".gitlab-ci.yml")
	endpoints = sharedaiprobe.DeduplicateEndpoints(endpoints)

	// Dry run: return discovered endpoints without probing
	if opts.DryRun {
		result.Success = true
		result.Message = fmt.Sprintf("[DRY RUN] Discovered %d AI service endpoint(s) across 1 CI file(s)", len(endpoints))
		result.Data = &sharedaiprobe.ScanResults{
			Endpoints: endpoints,
			Summary: sharedaiprobe.ScanSummary{
				EndpointsDiscovered: len(endpoints),
			},
		}

		// Print discovered endpoints
		if len(endpoints) > 0 {
			fmt.Println("\n=== Discovered AI Endpoints ===")
			for _, ep := range endpoints {
				fmt.Printf("\n%s\n", ep.URL)
				fmt.Printf("  Source: %s\n", ep.Source)
				fmt.Printf("  Confidence: %s\n", ep.Confidence)
				fmt.Printf("  Workflow: %s\n", ep.Workflow)
			}
			fmt.Println()
		}

		return result, nil
	}

	// Active probing
	scanConfig := sharedaiprobe.DefaultScanConfig()
	scanResults, err := sharedaiprobe.ProbeEndpoints(ctx, endpoints, scanConfig)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("probe failed: %v", err)
		return result, err
	}

	result.Success = true
	result.Message = fmt.Sprintf("Probed %d endpoint(s): %d reachable, %d service(s) identified",
		scanResults.Summary.EndpointsProbed,
		scanResults.Summary.EndpointsReachable,
		scanResults.Summary.ServicesIdentified)
	result.Data = scanResults

	// Print detailed probe results
	fmt.Println("\n=== AI Service Endpoints ===")
	for _, probeResult := range scanResults.Probed {
		status := "Unreachable"
		if probeResult.Reachable {
			status = "Reachable"
		}

		fmt.Printf("\n[%s] %s\n", status, probeResult.Endpoint.URL)
		fmt.Printf("  Source: %s (confidence: %s)\n", probeResult.Endpoint.Source, probeResult.Endpoint.Confidence)

		if probeResult.Reachable && probeResult.Service != "" {
			fmt.Printf("  Service: %s", probeResult.Service)
			if probeResult.Category != "" {
				fmt.Printf(" (%s)", probeResult.Category)
			}
			fmt.Println()

			if len(probeResult.Models) > 0 {
				fmt.Printf("  Models: %v\n", probeResult.Models)
			}
		} else if !probeResult.Reachable && probeResult.Error != "" {
			fmt.Printf("  Error: %s\n", probeResult.Error)
		}
	}
	fmt.Println()

	audit.LogAttackEnd(opts.SessionID, p.Name(), opts.Target, result)
	return result, nil
}

// Cleanup is a no-op — AI probing is read-only and creates no artifacts.
func (p *Plugin) Cleanup(ctx context.Context, session *attacks.Session) error {
	return nil
}
