package agentsecurity

import (
	"context"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func init() {
	registry.RegisterDetection(platforms.PlatformAzureDevOps, "agent-security", func() detections.Detection {
		return New()
	})
}

// Detection detects agent security issues such as use of self-hosted agent pools
type Detection struct {
	base.BaseDetection
}

// New creates a new agent-security detection
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("agent-security", platforms.PlatformAzureDevOps, detections.SeverityHigh),
	}
}

// Detect analyzes the graph for unrestricted self-hosted agent pools
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	hostedPools := buildHostedPoolSet(g)

	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)

	for _, wfNode := range workflows {
		wf := wfNode.(*graph.WorkflowNode)

		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			if node.Type() == graph.NodeTypeJob {
				job := node.(*graph.JobNode)

				if isSelfHostedPool(job.RunsOn, hostedPools) {
					findings = append(findings, detections.Finding{
						Type:        detections.VulnSelfHostedAgent,
						Platform:    platforms.PlatformAzureDevOps,
						Class:       detections.ClassRunnerSecurity,
						Severity:    detections.SeverityHigh,
						Confidence:  detections.ConfidenceHigh,
						Complexity:  detections.ComplexityLow,
						Repository:  wf.RepoSlug,
						Workflow:    wf.Name,
						Job:         job.Name,
						Line:        job.Line,
						Evidence:    "Job uses self-hosted agent pool: " + job.RunsOn,
						Remediation: "Use Microsoft-hosted agents when possible. If self-hosted agents are required, ensure they are properly secured, isolated, and regularly updated. Review agent pool permissions and restrict access.",
						Details: &detections.FindingDetails{
							LineRanges: []detections.LineRange{{
								Start: job.Line,
								End:   job.Line,
								Label: "self-hosted agent pool",
							}},
						},
					})
				}
			}
			return true
		})
	}

	return findings, nil
}

// buildHostedPoolSet reads agent pool metadata from the graph (set by the scan
// command via ListAgentPools) and returns a set of lowercase pool names that
// are Microsoft-hosted. Returns nil when no pool metadata is available (offline mode).
func buildHostedPoolSet(g *graph.Graph) map[string]bool {
	data, ok := g.GetMetadata("ado_agent_pools")
	if !ok {
		return nil
	}
	pools, ok := data.([]azuredevops.AgentPool)
	if !ok {
		return nil
	}
	hosted := make(map[string]bool, len(pools))
	for _, p := range pools {
		if p.IsHosted {
			hosted[strings.ToLower(p.Name)] = true
		}
	}
	return hosted
}

// isSelfHostedPool checks if the RunsOn value indicates a self-hosted agent pool.
// When hostedPools is non-nil (API data available), pool names are checked against
// the API's IsHosted field. When nil (offline mode), a vmImage heuristic is used.
func isSelfHostedPool(runsOn string, hostedPools map[string]bool) bool {
	if runsOn == "" {
		return false
	}

	runsOnLower := strings.ToLower(runsOn)

	// vmImage values are always Microsoft-hosted regardless of API data
	if isVMImage(runsOnLower) {
		return false
	}

	// When API pool data is available, use IsHosted for accurate classification
	if hostedPools != nil {
		return !hostedPools[runsOnLower]
	}

	// Offline fallback: "Azure Pipelines" is the only well-known hosted pool name
	return runsOnLower != "azure pipelines"
}

// isVMImage returns true if the RunsOn value (already lowercased) is a
// Microsoft-hosted vmImage string. These follow predictable naming conventions
// and don't need API validation.
func isVMImage(runsOnLower string) bool {
	if strings.HasPrefix(runsOnLower, "vmimage:") {
		return true
	}
	vmImagePrefixes := []string{"ubuntu-", "windows-", "macos-"}
	for _, prefix := range vmImagePrefixes {
		if strings.HasPrefix(runsOnLower, prefix) {
			return true
		}
	}
	return false
}
