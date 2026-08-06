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

type Detection struct {
	base.BaseDetection
}

func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("agent-security", platforms.PlatformAzureDevOps, detections.SeverityHigh),
	}
}

func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	poolMap := buildPoolMap(g)

	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)

	for _, wfNode := range workflows {
		wf, ok := wfNode.(*graph.WorkflowNode)
		if !ok {
			continue
		}

		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			if node.Type() == graph.NodeTypeJob {
				job, ok := node.(*graph.JobNode)
				if !ok {
					return true
				}

				if isSelfHostedPool(job.RunsOn, poolMap) {
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

// Maps lowercase pool name to the API's IsHosted flag; nil when the scan collected
// no pool metadata (offline mode).
func buildPoolMap(g *graph.Graph) map[string]bool {
	data, ok := g.GetMetadata("ado_agent_pools")
	if !ok {
		return nil
	}
	pools, ok := data.([]azuredevops.AgentPool)
	if !ok || len(pools) == 0 {
		return nil
	}
	m := make(map[string]bool, len(pools))
	for _, p := range pools {
		m[strings.ToLower(p.Name)] = p.IsHosted
	}
	return m
}

func isSelfHostedPool(runsOn string, poolMap map[string]bool) bool {
	if runsOn == "" {
		return false
	}

	runsOnLower := strings.ToLower(runsOn)

	// API pool data is authoritative.
	if poolMap != nil {
		if isHosted, known := poolMap[runsOnLower]; known {
			return !isHosted
		}
	}

	if isVMImage(runsOnLower) {
		return false
	}

	// "Azure Pipelines" is the default Microsoft-hosted pool.
	if poolMap == nil {
		return runsOnLower != "azure pipelines"
	}

	// Pool absent from the API data: flag conservatively.
	return true
}

// runsOnLower must already be lowercased by the caller.
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
