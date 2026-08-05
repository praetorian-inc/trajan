package serviceconnections

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/azuredevops/detections/common"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

var exprRegex = regexp.MustCompile(`\$\{\{\s*(.+?)\s*\}\}`)

func init() {
	registry.RegisterDetection(platforms.PlatformAzureDevOps, "service-connections", func() detections.Detection {
		return New()
	})
}

type Detection struct {
	base.BaseDetection
	mu              sync.Mutex
	connectionUsage map[string]map[string]bool // connection name -> set of workflow IDs that use it
	emitted         map[string]bool            // connection names already reported
}

func New() *Detection {
	return &Detection{
		BaseDetection:   base.NewBaseDetection("service-connections", platforms.PlatformAzureDevOps, detections.SeverityCritical),
		connectionUsage: make(map[string]map[string]bool),
		emitted:         make(map[string]bool),
	}
}

func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)
	for _, wfNode := range workflows {
		wf, ok := wfNode.(*graph.WorkflowNode)
		if !ok {
			continue
		}
		connectionsInWorkflow := make(map[string]bool)

		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			if node.Type() == graph.NodeTypeStep {
				step, ok := node.(*graph.StepNode)
				if !ok {
					return true
				}
				findings = append(findings, checkDynamicServiceConnections(wf, step)...)
				findings = append(findings, checkServiceConnectionInEnv(wf, step)...)
				trackConnectionUsage(step, connectionsInWorkflow)
			}
			return true
		})

		// Usage accumulates across Detect calls, so the threshold check must hold the mutex.
		d.mu.Lock()
		for conn := range connectionsInWorkflow {
			if d.connectionUsage[conn] == nil {
				d.connectionUsage[conn] = make(map[string]bool)
			}
			d.connectionUsage[conn][wf.ID()] = true
		}
		for conn, wfSet := range d.connectionUsage {
			if len(wfSet) >= 3 && !d.emitted[conn] {
				d.emitted[conn] = true
				findings = append(findings, detections.Finding{
					Type:        detections.VulnOverexposedServiceConnections,
					Platform:    platforms.PlatformAzureDevOps,
					Class:       detections.ClassPrivilegeEscalation,
					Severity:    detections.SeverityMedium,
					Confidence:  detections.ConfidenceMedium,
					Complexity:  detections.ComplexityLow,
					Repository:  "",
					Workflow:    "",
					Evidence:    fmt.Sprintf("Service connection '%s' used by %d workflows (suggests 'Grant access to all pipelines' enabled)", conn, len(wfSet)),
					Remediation: "Disable 'Grant access to all pipelines' for service connections. Explicitly grant access only to pipelines that require it. This prevents compromised pipelines from accessing sensitive service connections.",
				})
			}
		}
		d.mu.Unlock()
	}

	return findings, nil
}

func checkDynamicServiceConnections(wf *graph.WorkflowNode, step *graph.StepNode) []detections.Finding {
	var findings []detections.Finding

	connectionParams := []string{
		"azureSubscription",
		"connectedServiceName",
		"kubernetesServiceConnection",
		"dockerRegistryServiceConnection",
		"azureServiceConnection",
		"awsCredentials",
		"gcpConnection",
	}

	for _, param := range connectionParams {
		if value, exists := step.With[param]; exists {
			if hasDynamicExpression(value) {
				scLine := common.LineForKey(step.WithLines, param, step.Line)
				findings = append(findings, detections.Finding{
					Type:       detections.VulnServiceConnectionHijacking,
					Platform:   platforms.PlatformAzureDevOps,
					Class:      detections.GetVulnerabilityClass(detections.VulnServiceConnectionHijacking),
					Severity:   detections.SeverityCritical,
					Confidence: detections.ConfidenceHigh,
					Complexity: detections.ComplexityLow,
					Repository: wf.RepoSlug,
					Workflow:   wf.Name,
					Step:       step.Name,
					Line:       scLine,
					Evidence:   "Dynamic service connection in '" + param + "': " + value,
					Remediation: "Never use parameters or variables in service connection names. " +
						"Hardcode the connection name to prevent attackers from accessing arbitrary service connections.",
					Details: &detections.FindingDetails{
						LineRanges: []detections.LineRange{{
							Start: scLine,
							End:   scLine,
							Label: "dynamic service connection",
						}},
						Metadata: map[string]interface{}{
							"sink": "service connection parameter (dynamic expression)",
						},
					},
				})
			}
		}
	}

	return findings
}

func checkServiceConnectionInEnv(wf *graph.WorkflowNode, step *graph.StepNode) []detections.Finding {
	var findings []detections.Finding

	// Deliberately narrow to avoid matching generic env vars.
	connectionPatterns := []string{
		"service_connection",
		"serviceconnection",
		"_connection",
		"connection_",
		"_conn",
		"subscription_id",
		"subscriptionid",
		"registry_conn",
		"registryconn",
	}

	for envKey, envValue := range step.Env {
		envKeyLower := strings.ToLower(envKey)

		isConnectionEnv := false
		for _, pattern := range connectionPatterns {
			if strings.Contains(envKeyLower, pattern) {
				isConnectionEnv = true
				break
			}
		}

		if isConnectionEnv && hasDynamicExpression(envValue) {
			envLine := common.LineForKey(step.EnvLines, envKey, step.Line)
			findings = append(findings, detections.Finding{
				Type:       detections.VulnServiceConnectionHijacking,
				Platform:   platforms.PlatformAzureDevOps,
				Class:      detections.GetVulnerabilityClass(detections.VulnServiceConnectionHijacking),
				Severity:   detections.SeverityHigh,
				Confidence: detections.ConfidenceMedium,
				Complexity: detections.ComplexityLow,
				Repository: wf.RepoSlug,
				Workflow:   wf.Name,
				Step:       step.Name,
				Line:       envLine,
				Evidence:   "Service connection exposed in environment variable '" + envKey + "': " + envValue,
				Remediation: "Avoid exposing service connections in environment variables as they may leak to logs. " +
					"Use the task's built-in connection parameters instead.",
				Details: &detections.FindingDetails{
					LineRanges: []detections.LineRange{{
						Start: envLine,
						End:   envLine,
						Label: "service connection in environment",
					}},
				},
			})
		}
	}

	return findings
}

// Every ${{ }} source can be attacker-influenced: parameters at queue time, variables
// from PR context, step and job outputs from compromised jobs, env from the environment.
func hasDynamicExpression(value string) bool {
	matches := exprRegex.FindAllStringSubmatch(value, -1)
	return len(matches) > 0
}

func trackConnectionUsage(step *graph.StepNode, connectionsInWorkflow map[string]bool) {
	connectionParams := []string{
		"azuresubscription",
		"connectedservicename",
		"kubernetesserviceconnection",
		"dockerregistryserviceconnection",
		"serviceconnection",
	}

	for paramKey, paramValue := range step.With {
		paramKeyLower := strings.ToLower(paramKey)
		for _, connParam := range connectionParams {
			if strings.Contains(paramKeyLower, connParam) {
				connectionsInWorkflow[paramValue] = true
				break
			}
		}
	}
}
