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

// exprRegex matches ${{ }} Azure template expressions
var exprRegex = regexp.MustCompile(`\$\{\{\s*(.+?)\s*\}\}`)

func init() {
	registry.RegisterDetection(platforms.PlatformAzureDevOps, "service-connections", func() detections.Detection {
		return New()
	})
}

// Detection detects service connection vulnerabilities in Azure Pipelines
type Detection struct {
	base.BaseDetection
	mu              sync.Mutex
	connectionUsage map[string]map[string]bool // connection name -> set of workflow IDs that use it
	emitted         map[string]bool            // connections already emitted as findings
}

// New creates a new service connections detection
func New() *Detection {
	return &Detection{
		BaseDetection:   base.NewBaseDetection("service-connections", platforms.PlatformAzureDevOps, detections.SeverityCritical),
		connectionUsage: make(map[string]map[string]bool),
		emitted:         make(map[string]bool),
	}
}

// Detect analyzes the graph for service connection vulnerabilities
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

		// Accumulate connection usage across all Detect calls and check threshold under the mutex
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

// checkDynamicServiceConnections checks for dynamic service connection references
func checkDynamicServiceConnections(wf *graph.WorkflowNode, step *graph.StepNode) []detections.Finding {
	var findings []detections.Finding

	// List of known service connection parameter names in Azure DevOps tasks
	connectionParams := []string{
		"azureSubscription",
		"connectedServiceName",
		"kubernetesServiceConnection",
		"dockerRegistryServiceConnection",
		"azureServiceConnection",
		"awsCredentials",
		"gcpConnection",
	}

	// Check each connection parameter
	for _, param := range connectionParams {
		if value, exists := step.With[param]; exists {
			// Check if value contains dynamic template expressions
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

// checkServiceConnectionInEnv checks for service connections exposed in environment variables
func checkServiceConnectionInEnv(wf *graph.WorkflowNode, step *graph.StepNode) []detections.Finding {
	var findings []detections.Finding

	// Specific patterns that indicate actual service connections
	// These are more precise to reduce false positives on generic env vars
	connectionPatterns := []string{
		"service_connection",
		"serviceconnection",
		"_connection",     // Matches AZURE_CONNECTION, K8S_CONNECTION, etc.
		"connection_",     // Matches CONNECTION_STRING, etc.
		"_conn",           // Matches REGISTRY_CONN, DB_CONN, etc.
		"subscription_id", // Azure subscription IDs
		"subscriptionid",
		"registry_conn",
		"registryconn",
	}

	// Check environment variables
	for envKey, envValue := range step.Env {
		envKeyLower := strings.ToLower(envKey)

		// Check if env var name matches a service connection pattern
		isConnectionEnv := false
		for _, pattern := range connectionPatterns {
			if strings.Contains(envKeyLower, pattern) {
				isConnectionEnv = true
				break
			}
		}

		// If env var matches connection pattern and contains dynamic expression
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

// hasDynamicExpression checks if a value contains ${{ }} template expressions
// Any dynamic expression is potentially dangerous because:
// - parameters.* can be controlled by pipeline invocation
// - variables.* can come from PR context or previous steps
// - steps.*.outputs.* can be attacker-controlled if the step runs malicious code
// - jobs.*.outputs.* can be attacker-controlled from compromised jobs
// - env.* can reference attacker-controlled environment variables
func hasDynamicExpression(value string) bool {
	matches := exprRegex.FindAllStringSubmatch(value, -1)
	// Any ${{ }} expression is potentially dangerous for service connections
	return len(matches) > 0
}

// trackConnectionUsage records which service connections a step references
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
				// Found a connection reference
				connectionsInWorkflow[paramValue] = true
				break
			}
		}
	}
}
