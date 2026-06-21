package permissions

import (
	"context"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
)

func init() {
	registry.RegisterDetection("jenkins", "permissions", func() detections.Detection {
		return New()
	})
}

// Detection detects overly permissive pipeline permissions in Jenkins
type Detection struct {
	base.BaseDetection
}

// New creates a new permissions detection
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("permissions", "jenkins", detections.SeverityMedium),
	}
}

// overlyBroadPermValues contains permission values that indicate excessive access
var overlyBroadPermValues = map[string][]string{
	"admin":       {"true"},
	"all":         {"write", "true"},
	"credentials": {"write", "manage"},
	"build":       {"admin"},
}

// broadConditionKeywords contains keywords in job conditions that indicate
// overly broad permission grants
var broadConditionKeywords = []string{
	"org-admin",
	"admin-access",
	"full-control",
	"all-permissions",
	"unrestricted",
}

// Detect finds overly permissive pipeline permissions in the workflow graph
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

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

				if d.hasOverlyBroadPermissions(job) || d.hasBroadCondition(job) {
					findings = append(findings, d.createFinding(wf, job))
				}
			}
			return true
		})
	}

	return findings, nil
}

// hasOverlyBroadPermissions checks if a job has overly permissive permissions
func (d *Detection) hasOverlyBroadPermissions(job *graph.JobNode) bool {
	for key, value := range job.Permissions {
		lowerKey := strings.ToLower(key)
		lowerValue := strings.ToLower(value)

		if allowedValues, ok := overlyBroadPermValues[lowerKey]; ok {
			for _, allowed := range allowedValues {
				if lowerValue == allowed {
					return true
				}
			}
		}
	}
	return false
}

// hasBroadCondition checks if a job condition contains broad permission keywords
func (d *Detection) hasBroadCondition(job *graph.JobNode) bool {
	lowerIf := strings.ToLower(job.If)
	for _, keyword := range broadConditionKeywords {
		if strings.Contains(lowerIf, keyword) {
			return true
		}
	}
	return false
}

// createFinding creates a finding for excessive permissions
func (d *Detection) createFinding(wf *graph.WorkflowNode, job *graph.JobNode) detections.Finding {
	evidence := job.If
	if evidence == "" && len(job.Permissions) > 0 {
		parts := make([]string, 0, len(job.Permissions))
		for k, v := range job.Permissions {
			parts = append(parts, k+"="+v)
		}
		evidence = strings.Join(parts, ", ")
	}

	return detections.Finding{
		Type:        detections.VulnExcessivePermissions,
		Platform:    "jenkins",
		Class:       detections.ClassPrivilegeEscalation,
		Severity:    detections.SeverityMedium,
		Confidence:  detections.ConfidenceMedium,
		Complexity:  detections.ComplexityMedium,
		Repository:  wf.RepoSlug,
		Workflow:    wf.Name,
		Job:         job.Name,
		Line:        job.Line,
		Trigger:     strings.Join(wf.Triggers, ", "),
		Evidence:    evidence,
		Remediation: "Apply principle of least privilege to Jenkins pipeline permissions. Use folder-level permissions and restrict access to sensitive operations.",
	}
}
