package permissions

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
)

func init() {
	registry.RegisterDetection("github", "excessive-permissions", func() detections.Detection {
		return New()
	})
}

// Detection detects excessive permissions in risky workflow triggers
type Detection struct {
	base.BaseDetection
}

// New creates a new excessive permissions plugin
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("excessive-permissions", "github", detections.SeverityHigh),
	}
}

// Detect analyzes the graph for excessive permission vulnerabilities
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	// Define risky trigger -> tag mappings with severity levels
	riskyTriggers := map[string]struct {
		tag      graph.Tag
		severity detections.Severity
	}{
		"pull_request_target": {graph.TagPullRequestTarget, detections.SeverityHigh},
		"issue_comment":       {graph.TagIssueComment, detections.SeverityHigh},
		"workflow_run":        {graph.TagWorkflowRun, detections.SeverityMedium},
	}

	// Check each risky trigger type
	for triggerName, config := range riskyTriggers {
		workflows := g.GetNodesByTag(config.tag)

		for _, wfNode := range workflows {
			wf := wfNode.(*graph.WorkflowNode)

			// Traverse jobs in the workflow
			graph.DFS(g, wf.ID(), func(node graph.Node) bool {
				if node.Type() == graph.NodeTypeJob {
					jobNode := node.(*graph.JobNode)

					// Check for dangerous permissions
					if finding := checkPermissions(wf, jobNode, triggerName, config.severity); finding != nil {
						findings = append(findings, *finding)
					}
				}
				return true
			})
		}
	}

	return findings, nil
}

// checkPermissions analyzes job permissions against trigger context
func checkPermissions(wf *graph.WorkflowNode, job *graph.JobNode, trigger string, defaultSeverity detections.Severity) *detections.Finding {
	// CRITICAL: Missing permissions block on risky trigger = dangerous defaults
	// Note: nil = missing block (dangerous), empty map = explicit {} (safe/read-only)
	if job.Permissions == nil {
		// Create line range for job definition (permissions should be here)
		var lineRanges []detections.LineRange
		if job.Line > 0 {
			lineRanges = []detections.LineRange{
				{
					Start: job.Line,
					End:   job.Line + 3,
					Label: "job without permissions block",
				},
			}
		}

		return &detections.Finding{
			Type:       detections.VulnExcessivePermissions,
			Platform:   "github",
			Class:      detections.GetVulnerabilityClass(detections.VulnExcessivePermissions),
			Severity:   defaultSeverity,
			Confidence: detections.ConfidenceHigh,
			Complexity: detections.ComplexityLow,
		Repository:   wf.RepoSlug,
		Workflow:     wf.Path, // Use path
		WorkflowFile: wf.Path,
		Job:          job.Name,
		Line:         job.Line,
		Trigger:      trigger,
		Evidence:     fmt.Sprintf("Job on %s trigger missing permissions block. Defaults to write access, allowing privilege escalation.", trigger),
			Details: &detections.FindingDetails{
				LineRanges: lineRanges,
			},
		}
	}

	// Explicit empty permissions block {} = read-only = safe
	if len(job.Permissions) == 0 {
		return nil
	}

	// Check for dangerous explicit write permission combinations
	for perm, level := range job.Permissions {
		if level != "write" {
			continue
		}

		var severity detections.Severity

		// Determine severity based on trigger + permission combination
		switch trigger {
		case "pull_request_target":
			// Any write permission on pull_request_target is dangerous
			if perm == "contents" {
				severity = detections.SeverityCritical
			} else {
				severity = detections.SeverityHigh
			}

		case "issue_comment":
			// issue_comment + contents or pull-requests write is dangerous
			if perm == "contents" || perm == "pull-requests" {
				severity = detections.SeverityHigh
			}

		case "workflow_run":
			// workflow_run with write permissions is risky
			if perm == "contents" || perm == "pull-requests" {
				severity = detections.SeverityMedium
			}
		}

		// If we found a dangerous combination, return finding
		if severity != "" {
			// Create line range for permissions block
			var lineRanges []detections.LineRange
			if job.Line > 0 {
				lineRanges = []detections.LineRange{
					{
						Start: job.Line,
						End:   job.Line + 5, // Show permissions block
						Label: "excessive permissions",
					},
				}
			}

			// List the problematic permissions
			var permsList []string
			for p, l := range job.Permissions {
				if l == "write" {
					permsList = append(permsList, p)
				}
			}

			return &detections.Finding{
				Type:       detections.VulnExcessivePermissions,
				Platform:   "github",
				Class:      detections.GetVulnerabilityClass(detections.VulnExcessivePermissions),
				Severity:   severity,
				Confidence: detections.ConfidenceHigh,
				Complexity: detections.ComplexityLow,
			Repository:   wf.RepoSlug,
			Workflow:     wf.Path, // Use path
			WorkflowFile: wf.Path,
			Job:          job.Name,
			Line:         job.Line,
			Trigger:      trigger,
			Evidence:     fmt.Sprintf("Job on %s trigger has dangerous write permissions: %s", trigger, perm),
				Details: &detections.FindingDetails{
					LineRanges:  lineRanges,
					Permissions: permsList,
				},
			}
		}
	}

	return nil
}
