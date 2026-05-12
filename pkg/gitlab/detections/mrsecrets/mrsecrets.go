package mrsecrets

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/gitlab/detections/common"
)

func init() {
	registry.RegisterDetection("gitlab", "merge-request-secrets-exposure", func() detections.Detection {
		return New()
	})
}

// Detection detects when CI/CD secrets/variables are accessible in merge request pipelines
// without protected branch restrictions
type Detection struct {
	base.BaseDetection
	secretKeywords []string
	varPattern     *regexp.Regexp
}

// New creates a new merge-request-secrets-exposure detection
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection(
			"merge-request-secrets-exposure",
			"gitlab",
			detections.SeverityHigh,
		),
		secretKeywords: []string{
			"token",
			"key",
			"secret",
			"password",
			"api_key",
			"apikey",
			"credentials",
			"credential",
		},
		// Match GitLab CI variables like $VAR or ${VAR}
		varPattern: regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`),
	}
}

// Detect analyzes the graph for secrets exposed in merge request pipelines
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	// Get all workflow nodes
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)

	for _, wfNode := range workflows {
		wf, ok := wfNode.(*graph.WorkflowNode)
		if !ok {
			continue
		}

		// Only DFS from root workflows to avoid duplicates
		if !common.IsRootWorkflow(g, wf) {
			continue
		}

		// Check if workflow triggers on merge requests
		if !hasMergeRequestTrigger(wf, g) {
			continue
		}

		// DFS to find jobs and steps that access secrets
		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			job, ok := node.(*graph.JobNode)
			if !ok {
				return true
			}

			// Skip if job is restricted to protected branches only
			if isProtectedBranchOnly(job) {
				return true
			}

			// Check if job runs on merge request trigger
			// Jobs without If conditions inherit the workflow's trigger context
			// Only check jobs that explicitly mention MR events OR have no If condition (inherit from workflow)
			if !jobRunsOnMR(job, wf, g) {
				return true
			}

			// Collect ALL sensitive variables from ALL steps in this job
			var allSensitiveVars []string
			var firstStep *graph.StepNode
			seen := make(map[string]bool)

			graph.DFS(g, job.ID(), func(stepNode graph.Node) bool {
				step, ok := stepNode.(*graph.StepNode)
				if !ok {
					return true
				}

				if step.Run == "" {
					return true
				}

				if firstStep == nil {
					firstStep = step
				}

				// Collect sensitive variables from this step
				sensitiveVars := d.findSensitiveVariables(step.Run)
				for _, varName := range sensitiveVars {
					if !seen[varName] {
						allSensitiveVars = append(allSensitiveVars, varName)
						seen[varName] = true
					}
				}

				return true
			})

			// Create ONE finding per job with all exposed variables
			if len(allSensitiveVars) > 0 && firstStep != nil {
				finding := d.createFinding(g, job, firstStep, allSensitiveVars)
				findings = append(findings, finding)
			}

			return true
		})
	}

	return findings, nil
}

// hasMergeRequestTrigger checks if the workflow triggers on merge requests
func hasMergeRequestTrigger(wf *graph.WorkflowNode, g *graph.Graph) bool {
	// Check tags for merge request indicators
	for _, tag := range wf.Tags() {
		if tag == graph.TagMergeRequest || tag == graph.TagExternalPullRequest {
			return true
		}
	}

	// Fallback: check if workflow has merge_request in triggers (case-insensitive)
	for _, trigger := range wf.Triggers {
		triggerLower := strings.ToLower(trigger)
		if strings.Contains(triggerLower, "merge_request") ||
			strings.Contains(triggerLower, "external_pull_request") {
			return true
		}
	}

	// Also check job-level If conditions for merge request references
	foundMR := false
	graph.DFS(g, wf.ID(), func(node graph.Node) bool {
		if job, ok := node.(*graph.JobNode); ok {
			if jobRunsOnMRExplicit(job) {
				foundMR = true
				return false // Stop DFS, we found it
			}
		}
		return true
	})

	return foundMR
}

// jobRunsOnMRExplicit checks if a job explicitly mentions MR events in its If condition
func jobRunsOnMRExplicit(job *graph.JobNode) bool {
	if job.If == "" {
		return false
	}

	ifLower := strings.ToLower(job.If)
	return strings.Contains(ifLower, "merge_request") ||
		strings.Contains(ifLower, "external_pull_request")
}

// jobRunsOnMR checks if a job runs on merge request events
// This includes jobs that explicitly mention MR events OR jobs without If conditions
// in workflows that have MR triggers
func jobRunsOnMR(job *graph.JobNode, wf *graph.WorkflowNode, g *graph.Graph) bool {
	// If job explicitly mentions MR events, it runs on MR
	if jobRunsOnMRExplicit(job) {
		return true
	}

	// If job has an If condition but doesn't mention MR events, it doesn't run on MR
	if job.If != "" {
		return false
	}

	// Job has no If condition - check if workflow has MR trigger
	return hasMergeRequestTrigger(wf, g)
}

// isProtectedBranchOnly checks if a job is restricted to protected branches
func isProtectedBranchOnly(job *graph.JobNode) bool {
	if job.If == "" {
		return false
	}

	ifLower := strings.ToLower(job.If)

	// Check for protected branch patterns
	protectedBranchPatterns := []string{
		"== \"main\"",
		"== \"master\"",
		"== 'main'",
		"== 'master'",
		"=~ /^main$/",
		"=~ /^master$/",
		"ci_commit_branch == \"main\"",
		"ci_commit_branch == \"master\"",
		"ci_commit_branch == 'main'",
		"ci_commit_branch == 'master'",
		"ci_commit_ref_name == \"main\"",
		"ci_commit_ref_name == \"master\"",
		"ci_commit_ref_name == 'main'",
		"ci_commit_ref_name == 'master'",
	}

	for _, pattern := range protectedBranchPatterns {
		if strings.Contains(ifLower, pattern) {
			return true
		}
	}

	return false
}

// findSensitiveVariables finds sensitive variable references in a script
func (d *Detection) findSensitiveVariables(script string) []string {
	var sensitiveVars []string
	seen := make(map[string]bool)

	// Find all variable references
	matches := d.varPattern.FindAllStringSubmatch(script, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		varName := match[1]
		if seen[varName] {
			continue
		}

		// Check if variable name contains sensitive keywords
		if d.isSensitiveVariable(varName) {
			sensitiveVars = append(sensitiveVars, varName)
			seen[varName] = true
		}
	}

	return sensitiveVars
}

// isSensitiveVariable checks if a variable name contains sensitive keywords
func (d *Detection) isSensitiveVariable(varName string) bool {
	varLower := strings.ToLower(varName)

	for _, keyword := range d.secretKeywords {
		if strings.Contains(varLower, keyword) {
			return true
		}
	}

	return false
}

// createFinding creates a finding for secrets exposed in an MR pipeline
func (d *Detection) createFinding(g *graph.Graph, job *graph.JobNode, step *graph.StepNode, exposedVars []string) detections.Finding {
	wf := getJobParentWorkflow(g, job)
	if wf == nil {
		// Fallback to empty workflow info if parent not found
		wf = &graph.WorkflowNode{}
	}
	// Build enhanced evidence message
	varList := strings.Join(exposedVars, ", ")
	evidence := fmt.Sprintf("Job '%s' runs on merge_request trigger and accesses sensitive variables (%s) without protected branch restrictions. ", job.Name, varList)
	evidence += fmt.Sprintf("External attackers can submit malicious merge requests that modify this job to exfiltrate %d secrets.", len(exposedVars))

	// Build attack chain
	attackChain := detections.BuildChainFromNodes(wf, job, step)

	// Create line ranges
	var lineRanges []detections.LineRange
	if job.Line > 0 {
		lineRanges = append(lineRanges, detections.LineRange{
			Start: job.Line,
			End:   job.Line + 3,
			Label: "MR-triggered job with secrets",
		})
	}
	if step.Line > 0 && step.Line != job.Line {
		lineRanges = append(lineRanges, detections.LineRange{
			Start: step.Line,
			End:   step.Line,
			Label: "secret usage",
		})
	}

	// Build metadata
	metadata := make(map[string]interface{})
	metadata["exposedSecrets"] = exposedVars
	metadata["secretCount"] = len(exposedVars)
	metadata["trigger"] = "merge_request"

	return detections.Finding{
		Type:        detections.VulnMergeRequestSecretsExposure,
		Severity:    detections.SeverityHigh,
		Confidence:  detections.ConfidenceHigh,
		Complexity:  detections.ComplexityZeroClick,
		Platform:    "gitlab",
		Class:       detections.GetVulnerabilityClass(detections.VulnMergeRequestSecretsExposure),
		Repository:   wf.RepoSlug,
		Workflow:     wf.Path,
		WorkflowFile: wf.Path,
		Job:          job.Name,
		Step:        step.Name,
		Line:        step.Line,
		Evidence:    evidence,
		Remediation: "Restrict this job to protected branches using rules: [{if: \"$CI_COMMIT_BRANCH == 'main'\"}], or mark variables as protected in Settings → CI/CD → Variables (protected variables are only available on protected branches).",
		Details: &detections.FindingDetails{
			LineRanges:  lineRanges,
			AttackChain: attackChain,
			Metadata:    metadata,
		},
	}
}

// getJobParentWorkflow finds the parent workflow node for a job.
// Returns nil if job has no parent workflow or parent is not a WorkflowNode.
func getJobParentWorkflow(g *graph.Graph, job *graph.JobNode) *graph.WorkflowNode {
	if job == nil {
		return nil
	}

	// Get parent workflow
	wfNode, ok := g.GetNode(job.Parent())
	if !ok {
		return nil
	}

	// Type assert to WorkflowNode
	if wf, ok := wfNode.(*graph.WorkflowNode); ok {
		return wf
	}

	return nil
}
