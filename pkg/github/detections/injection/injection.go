package injection

import (
	"context"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/flow"
	"github.com/praetorian-inc/trajan/pkg/analysis/gates"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/github/detections/common"
)

func init() {
	registry.RegisterDetection("github", "actions-injection", func() detections.Detection {
		return New()
	})
}

// Detection detects script injection vulnerabilities in GitHub Actions
type Detection struct {
	base.BaseDetection
	detector *gates.Detector
}

// New creates a new injection detection with gate detection
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("actions-injection", "github", detections.SeverityHigh),
		detector:      gates.NewDetector(),
	}
}

// Detect analyzes the graph for injection vulnerabilities with gate detection
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)

	for _, wfNode := range workflows {
		wf, ok := wfNode.(*graph.WorkflowNode)
		if !ok {
			continue
		}

		// Skip review triggers - let review_injection handle those
		if hasReviewTrigger(wf.Triggers) {
			continue
		}

		// Check if workflow has zero-click trigger
		isZeroClick := false
		for _, tag := range wf.Tags() {
			if common.ZeroClickTriggers[tag] {
				isZeroClick = true
				break
			}
		}

		// Find all injectable steps in this workflow
		var injectablePaths [][]string
		visited := make(map[string]bool)
		d.findInjectablePaths(g, wf.ID(), []string{}, &injectablePaths, visited)

		// Analyze each path for gates and create findings
		for _, path := range injectablePaths {
			if len(path) == 0 {
				continue
			}

			// Get the injectable step (last node in path)
			stepNode, ok := g.GetNode(path[len(path)-1])
			if !ok {
				continue
			}
			step, ok := stepNode.(*graph.StepNode)
			if !ok {
				continue
			}

			// Detect gates in the path to this injectable step
			pathGates := d.detector.DetectGates(g, path)

			// Skip findings if path has blocking gate (requires human approval)
			if d.detector.HasBlockingGate(pathGates) {
				continue
			}

			// Get job node for attack chain
			var jobNode *graph.JobNode
			for _, nodeID := range path {
				if node, ok := g.GetNode(nodeID); ok && node.Type() == graph.NodeTypeJob {
					if jn, ok := node.(*graph.JobNode); ok {
						jobNode = jn
					}
					break
				}
			}

			// Find all injectable contexts in the step
			injectableContexts := findInjectableContexts(step.Run)
			if len(injectableContexts) > 0 {
				// Create ONE finding per step with ALL injectable contexts
				finding := d.createFindingWithGates(wf, jobNode, step, injectableContexts, isZeroClick, pathGates)
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// findInjectablePaths finds all paths from workflow to injectable steps with cycle detection
func (d *Detection) findInjectablePaths(g *graph.Graph, nodeID string, currentPath []string, paths *[][]string, visited map[string]bool) {
	// Cycle detection: if we've already visited this node in the current path, return
	if visited[nodeID] {
		return
	}
	visited[nodeID] = true
	currentPath = append(currentPath, nodeID)

	node, ok := g.GetNode(nodeID)
	if !ok {
		visited[nodeID] = false
		return
	}

	// If this is an injectable step, save the path
	if node.Type() == graph.NodeTypeStep {
		step, ok := node.(*graph.StepNode)
		if !ok {
			visited[nodeID] = false
			return
		}
		if step.Run != "" && len(findInjectableContexts(step.Run)) > 0 {
			pathCopy := make([]string, len(currentPath))
			copy(pathCopy, currentPath)
			*paths = append(*paths, pathCopy)
			visited[nodeID] = false
			return // Don't traverse further from injectable nodes
		}
	}

	// Continue traversing to children
	for _, childID := range g.Children(nodeID) {
		d.findInjectablePaths(g, childID, currentPath, paths, visited)
	}

	// Backtrack: allow revisiting this node via different paths
	visited[nodeID] = false
}

func hasReviewTrigger(triggers []string) bool {
	reviewTriggers := map[string]bool{
		"pull_request_review":         true,
		"pull_request_review_comment": true,
	}
	for _, t := range triggers {
		if reviewTriggers[t] {
			return true
		}
	}
	return false
}

func findInjectableContexts(s string) []string {
	foundMap := make(map[string]bool) // Use map to deduplicate
	matches := common.ExpressionRegex.FindAllString(s, -1)
	for _, match := range matches {
		for _, ctx := range common.InjectableContexts {
			if strings.Contains(match, ctx) {
				foundMap[ctx] = true
				break
			}
		}
	}

	// Convert map to slice
	found := make([]string, 0, len(foundMap))
	for ctx := range foundMap {
		found = append(found, ctx)
	}
	return found
}

// createFindingWithGates creates a finding with confidence adjusted based on detected gates
func (d *Detection) createFindingWithGates(wf *graph.WorkflowNode, job *graph.JobNode, step *graph.StepNode, injectableContexts []string, isZeroClick bool, pathGates []flow.GateInfo) detections.Finding {
	// Start with base confidence
	baseConfidence := flow.ConfidenceMedium
	if isZeroClick {
		baseConfidence = flow.ConfidenceHigh
	}

	// Adjust confidence based on gates
	adjustedConfidence := d.detector.CalculateConfidence(baseConfidence, pathGates)

	// Convert flow.Confidence to detections.Confidence
	pluginConfidence := detections.ConfidenceMedium
	switch adjustedConfidence {
	case flow.ConfidenceLow:
		pluginConfidence = detections.ConfidenceLow
	case flow.ConfidenceMedium:
		pluginConfidence = detections.ConfidenceMedium
	case flow.ConfidenceHigh:
		pluginConfidence = detections.ConfidenceHigh
	}

	complexity := detections.ComplexityMedium
	if isZeroClick {
		complexity = detections.ComplexityZeroClick
	}

	jobName := ""
	if job != nil {
		jobName = job.Name
	}

	// Build attack chain
	attackChain := detections.BuildChainFromNodes(wf, job, step)

	// Create line ranges for the injectable step
	var lineRanges []detections.LineRange
	if step.Line > 0 {
		lineRanges = []detections.LineRange{
			{
				Start: step.Line,
				End:   step.Line + 4, // run steps typically span several lines
				Label: "injectable context usage",
			},
		}
	}

	// Build enhanced evidence with all contexts
	contextList := strings.Join(injectableContexts, ", ")
	evidence := "Workflow uses " + strings.Join(wf.Triggers, ", ") + " trigger and injects user-controllable contexts (" + contextList + ") into run command. This allows arbitrary command injection."

	// Build metadata with gates info if present
	metadata := make(map[string]interface{})
	if len(pathGates) > 0 {
		gateDescriptions := make([]string, 0, len(pathGates))
		for _, gate := range pathGates {
			gateDescriptions = append(gateDescriptions, gate.Description)
		}
		metadata["gates"] = gateDescriptions
	}

	return detections.Finding{
		Type:         detections.VulnActionsInjection,
		Platform:     "github",
		Class:        detections.GetVulnerabilityClass(detections.VulnActionsInjection),
		Severity:     detections.SeverityHigh,
		Confidence:   pluginConfidence,
		Complexity:   complexity,
		Repository:   wf.RepoSlug,
		Workflow:     wf.Path, // Use path for matching
		WorkflowFile: wf.Path,
		Job:          jobName,
		Step:         step.Name,
		Line:         step.Line,
		Trigger:      strings.Join(wf.Triggers, ", "),
		Evidence:     evidence,
		Remediation:  "Avoid using user-controllable GitHub contexts directly in run commands. Instead, pass them through environment variables (env:) or action inputs which are not subject to shell interpretation. For example, use 'env: TITLE: ${{ github.event.issue.title }}' and reference '$TITLE' in the script.",
		Details: &detections.FindingDetails{
			LineRanges:         lineRanges,
			AttackChain:        attackChain,
			InjectableContexts: injectableContexts,
			Metadata:           metadata,
		},
	}
}
