package pwnrequest

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func init() {
	registry.RegisterDetection("github", "pwn-request", func() detections.Detection {
		return New()
	})
}

// Detection detects pull_request_target with unsafe checkout
type Detection struct {
	base.BaseDetection
}

// New creates a new pwn request plugin
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("pwn-request", "github", detections.SeverityCritical),
	}
}

// Detect analyzes the graph for pwn request vulnerabilities
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	// Get all workflows from metadata for cross-workflow analysis
	var allWorkflows map[string][]platforms.Workflow
	if wfData, ok := g.GetMetadata("all_workflows"); ok {
		if wfs, ok := wfData.(map[string][]platforms.Workflow); ok {
			allWorkflows = wfs
		}
	}

	// Check all zero-click triggers that could checkout PR code
	zeroClickWorkflows := []graph.Node{}
	zeroClickWorkflows = append(zeroClickWorkflows, g.GetNodesByTag(graph.TagPullRequestTarget)...)
	zeroClickWorkflows = append(zeroClickWorkflows, g.GetNodesByTag(graph.TagIssueComment)...)
	zeroClickWorkflows = append(zeroClickWorkflows, g.GetNodesByTag(graph.TagWorkflowRun)...)
	zeroClickWorkflows = append(zeroClickWorkflows, g.GetNodesByTag(graph.TagDiscussion)...)

	for _, wfNode := range zeroClickWorkflows {
		wf := wfNode.(*graph.WorkflowNode)

		// Track nodes for complete path
		var checkoutStep *graph.StepNode
		var jobNode *graph.JobNode
		var intermediateJobs []*graph.JobNode
		var intermediateSteps []*graph.StepNode

		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			switch node.Type() {
			case graph.NodeTypeJob:
				currentJob := node.(*graph.JobNode)

				// Track all jobs for complete path
				if jobNode != nil {
					intermediateJobs = append(intermediateJobs, jobNode)
				}
				jobNode = currentJob

				// Check if this job calls a reusable workflow
				if jobNode.Uses != "" && allWorkflows != nil {
					// Build path with intermediate jobs
					pathNodes := []graph.Node{wf}
					for _, j := range intermediateJobs {
						pathNodes = append(pathNodes, j)
					}
					pathNodes = append(pathNodes, jobNode)

					if finding := checkReusableWorkflowCallWithPath(wf, jobNode, pathNodes, allWorkflows); finding != nil {
						findings = append(findings, *finding)
					}
				}

			case graph.NodeTypeStep:
				step := node.(*graph.StepNode)

				// Found unsafe checkout
				if step.HasTag(graph.TagUnsafeCheckout) {
					checkoutStep = step
					intermediateSteps = nil // Reset intermediate steps after checkout
					return true
				}

				// Track steps after checkout
				if checkoutStep != nil && step.Run == "" {
					intermediateSteps = append(intermediateSteps, step)
				}

				// If we found checkout and now see execution
				if checkoutStep != nil && step.Run != "" {
					// Build complete path: workflow → all intermediate jobs → current job → intermediate steps → checkout → sink
					pathNodes := []graph.Node{wf}
					for _, j := range intermediateJobs {
						pathNodes = append(pathNodes, j)
					}
					pathNodes = append(pathNodes, jobNode)
					for _, s := range intermediateSteps {
						pathNodes = append(pathNodes, s)
					}
					pathNodes = append(pathNodes, checkoutStep)
					if step != checkoutStep {
						pathNodes = append(pathNodes, step)
					}

					// Sort nodes by line number for execution order
					sortPathByLineNumber(pathNodes)

					findings = append(findings, createFindingWithPath(wf, pathNodes))
					checkoutStep = nil
					intermediateSteps = nil
				}
			}
			return true
		})
	}

	// Detect local workflow loading in privileged contexts.
	// When a workflow uses pull_request_target/issue_comment/workflow_run/discussion
	// and calls a local reusable workflow (uses: ./), the reusable workflow is loaded
	// from the PR branch (attacker-controlled), not the base branch. This allows
	// arbitrary code execution without requiring unsafe checkout.
	for _, wfNode := range zeroClickWorkflows {
		wf, ok := wfNode.(*graph.WorkflowNode)
		if !ok {
			continue
		}

		// Get all child nodes (jobs) of this workflow
		for _, childID := range g.Children(wf.ID()) {
			childNode, ok := g.GetNode(childID)
			if !ok {
				continue
			}
			job, ok := childNode.(*graph.JobNode)
			if !ok {
				continue
			}

			// Check if job uses a local reusable workflow (starts with ./)
			if job.Uses != "" && strings.HasPrefix(job.Uses, "./") {
				triggerName := getTriggerName(wf)

				pathNodes := []graph.Node{wf, job}
				attackChain := detections.BuildChainFromNodes(pathNodes...)

				var lineRanges []detections.LineRange
				if job.Line > 0 {
					lineRanges = []detections.LineRange{
						{
							Start: job.Line,
							End:   job.Line + 3,
							Label: "local reusable workflow call",
						},
					}
				}

				findings = append(findings, detections.Finding{
					Type:         detections.VulnPwnRequest,
					Platform:     "github",
					Class:        detections.ClassInjection,
					Severity:     detections.SeverityCritical,
					Confidence:   detections.ConfidenceHigh,
					Complexity:   detections.ComplexityZeroClick,
					Repository:   wf.RepoSlug,
					Workflow:     wf.Path,
					WorkflowFile: wf.Path,
					Job:          getJobName(job),
					Line:         job.Line,
					Trigger:      triggerName,
					Evidence:     fmt.Sprintf("Local workflow loading: Job with %s trigger uses local reusable workflow (uses: %s) which resolves from PR branch, allowing fork to execute arbitrary code", triggerName, job.Uses),
					Remediation:  "Use external reusable workflow with SHA pinning (org/repo/.github/workflows/name.yml@<sha>), or avoid reusable workflows in privileged triggers. Local workflows (uses: ./) resolve from PR branch, allowing fork to execute arbitrary code.",
					Details: &detections.FindingDetails{
						LineRanges:  lineRanges,
						AttackChain: attackChain,
						Metadata: map[string]interface{}{
							"local_workflow": job.Uses,
						},
					},
				})
			}
		}
	}

	return findings, nil
}

func createFindingWithPath(wf *graph.WorkflowNode, path []graph.Node) detections.Finding {
	// Extract key nodes from path
	var job *graph.JobNode
	var checkoutStep *graph.StepNode
	var sinkStep *graph.StepNode

	for _, node := range path {
		switch node.Type() {
		case graph.NodeTypeJob:
			job = node.(*graph.JobNode) // Keep updating to get the last job
		case graph.NodeTypeStep:
			step := node.(*graph.StepNode)
			if step.HasTag(graph.TagUnsafeCheckout) && checkoutStep == nil {
				checkoutStep = step
			} else if checkoutStep != nil && step.Run != "" && sinkStep == nil {
				sinkStep = step
			}
		}
	}

	return createFinding(wf, job, checkoutStep, sinkStep, path)
}

func createFinding(wf *graph.WorkflowNode, job *graph.JobNode, checkoutStep *graph.StepNode, sinkStep *graph.StepNode, fullPath []graph.Node) detections.Finding {
	// Extract checkout ref from step
	checkoutRef := ""
	if checkoutStep != nil && checkoutStep.With != nil {
		if ref, ok := checkoutStep.With["ref"]; ok {
			checkoutRef = ref
		}
	}

	// Get trigger name for evidence
	triggerName := getTriggerName(wf)

	// Build enhanced evidence message
	evidence := "pull_request_target with checkout of PR head"
	if checkoutRef != "" {
		evidence = "Workflow uses " + triggerName + " trigger and checks out PR code with ref " + checkoutRef + ". This allows attackers to execute arbitrary code with repository write permissions."
	}

	jobName := ""
	if job != nil {
		jobName = job.Name
	}

	// Build attack chain from complete path (includes all intermediate nodes)
	var attackChain []detections.ChainNode
	if len(fullPath) > 0 {
		attackChain = detections.BuildChainFromNodes(fullPath...)
	} else {
		// Fallback for cases without path tracking
		attackChain = detections.BuildChainFromNodes(wf, job, checkoutStep)
		if sinkStep != nil {
			attackChain = append(attackChain, detections.ChainNode{
				NodeType: "step",
				Name:     sinkStep.Name,
				Line:     sinkStep.Line,
			})
		}
	}

	// Create line ranges for the checkout step
	var lineRanges []detections.LineRange
	if checkoutStep != nil && checkoutStep.Line > 0 {
		lineRanges = []detections.LineRange{
			{
				Start: checkoutStep.Line,
				End:   checkoutStep.Line + 3, // Assume ~4 lines for checkout step
				Label: "vulnerable checkout",
			},
		}
	}

	// Get line number from checkout step
	line := 0
	if checkoutStep != nil {
		line = checkoutStep.Line
	}

	// Name the execution sink. Operators triaging at scale need the specific
	// command, not "may execute untrusted code, review to confirm." Gato-X
	// style: surface "Sink: <command>" in Evidence and the bare command in
	// Metadata[sink] for programmatic consumers.
	sinkCommand := ""
	if sinkStep != nil && sinkStep.Run != "" {
		sinkCommand = strings.Split(sinkStep.Run, "\n")[0]
		if len(sinkCommand) > 60 {
			sinkCommand = sinkCommand[:60] + "..."
		}
	}
	if sinkCommand != "" {
		evidence += " Sink: " + sinkCommand
	}

	metadata := make(map[string]interface{})
	if sinkCommand != "" {
		metadata["sink"] = sinkCommand
	}

	return detections.Finding{
		Type:         detections.VulnPwnRequest,
		Platform:     "github",
		Class:        detections.GetVulnerabilityClass(detections.VulnPwnRequest),
		Severity:     detections.SeverityCritical,
		Confidence:   detections.ConfidenceHigh,
		Complexity:   detections.ComplexityZeroClick,
		Repository:   wf.RepoSlug,
		Workflow:     wf.Path, // Use path for matching, not name
		WorkflowFile: wf.Path,
		Job:          jobName,
		Step:         checkoutStep.Name, // Set step name
		Line:         line,              // Set line number
		Trigger:      triggerName,
		Evidence:     evidence,
		Remediation:  "This pattern is risky even with immutable SHA refs. Consider using pull_request trigger instead of pull_request_target if write permissions are not needed, or use workflow_run with artifact passing to avoid running PR code in privileged context.",
		Details: &detections.FindingDetails{
			LineRanges:  lineRanges,
			AttackChain: attackChain,
			CheckoutRef: checkoutRef,
			Metadata:    metadata,
		},
	}
}

func getTriggerName(wf *graph.WorkflowNode) string {
	if len(wf.Triggers) > 0 {
		return wf.Triggers[0]
	}
	return "unknown"
}

// checkReusableWorkflowCallWithPath checks if a job calls a reusable workflow with unsafe checkouts
func checkReusableWorkflowCallWithPath(wf *graph.WorkflowNode, job *graph.JobNode, currentPath []graph.Node, allWorkflows map[string][]platforms.Workflow) *detections.Finding {
	// job.Uses should have the workflow path (e.g., ./.github/workflows/pr-plan.yml)
	if job.Uses == "" {
		return nil
	}

	repoSlug := wf.RepoSlug
	if repoSlug == "" {
		return nil
	}

	workflows, ok := allWorkflows[repoSlug]
	if !ok {
		return nil
	}

	// Find the called workflow
	var calledWorkflow *platforms.Workflow
	for i, checkWf := range workflows {
		// Match by path or suffix
		if strings.HasSuffix(checkWf.Path, job.Uses) || checkWf.Path == job.Uses || strings.HasSuffix(job.Uses, checkWf.Path) {
			calledWorkflow = &workflows[i]
			break
		}
	}

	if calledWorkflow == nil {
		return nil // Called workflow not found
	}

	// Check if called workflow has workflow_call trigger and unsafe checkouts
	content := string(calledWorkflow.Content)
	if !strings.Contains(content, "workflow_call") {
		return nil // Not a reusable workflow
	}

	// Check if it has unsafe checkout patterns
	hasUnsafeCheckout := strings.Contains(content, "actions/checkout") &&
		(strings.Contains(content, "steps.pr.outputs.head") ||
			strings.Contains(content, "steps.") && strings.Contains(content, "head") ||
			strings.Contains(content, "inputs.pr") ||
			strings.Contains(content, "github.event.pull_request.head"))

	if !hasUnsafeCheckout {
		return nil // No unsafe checkout in called workflow
	}

	// Found pwn-request through reusable workflow call
	triggerName := getTriggerName(wf)
	evidence := fmt.Sprintf("Workflow uses %s trigger and calls reusable workflow %s which checks out PR code. This enables arbitrary code execution through the called workflow chain.", triggerName, calledWorkflow.Path)

	// Build attack chain from complete path (includes all intermediate jobs/steps)
	attackChain := detections.BuildChainFromNodes(currentPath...)

	// Create line ranges for the job making the call
	var lineRanges []detections.LineRange
	if job.Line > 0 {
		lineRanges = []detections.LineRange{
			{
				Start: job.Line,
				End:   job.Line + 5, // Job definition with uses: call
				Label: "reusable workflow call",
			},
		}
	}

	return &detections.Finding{
		Type:         detections.VulnPwnRequest,
		Platform:     "github",
		Class:        detections.GetVulnerabilityClass(detections.VulnPwnRequest),
		Severity:     detections.SeverityCritical,
		Confidence:   detections.ConfidenceHigh,
		Complexity:   detections.ComplexityZeroClick,
		Repository:   wf.RepoSlug,
		Workflow:     wf.Path,
		WorkflowFile: wf.Path,
		Job:          getJobName(job),
		Line:         job.Line,
		Trigger:      triggerName,
		Evidence:     evidence,
		Details: &detections.FindingDetails{
			LineRanges:  lineRanges,
			AttackChain: attackChain,
			Metadata: map[string]interface{}{
				"called_workflow": calledWorkflow.Path,
				"cross_workflow":  true,
			},
		},
	}
}

func getJobName(job *graph.JobNode) string {
	if job.Name != "" {
		return job.Name
	}
	// Extract job name from ID
	parts := strings.Split(job.ID(), ":job:")
	if len(parts) > 1 {
		return parts[1]
	}
	return ""
}

// sortPathByLineNumber sorts nodes by line number for execution order
func sortPathByLineNumber(nodes []graph.Node) {
	sort.Slice(nodes, func(i, j int) bool {
		lineI := getNodeLine(nodes[i])
		lineJ := getNodeLine(nodes[j])

		// Workflow node always first (line 0)
		if lineI == 0 {
			return true
		}
		if lineJ == 0 {
			return false
		}

		return lineI < lineJ
	})
}

// getNodeLine extracts line number from any node type
func getNodeLine(node graph.Node) int {
	switch n := node.(type) {
	case *graph.WorkflowNode:
		return 0 // Workflow always first
	case *graph.JobNode:
		return n.Line
	case *graph.StepNode:
		return n.Line
	default:
		return 0
	}
}
