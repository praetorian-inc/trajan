package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/olekukonko/tablewriter"

	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func RenderDetailed(w io.Writer, result *platforms.ScanResult, findings []detections.Finding) {
	if len(findings) == 0 {
		_, _ = fmt.Fprintln(w, "\nNo vulnerabilities found.")
		return
	}

	byRepo := make(map[string][]detections.Finding)
	for _, f := range findings {
		byRepo[f.Repository] = append(byRepo[f.Repository], f)
	}

	repos := make([]string, 0, len(byRepo))
	for repo := range byRepo {
		repos = append(repos, repo)
	}
	sort.Strings(repos)

	for _, repo := range repos {
		repoFindings := byRepo[repo]

		sort.Slice(repoFindings, func(i, j int) bool {
			rankI := severityRank(repoFindings[i].Severity)
			rankJ := severityRank(repoFindings[j].Severity)
			if rankI != rankJ {
				return rankI < rankJ
			}
			return repoFindings[i].Type < repoFindings[j].Type
		})

		printRepoHeader(w, repo, len(repoFindings))

		for i, finding := range repoFindings {
			printFindingDetailed(w, result, finding)

			if i < len(repoFindings)-1 {
				_, _ = fmt.Fprintln(w, "\n─────────────────────────────────────────────")
			}
		}

		_, _ = fmt.Fprintln(w)
	}
}

func printRepoHeader(w io.Writer, repo string, count int) {
	_, _ = fmt.Fprintln(w, "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	_, _ = fmt.Fprintf(w, "Repository: %s (%d finding", repo, count)
	if count != 1 {
		_, _ = fmt.Fprint(w, "s")
	}
	_, _ = fmt.Fprintln(w, ")")
	_, _ = fmt.Fprintln(w, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func printFindingDetailed(w io.Writer, result *platforms.ScanResult, f detections.Finding) {
	severityText := fmt.Sprintf("[%s]", strings.ToUpper(string(f.Severity)))
	color := severityColor(f.Severity)
	_, _ = fmt.Fprintf(w, "\n  %s\n", colorText(severityText, color))
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "  %s %s\n", colorText("Finding:", tablewriter.FgMagentaColor), f.Type)

	_, _ = fmt.Fprintf(w, "  %s %s\n", colorText("Workflow:", tablewriter.FgMagentaColor), f.Workflow)

	locationParts := []string{fmt.Sprintf("Line %d", f.Line)}
	if f.Job != "" {
		locationParts = append(locationParts, fmt.Sprintf("Job: %s", f.Job))
	}
	if f.Step != "" {
		locationParts = append(locationParts, fmt.Sprintf("Step: %s", f.Step))
	}
	_, _ = fmt.Fprintf(w, "  %s %s\n", colorText("Location:", tablewriter.FgMagentaColor), strings.Join(locationParts, ", "))

	if f.Evidence != "" {
		_, _ = fmt.Fprintf(w, "\n  %s\n", colorText("Description:", tablewriter.FgMagentaColor))
		_, _ = fmt.Fprintf(w, "  %s\n", wrapText(f.Evidence, 78))
	}

	if f.Details != nil && len(f.Details.AttackChain) > 0 {
		printAttackChain(w, f.Details.AttackChain)
	}

	if f.Details != nil {
		if len(f.Details.AttackChain) > 1 {
			printMultiJobContext(w, result, f)
		} else if len(f.Details.LineRanges) > 0 {
			printCodeContext(w, result, f)
		}
	}

	if f.Details != nil && f.Details.Metadata != nil {
		if calledWfPath, ok := f.Details.Metadata["called_workflow"]; ok {
			if pathStr, ok := calledWfPath.(string); ok {
				printCalledWorkflowContext(w, result, f.Repository, pathStr)
			}
		}
	}

	if f.Details != nil && f.Details.Metadata != nil {
		if sink, ok := f.Details.Metadata["sink"]; ok {
			_, _ = fmt.Fprintf(w, "\n  %s\n", colorText("Sink:", tablewriter.FgMagentaColor))
			_, _ = fmt.Fprintf(w, "  %s\n", sink)
		}
	}

	if f.Details != nil && len(f.Details.InjectableContexts) > 0 {
		_, _ = fmt.Fprintf(w, "\n  %s\n", colorText("Injectable Contexts:", tablewriter.FgMagentaColor))
		for _, ctx := range f.Details.InjectableContexts {
			_, _ = fmt.Fprintf(w, "    • %s\n", ctx)
		}
	}

	if f.Details != nil && len(f.Details.Permissions) > 0 {
		_, _ = fmt.Fprintf(w, "\n  %s\n", colorText("Write Permissions:", tablewriter.FgMagentaColor))
		for _, perm := range f.Details.Permissions {
			_, _ = fmt.Fprintf(w, "    • %s\n", perm)
		}
	}
}

func printAttackChain(w io.Writer, chain []detections.ChainNode) {
	_, _ = fmt.Fprintf(w, "\n  %s\n", colorText("Attack Chain:", tablewriter.FgMagentaColor))

	for _, node := range chain {
		if node.Line > 0 {
			_, _ = fmt.Fprintf(w, "  → %s: %s (line %d)\n", node.NodeType, node.Name, node.Line)
		} else {
			_, _ = fmt.Fprintf(w, "  → %s: %s\n", node.NodeType, node.Name)
		}

		if node.IfCondition != "" {
			_, _ = fmt.Fprintf(w, "    ↪ If: %s\n", node.IfCondition)
		}
	}
}

func printCodeContext(w io.Writer, result *platforms.ScanResult, f detections.Finding) {
	workflows, ok := result.Workflows[f.Repository]
	if !ok {
		return
	}

	var workflowContent []byte
	for _, wf := range workflows {
		// A finding may carry either the workflow name or its path.
		if wf.Path == f.Workflow || strings.HasSuffix(wf.Path, f.Workflow) || wf.Name == f.Workflow {
			workflowContent = wf.Content
			break
		}
	}

	if len(workflowContent) == 0 {
		return
	}

	lines := strings.Split(string(workflowContent), "\n")

	_, _ = fmt.Fprintf(w, "\n  %s\n", colorText("Code Context:", tablewriter.FgMagentaColor))
	_, _ = fmt.Fprintln(w, "  ───────────────────────────────────────────")

	// Merged so an overlapping range cannot print the same line twice.
	mergedRanges := mergeLineRanges(f.Details.LineRanges, 2)

	if len(mergedRanges) > 0 {
		displayStart := max(1, mergedRanges[0].Start-2)
		displayEnd := min(len(lines), mergedRanges[len(mergedRanges)-1].End+2)

		isHighlighted := func(lineNum int) bool {
			for _, r := range f.Details.LineRanges {
				if lineNum >= r.Start && lineNum <= r.End {
					return true
				}
			}
			return false
		}

		for i := displayStart; i <= displayEnd; i++ {
			if i > len(lines) {
				break
			}

			lineNum := fmt.Sprintf("%4d", i)
			lineContent := lines[i-1] // lines are 0-indexed

			// Highlight against the original ranges, not the merged ones.
			if isHighlighted(i) {
				_, _ = fmt.Fprintf(w, "  %s → %s\n",
					colorText(lineNum, tablewriter.FgYellowColor),
					colorText(lineContent, tablewriter.FgYellowColor))
			} else {
				_, _ = fmt.Fprintf(w, "  %s   %s\n", lineNum, lineContent)
			}
		}
	}

	_, _ = fmt.Fprintln(w, "  ───────────────────────────────────────────")
}

func printMultiJobContext(w io.Writer, result *platforms.ScanResult, f detections.Finding) {
	_, _ = fmt.Fprintf(w, "\n  %s\n", colorText("Code Context:", tablewriter.FgMagentaColor))
	_, _ = fmt.Fprintln(w, "  ───────────────────────────────────────────")

	workflows, ok := result.Workflows[f.Repository]
	if !ok {
		return
	}

	var workflowContent []byte
	for _, wf := range workflows {
		if wf.Path == f.Workflow || strings.HasSuffix(wf.Path, f.Workflow) || wf.Name == f.Workflow {
			workflowContent = wf.Content
			break
		}
	}

	if len(workflowContent) == 0 {
		return
	}

	lines := strings.Split(string(workflowContent), "\n")
	shownJobs := make(map[int]bool)
	shownLines := make(map[int]bool)

	hasStepDetails := len(f.Details.LineRanges) > 0
	lastJobLine := 0
	if hasStepDetails {
		for i := len(f.Details.AttackChain) - 1; i >= 0; i-- {
			if f.Details.AttackChain[i].NodeType == "job" {
				lastJobLine = f.Details.AttackChain[i].Line
				break
			}
		}
	}

	for _, chainNode := range f.Details.AttackChain {
		if chainNode.NodeType == "job" && chainNode.Line > 0 && !shownJobs[chainNode.Line] {
			// The last job is shown in full detail below.
			if hasStepDetails && chainNode.Line == lastJobLine {
				continue
			}

			start := max(1, chainNode.Line-1)
			end := min(len(lines), chainNode.Line+3)

			for i := start; i <= end; i++ {
				if i > len(lines) {
					break
				}
				lineNum := fmt.Sprintf("%4d", i)
				content := lines[i-1]

				if i == chainNode.Line {
					_, _ = fmt.Fprintf(w, "  %s → %s (Job: %s)\n",
						colorText(lineNum, tablewriter.FgYellowColor),
						colorText(content, tablewriter.FgYellowColor),
						chainNode.Name)
				} else {
					_, _ = fmt.Fprintf(w, "  %s   %s\n", lineNum, content)
				}
				shownLines[i] = true
			}
			_, _ = fmt.Fprintln(w)
			shownJobs[chainNode.Line] = true
		}
	}

	if hasStepDetails {
		mergedRanges := mergeLineRanges(f.Details.LineRanges, 2)

		if len(mergedRanges) > 0 {
			displayStart := max(1, mergedRanges[0].Start-2)
			displayEnd := min(len(lines), mergedRanges[len(mergedRanges)-1].End+2)

			isHighlighted := func(lineNum int) bool {
				for _, r := range f.Details.LineRanges {
					if lineNum >= r.Start && lineNum <= r.End {
						return true
					}
				}
				return false
			}

			for i := displayStart; i <= displayEnd; i++ {
				if i > len(lines) {
					break
				}

				lineNum := fmt.Sprintf("%4d", i)
				lineContent := lines[i-1]

				if isHighlighted(i) {
					_, _ = fmt.Fprintf(w, "  %s → %s\n",
						colorText(lineNum, tablewriter.FgYellowColor),
						colorText(lineContent, tablewriter.FgYellowColor))
				} else {
					_, _ = fmt.Fprintf(w, "  %s   %s\n", lineNum, lineContent)
				}
			}
		}
	}

	_, _ = fmt.Fprintln(w, "  ───────────────────────────────────────────")
}

func printCalledWorkflowContext(w io.Writer, result *platforms.ScanResult, repo, calledWorkflowPath string) {
	workflows, ok := result.Workflows[repo]
	if !ok {
		return
	}

	var calledWorkflow *platforms.Workflow
	for i, wf := range workflows {
		if wf.Path == calledWorkflowPath || strings.HasSuffix(wf.Path, calledWorkflowPath) {
			calledWorkflow = &workflows[i]
			break
		}
	}

	if calledWorkflow == nil {
		return
	}

	lines := strings.Split(string(calledWorkflow.Content), "\n")

	for i, line := range lines {
		if strings.Contains(line, "actions/checkout") {
			start := max(1, i+1-2)
			end := min(len(lines), i+1+5)

			_, _ = fmt.Fprintf(w, "\n  %s\n", colorText("Called Workflow ("+calledWorkflowPath+"):", tablewriter.FgMagentaColor))
			_, _ = fmt.Fprintln(w, "  ───────────────────────────────────────────")

			for lineNum := start; lineNum <= end; lineNum++ {
				if lineNum > len(lines) {
					break
				}

				numStr := fmt.Sprintf("%4d", lineNum)
				content := lines[lineNum-1]

				// The checkout line plus the three that may carry ref:.
				if lineNum >= i+1 && lineNum <= i+4 {
					_, _ = fmt.Fprintf(w, "  %s → %s\n",
						colorText(numStr, tablewriter.FgYellowColor),
						colorText(content, tablewriter.FgYellowColor))
				} else {
					_, _ = fmt.Fprintf(w, "  %s   %s\n", numStr, content)
				}
			}

			_, _ = fmt.Fprintln(w, "  ───────────────────────────────────────────")
			break // Only show first checkout
		}
	}
}

func colorText(text string, color int) string {
	// color is a tablewriter code (30-37, 90-97), emitted as a raw ANSI escape.
	return fmt.Sprintf("\033[%dm%s\033[0m", color, text)
}

// Continuation lines are indented two spaces to match the caller's layout.
func wrapText(text string, width int) string {
	if len(text) <= width {
		return text
	}

	words := strings.Fields(text)
	if len(words) == 0 {
		return text
	}

	var lines []string
	var currentLine string

	for _, word := range words {
		if len(currentLine)+len(word)+1 <= width {
			if currentLine == "" {
				currentLine = word
			} else {
				currentLine += " " + word
			}
		} else {
			if currentLine != "" {
				lines = append(lines, currentLine)
			}
			currentLine = word
		}
	}

	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return strings.Join(lines, "\n  ")
}

func mergeLineRanges(ranges []detections.LineRange, contextPadding int) []detections.LineRange {
	if len(ranges) == 0 {
		return nil
	}

	sorted := make([]detections.LineRange, len(ranges))
	copy(sorted, ranges)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].Start < sorted[i].Start {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	merged := []detections.LineRange{sorted[0]}
	for i := 1; i < len(sorted); i++ {
		current := sorted[i]
		last := &merged[len(merged)-1]

		if current.Start-contextPadding <= last.End+contextPadding {
			if current.End > last.End {
				last.End = current.End
			}
		} else {
			merged = append(merged, current)
		}
	}

	return merged
}
