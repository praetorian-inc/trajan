package detections

import (
	"strings"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

func BuildChainFromNodes(nodes ...graph.Node) []ChainNode {
	if len(nodes) == 0 {
		return nil
	}

	chain := make([]ChainNode, 0, len(nodes))
	for _, node := range nodes {
		chainNode := ChainNode{}

		switch node.Type() {
		case graph.NodeTypeWorkflow:
			chainNode.NodeType = "trigger"
			if wf, ok := node.(*graph.WorkflowNode); ok {
				chainNode.Name = wf.Name
				if len(wf.Triggers) > 0 {
					chainNode.Name = wf.Triggers[0]
				}
			}
			// nodes[1] is the job that follows the workflow in the chain.
			if chainNode.Name == "" && len(nodes) > 1 {
				if job, ok := nodes[1].(*graph.JobNode); ok {
					if len(job.ComputedTriggers) > 0 {
						chainNode.Name = job.ComputedTriggers[0]
					}
				}
			}
		case graph.NodeTypeJob:
			chainNode.NodeType = "job"
			if job, ok := node.(*graph.JobNode); ok {
				chainNode.Name = job.Name
				chainNode.Line = job.Line
				chainNode.IfCondition = job.If
			}
		case graph.NodeTypeStep:
			chainNode.NodeType = "step"
			if step, ok := node.(*graph.StepNode); ok {
				chainNode.Name = step.Name
				chainNode.Line = step.Line
				chainNode.IfCondition = step.If
			}
		default:
			chainNode.NodeType = string(node.Type())
		}

		chain = append(chain, chainNode)
	}

	return chain
}

// Distinguishes a run: that executes downloaded content from one that merely inspects it;
// artifact- and cache-poisoning detections use it to suppress false positives.
func IsExecutionSink(runCmd string) bool {
	if runCmd == "" {
		return false
	}

	cmdLower := strings.ToLower(runCmd)

	executionPatterns := []string{
		"./",
		" bash ", // Spaced so that "subash" does not match.
		"\nbash ",
		" sh ", // Spaced so that "sha256sum" does not match.
		"\nsh ",
		"/bin/",
		" python ",
		"\npython ",
		" node ",
		"\nnode ",
		" npm ",
		"\nnpm ",
		" yarn ",
		"\nyarn ",
		" source ",
		"\nsource ",
		" eval ",
		" exec ",
	}

	for _, pattern := range executionPatterns {
		if strings.Contains(cmdLower, pattern) {
			return true
		}
	}

	// The patterns above need a leading space or newline, but a run: value like
	// "npm run build" starts directly with the command.
	commandPrefixes := []string{
		"bash ", "sh ", "python ", "node ", "npm ", "yarn ",
		"source ", "eval ", "exec ",
	}
	for _, prefix := range commandPrefixes {
		if strings.HasPrefix(cmdLower, prefix) {
			return true
		}
	}

	return false
}
