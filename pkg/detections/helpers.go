// pkg/detections/helpers.go
package detections

import (
	"strings"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

// BuildChainFromNodes creates an attack chain from a sequence of graph nodes.
// Useful for detections that track attack paths (pwn-request, injection, toctou).
func BuildChainFromNodes(nodes ...graph.Node) []ChainNode {
	if len(nodes) == 0 {
		return nil
	}

	chain := make([]ChainNode, 0, len(nodes))
	for _, node := range nodes {
		chainNode := ChainNode{}

		// Set node type and extract fields based on graph node type
		switch node.Type() {
		case graph.NodeTypeWorkflow:
			chainNode.NodeType = "trigger"
			if wf, ok := node.(*graph.WorkflowNode); ok {
				chainNode.Name = wf.Name
				// Get first trigger as name
				if len(wf.Triggers) > 0 {
					chainNode.Name = wf.Triggers[0]
				}
			}
			// If workflow has no trigger, try to get from first job in chain
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

// IsExecutionSink determines if a run command actually executes code vs just validates.
// Used by artifact-poisoning and cache-poisoning detections to reduce false positives.
func IsExecutionSink(runCmd string) bool {
	if runCmd == "" {
		return false
	}

	cmdLower := strings.ToLower(runCmd)

	// Execution patterns (actual code execution from artifact/cache).
	// Tools added beyond bash/sh/python/node mirror the Gato-X SINKS list —
	// each executes attacker-controlled code from a checked-out repo or
	// restored cache (lifecycle scripts, build hooks, conftest.py, etc.).
	executionPatterns := []string{
		"./",             // Execute local script
		" bash ",         // Bash execution (with spaces to avoid matching "subash")
		"\nbash ",        // Bash at line start
		" sh ",           // Shell execution (with spaces to avoid matching "sha256sum")
		"\nsh ",          // Shell at line start
		"/bin/",          // Binary execution
		" python ",       // Python execution
		"\npython ",      // Python at line start
		" node ",         // Node execution
		"\nnode ",        // Node at line start
		" npm ",          // npm commands
		"\nnpm ",         // npm at line start
		" pnpm ",         // pnpm commands (TanStack-class supply-chain vector)
		"\npnpm ",        // pnpm at line start
		" yarn ",         // yarn commands
		"\nyarn ",        // yarn at line start
		" bun ",          // bun (lifecycle scripts like npm)
		"\nbun ",         // bun at line start
		" poetry ",       // poetry (runs setup.py / build hooks)
		"\npoetry ",      // poetry at line start
		" cargo ",        // cargo (build.rs executes)
		"\ncargo ",       // cargo at line start
		" go run ",       // go run main.go etc.
		"\ngo run ",      // go run at line start
		" go generate ",  // go generate triggers //go:generate directives
		"\ngo generate ", // go generate at line start
		" make ",         // make (Makefile targets execute commands)
		"\nmake ",        // make at line start
		" mvn ",          // maven (pom.xml plugins execute)
		"\nmvn ",         // mvn at line start
		" gradle ",       // gradle (build.gradle Groovy/Kotlin executes)
		"\ngradle ",      // gradle at line start
		" pytest ",       // pytest (conftest.py executes on collection)
		"\npytest ",      // pytest at line start
		" source ",       // Source script
		"\nsource ",      // Source at line start
		" eval ",         // Eval command
		" exec ",         // Exec command
	}

	for _, pattern := range executionPatterns {
		if strings.Contains(cmdLower, pattern) {
			return true
		}
	}

	// Check if command starts with a known execution command.
	// The patterns above require a leading space/newline, but run: values
	// like "npm run build" start directly with the command.
	commandPrefixes := []string{
		"bash ", "sh ", "python ", "node ",
		"npm ", "pnpm ", "yarn ", "bun ",
		"poetry ", "cargo ",
		"go run ", "go generate ",
		"make ", "mvn ", "gradle ", "pytest ",
		"source ", "eval ", "exec ",
	}
	for _, prefix := range commandPrefixes {
		if strings.HasPrefix(cmdLower, prefix) {
			return true
		}
	}

	return false
}
