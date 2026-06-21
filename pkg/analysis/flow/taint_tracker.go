// modules/trajan/pkg/analysis/flow/taint_tracker.go
package flow

import (
	"context"
	"regexp"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections/shared/taintsources"
)

// TaintTracker performs taint analysis on workflow graphs
type TaintTracker struct {
	exprRegex      *regexp.Regexp
	taintedSources map[string]TaintSource
}

// NewTaintTracker creates a new taint tracker
func NewTaintTracker() *TaintTracker {
	return &TaintTracker{
		exprRegex:      regexp.MustCompile(`\$\{\{\s*(.+?)\s*\}\}`),
		taintedSources: buildTaintedSourcesMap(),
	}
}

// buildTaintedSourcesMap creates the map of known tainted sources
func buildTaintedSourcesMap() map[string]TaintSource {
	sources := make(map[string]TaintSource)
	for _, s := range taintsources.GitHubTaintedContexts {
		sources[s] = TaintSourceUserInput
	}

	// Add fork-related sources
	sources["github.event.pull_request.head.repo.fork"] = TaintSourceFork

	return sources
}

// Analyze performs taint analysis on the workflow graph
func (tt *TaintTracker) Analyze(ctx context.Context, g *graph.Graph) (map[string]*FlowContext, error) {
	result := make(map[string]*FlowContext)

	// Get all workflows
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)

	for _, wfNode := range workflows {
		wf, ok := wfNode.(*graph.WorkflowNode)
		if !ok {
			continue
		}

		// Create initial context for workflow
		wfCtx := NewFlowContext()

		// Analyze workflow-level env
		if wf.Env != nil {
			for key, value := range wf.Env {
				wfCtx.EnvLookup[key] = value
				tt.checkAndAddTaint(value, "env."+key, wfCtx)
			}
		}

		// DFS through all nodes
		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			nodeCtx := tt.analyzeNode(node, wfCtx)
			if nodeCtx != nil {
				result[node.ID()] = nodeCtx
			}
			return true
		})
	}

	return result, nil
}

// analyzeNode performs taint analysis on a single node
func (tt *TaintTracker) analyzeNode(node graph.Node, parentCtx *FlowContext) *FlowContext {
	// Create context inheriting from parent
	ctx := &FlowContext{
		InputLookup:        copyMap(parentCtx.InputLookup),
		EnvLookup:          copyMap(parentCtx.EnvLookup),
		StepOutputs:        copyMap(parentCtx.StepOutputs),
		ApprovalGate:       parentCtx.ApprovalGate,
		GateDetails:        parentCtx.GateDetails,
		TaintMap:           copyTaintMap(parentCtx.TaintMap),
		TaintedExpressions: []string{},
	}

	switch n := node.(type) {
	case *graph.JobNode:
		// Analyze job-level env
		if n.Env != nil {
			for key, value := range n.Env {
				ctx.EnvLookup[key] = value
				tt.checkAndAddTaint(value, "env."+key, ctx)
			}
		}

	case *graph.StepNode:
		// Analyze step env
		if n.Env != nil {
			for key, value := range n.Env {
				ctx.EnvLookup[key] = value
				tt.checkAndAddTaint(value, "env."+key, ctx)
			}
		}

		// Analyze run command for tainted expressions
		if n.Run != "" {
			tt.analyzeExpression(n.Run, ctx)
		}

		// Analyze 'with' inputs
		if n.With != nil {
			for key, value := range n.With {
				tt.checkAndAddTaint(value, "inputs."+key, ctx)
			}
		}
	}

	return ctx
}

// checkAndAddTaint checks if a value contains tainted references and adds them
func (tt *TaintTracker) checkAndAddTaint(value, variable string, ctx *FlowContext) {
	matches := tt.exprRegex.FindAllStringSubmatch(value, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		expr := strings.TrimSpace(match[1])

		// Check if expression references a tainted source
		for taintedRef, source := range tt.taintedSources {
			if containsRef(expr, taintedRef) {
				tv := NewTaintedValue(value, source, taintedRef)
				ctx.AddTaint(variable, tv.PropagateThrough(variable))
			}
		}

		// Also check if expression references an already-tainted variable
		for taintedVar := range ctx.TaintMap {
			if containsRef(expr, taintedVar) {
				ctx.PropagateTaint(taintedVar, variable)
			}
		}
	}
}

// analyzeExpression analyzes an expression for tainted references
func (tt *TaintTracker) analyzeExpression(expr string, ctx *FlowContext) {
	matches := tt.exprRegex.FindAllStringSubmatch(expr, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		innerExpr := strings.TrimSpace(match[1])

		// Check against known tainted sources
		for taintedRef := range tt.taintedSources {
			if containsRef(innerExpr, taintedRef) {
				ctx.AddTaintedExpression(match[0])
			}
		}

		// Check against propagated taints
		for taintedVar := range ctx.TaintMap {
			if containsRef(innerExpr, taintedVar) {
				ctx.AddTaintedExpression(match[0])
			}
		}
	}
}

// containsRef checks if expr contains ref as a complete reference
// (not as a substring of a longer reference like body_html matching body)
func containsRef(expr, ref string) bool {
	idx := strings.Index(expr, ref)
	if idx == -1 {
		return false
	}
	end := idx + len(ref)
	if end < len(expr) {
		next := expr[end]
		if next == '_' || next == '.' || (next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z') || (next >= '0' && next <= '9') {
			return false
		}
	}
	return true
}

// Helper functions
func copyMap(m map[string]string) map[string]string {
	result := make(map[string]string, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

func copyTaintMap(m map[string]*TaintedValue) map[string]*TaintedValue {
	result := make(map[string]*TaintedValue, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}
