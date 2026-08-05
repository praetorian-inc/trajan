// pkg/analysis/graph/graph.go
package graph

import (
	"strings"
	"sync"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// EdgeType represents the relationship between nodes
type EdgeType string

const (
	EdgeContains EdgeType = "contains" // Workflow contains Job, Job contains Step
	EdgeUses     EdgeType = "uses"     // Step uses Action
	EdgeDepends  EdgeType = "depends"  // Job depends on (needs) Job
	EdgeTriggers EdgeType = "triggers" // Workflow triggers Workflow (workflow_run)
	EdgeIncludes EdgeType = "includes" // Workflow includes another workflow
)

// Edge represents a directed edge in the graph
type Edge struct {
	From string
	To   string
	Type EdgeType
}

// Graph represents a workflow graph with nodes and edges
type Graph struct {
	nodes    map[string]Node
	edges    map[string][]Edge      // from -> edges
	tags     map[Tag][]string       // tag -> node IDs
	metadata map[string]interface{} // platform-level context (runners, secrets, etc.)
	mu       sync.RWMutex
}

// NewGraph creates a new empty graph
func NewGraph() *Graph {
	return &Graph{
		nodes:    make(map[string]Node),
		edges:    make(map[string][]Edge),
		tags:     make(map[Tag][]string),
		metadata: make(map[string]interface{}),
	}
}

// AddNode adds a node to the graph
func (g *Graph) AddNode(node Node) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.nodes[node.ID()] = node

	// Index by tags
	for _, tag := range node.Tags() {
		g.tags[tag] = append(g.tags[tag], node.ID())
	}
}

// GetNode returns a node by ID
func (g *Graph) GetNode(id string) (Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	node, ok := g.nodes[id]
	return node, ok
}

// AddEdge adds a directed edge between two nodes
func (g *Graph) AddEdge(from, to string, edgeType EdgeType) {
	g.mu.Lock()
	defer g.mu.Unlock()

	edge := Edge{From: from, To: to, Type: edgeType}
	g.edges[from] = append(g.edges[from], edge)

	// Set parent reference
	if node, ok := g.nodes[to]; ok {
		node.SetParent(from)
	}
}

// Children returns the IDs of nodes connected from the given node
func (g *Graph) Children(id string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	edges := g.edges[id]
	children := make([]string, 0, len(edges))
	for _, edge := range edges {
		children = append(children, edge.To)
	}
	return children
}

// GetIncomingEdges returns all edges pointing to the given node ID
func (g *Graph) GetIncomingEdges(id string) []Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var incoming []Edge
	for _, edges := range g.edges {
		for _, edge := range edges {
			if edge.To == id {
				incoming = append(incoming, edge)
			}
		}
	}
	return incoming
}

// GetNodesByTag returns all nodes with the given tag
func (g *Graph) GetNodesByTag(tag Tag) []Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	ids := g.tags[tag]
	nodes := make([]Node, 0, len(ids))
	for _, id := range ids {
		if node, ok := g.nodes[id]; ok {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// GetNodesByType returns all nodes of the given type
func (g *Graph) GetNodesByType(nodeType NodeType) []Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var nodes []Node
	for _, node := range g.nodes {
		if node.Type() == nodeType {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// Nodes returns all nodes in the graph
func (g *Graph) Nodes() []Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]Node, 0, len(g.nodes))
	for _, node := range g.nodes {
		nodes = append(nodes, node)
	}
	return nodes
}

// NodeCount returns the number of nodes
func (g *Graph) NodeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

// SetMetadata stores platform-level context in the graph
func (g *Graph) SetMetadata(key string, value interface{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.metadata[key] = value
}

// GetMetadata retrieves platform-level context from the graph
func (g *Graph) GetMetadata(key string) (interface{}, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	val, ok := g.metadata[key]
	return val, ok
}

// GetIncludedWorkflows retrieves all included workflows from graph metadata
// Returns workflows from external repositories that were included during graph building
// Used by executor to populate workflows map for code context rendering
func (g *Graph) GetIncludedWorkflows(repoSlug string) []platforms.Workflow {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var workflows []platforms.Workflow

	for key, value := range g.metadata {
		if !strings.HasPrefix(key, "included_workflow:") {
			continue
		}

		if wf, ok := value.(platforms.Workflow); ok {
			// Return all included workflows regardless of their repo
			// These are by definition from external sources (includes)
			workflows = append(workflows, wf)
		}
	}

	return workflows
}
