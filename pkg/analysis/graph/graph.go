package graph

import (
	"strings"
	"sync"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

type EdgeType string

const (
	EdgeContains EdgeType = "contains" // Workflow contains Job, Job contains Step
	EdgeUses     EdgeType = "uses"     // Step uses Action
	EdgeDepends  EdgeType = "depends"  // Job depends on (needs) Job
	EdgeTriggers EdgeType = "triggers" // Workflow triggers Workflow (workflow_run)
	EdgeIncludes EdgeType = "includes" // Workflow includes another workflow
)

type Edge struct {
	From string
	To   string
	Type EdgeType
}

type Graph struct {
	nodes    map[string]Node
	edges    map[string][]Edge      // from -> edges
	tags     map[Tag][]string       // tag -> node IDs
	metadata map[string]interface{} // platform-level context (runners, secrets, etc.)
	mu       sync.RWMutex
}

func NewGraph() *Graph {
	return &Graph{
		nodes:    make(map[string]Node),
		edges:    make(map[string][]Edge),
		tags:     make(map[Tag][]string),
		metadata: make(map[string]interface{}),
	}
}

func (g *Graph) AddNode(node Node) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.nodes[node.ID()] = node

	for _, tag := range node.Tags() {
		g.tags[tag] = append(g.tags[tag], node.ID())
	}
}

func (g *Graph) GetNode(id string) (Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	node, ok := g.nodes[id]
	return node, ok
}

func (g *Graph) AddEdge(from, to string, edgeType EdgeType) {
	g.mu.Lock()
	defer g.mu.Unlock()

	edge := Edge{From: from, To: to, Type: edgeType}
	g.edges[from] = append(g.edges[from], edge)

	if node, ok := g.nodes[to]; ok {
		node.SetParent(from)
	}
}

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

func (g *Graph) Nodes() []Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]Node, 0, len(g.nodes))
	for _, node := range g.nodes {
		nodes = append(nodes, node)
	}
	return nodes
}

func (g *Graph) NodeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

func (g *Graph) SetMetadata(key string, value interface{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.metadata[key] = value
}

func (g *Graph) GetMetadata(key string) (interface{}, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	val, ok := g.metadata[key]
	return val, ok
}

func (g *Graph) GetIncludedWorkflows(repoSlug string) []platforms.Workflow {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var workflows []platforms.Workflow

	for key, value := range g.metadata {
		if !strings.HasPrefix(key, "included_workflow:") {
			continue
		}

		if wf, ok := value.(platforms.Workflow); ok {
			// Includes are external by definition, so repoSlug does not narrow the result.
			workflows = append(workflows, wf)
		}
	}

	return workflows
}
