package graph

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func buildTestGraph() *Graph {
	g := NewGraph()

	// Workflow -> Job -> Step1 -> Step2
	workflow := NewWorkflowNode("wf", "Build", "build.yml", "owner/repo", []string{"push"})
	job := NewJobNode("job", "build", "ubuntu-latest")
	step1 := NewStepNode("step1", "Checkout", 10)
	step1.AddTag(TagCheckout)
	step2 := NewStepNode("step2", "Build", 15)

	g.AddNode(workflow)
	g.AddNode(job)
	g.AddNode(step1)
	g.AddNode(step2)

	g.AddEdge("wf", "job", EdgeContains)
	g.AddEdge("job", "step1", EdgeContains)
	g.AddEdge("job", "step2", EdgeContains)

	return g
}

func TestDFS(t *testing.T) {
	g := buildTestGraph()

	var visited []string
	DFS(g, "wf", func(node Node) bool {
		visited = append(visited, node.ID())
		return true
	})

	assert.Contains(t, visited, "wf")
	assert.Contains(t, visited, "job")
	assert.Contains(t, visited, "step1")
	assert.Contains(t, visited, "step2")
}

func TestDFS_StopEarly(t *testing.T) {
	g := buildTestGraph()

	var visited []string
	DFS(g, "wf", func(node Node) bool {
		visited = append(visited, node.ID())
		return node.ID() != "job"
	})

	assert.Contains(t, visited, "wf")
	assert.Contains(t, visited, "job")
	assert.NotContains(t, visited, "step1")
}
