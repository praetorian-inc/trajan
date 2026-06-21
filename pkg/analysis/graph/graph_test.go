// pkg/analysis/graph/graph_test.go
package graph

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestGraph_AddNode(t *testing.T) {
	g := NewGraph()

	workflow := NewWorkflowNode("wf1", "Build", ".github/workflows/build.yml", "owner/repo", []string{"push"})
	g.AddNode(workflow)

	node, ok := g.GetNode("wf1")
	require.True(t, ok)
	assert.Equal(t, "Build", node.(*WorkflowNode).Name)
}

func TestGraph_AddEdge(t *testing.T) {
	g := NewGraph()

	workflow := NewWorkflowNode("wf1", "Build", "build.yml", "owner/repo", []string{"push"})
	job := NewJobNode("job1", "build", "ubuntu-latest")

	g.AddNode(workflow)
	g.AddNode(job)
	g.AddEdge("wf1", "job1", EdgeContains)

	children := g.Children("wf1")
	require.Len(t, children, 1)
	assert.Equal(t, "job1", children[0])
}

func TestGraph_GetNodesByTag(t *testing.T) {
	g := NewGraph()

	workflow1 := NewWorkflowNode("wf1", "Build", "build.yml", "owner/repo", []string{"pull_request_target"})
	workflow1.AddTag(TagPullRequestTarget)

	workflow2 := NewWorkflowNode("wf2", "Test", "test.yml", "owner/repo", []string{"push"})
	workflow2.AddTag(TagPush)

	g.AddNode(workflow1)
	g.AddNode(workflow2)

	prtNodes := g.GetNodesByTag(TagPullRequestTarget)
	require.Len(t, prtNodes, 1)
	assert.Equal(t, "wf1", prtNodes[0].ID())
}

func TestGraph_GetNodesByType(t *testing.T) {
	g := NewGraph()

	wf := NewWorkflowNode("wf1", "Build", "build.yml", "owner/repo", []string{"push"})
	job := NewJobNode("job1", "build", "ubuntu-latest")
	step := NewStepNode("step1", "Checkout", 10)

	g.AddNode(wf)
	g.AddNode(job)
	g.AddNode(step)

	workflows := g.GetNodesByType(NodeTypeWorkflow)
	assert.Len(t, workflows, 1)
	assert.Equal(t, "wf1", workflows[0].ID())

	jobs := g.GetNodesByType(NodeTypeJob)
	assert.Len(t, jobs, 1)

	steps := g.GetNodesByType(NodeTypeStep)
	assert.Len(t, steps, 1)

	actions := g.GetNodesByType(NodeTypeAction)
	assert.Len(t, actions, 0)
}

func TestGraph_Nodes(t *testing.T) {
	g := NewGraph()

	assert.Len(t, g.Nodes(), 0)

	wf := NewWorkflowNode("wf1", "Build", "build.yml", "owner/repo", []string{"push"})
	job := NewJobNode("job1", "build", "ubuntu-latest")

	g.AddNode(wf)
	g.AddNode(job)

	nodes := g.Nodes()
	assert.Len(t, nodes, 2)
}

func TestGraph_NodeCount(t *testing.T) {
	g := NewGraph()

	assert.Equal(t, 0, g.NodeCount())

	g.AddNode(NewWorkflowNode("wf1", "Build", "build.yml", "owner/repo", []string{"push"}))
	assert.Equal(t, 1, g.NodeCount())

	g.AddNode(NewJobNode("job1", "build", "ubuntu-latest"))
	assert.Equal(t, 2, g.NodeCount())
}

func TestGraph_UpdateNodeTag(t *testing.T) {
	g := NewGraph()

	wf := NewWorkflowNode("wf1", "Build", "build.yml", "owner/repo", []string{"push"})
	g.AddNode(wf)

	// Initially no injectable tag
	assert.False(t, wf.HasTag(TagInjectable))

	// Update tag
	g.UpdateNodeTag("wf1", TagInjectable)

	// Now should have tag
	node, _ := g.GetNode("wf1")
	assert.True(t, node.HasTag(TagInjectable))

	// Tag should be in index
	tagged := g.GetNodesByTag(TagInjectable)
	assert.Len(t, tagged, 1)
}

func TestGraph_GetIncludedWorkflows(t *testing.T) {
	g := NewGraph()

	// Create included workflows from external repos
	// These represent workflows that were included from other repositories
	wf1 := platforms.Workflow{
		Name:     "build.yml",
		Path:     "local:123:.gitlab/ci/build.yml:main",
		Content:  []byte("build:\n  script:\n    - make build"),
		RepoSlug: "shared/templates",
	}

	wf2 := platforms.Workflow{
		Name:     "test.yml",
		Path:     "local:456:.gitlab/ci/test.yml:main",
		Content:  []byte("test:\n  script:\n    - make test"),
		RepoSlug: "shared/templates",
	}

	wf3 := platforms.Workflow{
		Name:     "deploy.yml",
		Path:     "local:789:.gitlab/ci/deploy.yml:main",
		Content:  []byte("deploy:\n  script:\n    - make deploy"),
		RepoSlug: "other/repo",
	}

	// Store as metadata with included_workflow: prefix
	g.SetMetadata("included_workflow:local:123:.gitlab/ci/build.yml:main", wf1)
	g.SetMetadata("included_workflow:local:456:.gitlab/ci/test.yml:main", wf2)
	g.SetMetadata("included_workflow:local:789:.gitlab/ci/deploy.yml:main", wf3)
	g.SetMetadata("other_metadata", "some value") // Should be ignored

	// Get all included workflows (repoSlug parameter kept for API consistency)
	included := g.GetIncludedWorkflows("current/repo")

	// Should return all 3 included workflows
	require.Len(t, included, 3)

	// Verify all workflows are present
	paths := make(map[string]bool)
	repoSlugs := make(map[string]int)
	for _, wf := range included {
		paths[wf.Path] = true
		repoSlugs[wf.RepoSlug]++
	}

	assert.True(t, paths[wf1.Path])
	assert.True(t, paths[wf2.Path])
	assert.True(t, paths[wf3.Path])

	// Verify repo slug distribution
	assert.Equal(t, 2, repoSlugs["shared/templates"])
	assert.Equal(t, 1, repoSlugs["other/repo"])
}

func TestGraph_GetIncomingEdges(t *testing.T) {
	tests := []struct {
		name          string
		setupGraph    func() (*Graph, string)
		expectedCount int
		expectedTypes []EdgeType
	}{
		{
			name: "node with no incoming edges",
			setupGraph: func() (*Graph, string) {
				g := NewGraph()
				wf := NewWorkflowNode("wf1", "main", ".gitlab-ci.yml", "owner/repo", []string{"push"})
				g.AddNode(wf)
				return g, "wf1"
			},
			expectedCount: 0,
			expectedTypes: []EdgeType{},
		},
		{
			name: "node with single incoming edge",
			setupGraph: func() (*Graph, string) {
				g := NewGraph()
				parent := NewWorkflowNode("parent", "parent", ".gitlab-ci.yml", "owner/repo", []string{"push"})
				child := NewWorkflowNode("child", "child", "included.yml", "owner/repo", []string{"push"})
				g.AddNode(parent)
				g.AddNode(child)
				g.AddEdge(parent.ID(), child.ID(), EdgeIncludes)
				return g, "child"
			},
			expectedCount: 1,
			expectedTypes: []EdgeType{EdgeIncludes},
		},
		{
			name: "node with multiple incoming edges of different types",
			setupGraph: func() (*Graph, string) {
				g := NewGraph()
				trigger := NewWorkflowNode("trigger", "trigger", "trigger.yml", "owner/repo", []string{"push"})
				include := NewWorkflowNode("include", "include", "include.yml", "owner/repo", []string{"push"})
				target := NewWorkflowNode("target", "target", "target.yml", "owner/repo", []string{"push"})
				g.AddNode(trigger)
				g.AddNode(include)
				g.AddNode(target)
				g.AddEdge(trigger.ID(), target.ID(), EdgeTriggers)
				g.AddEdge(include.ID(), target.ID(), EdgeIncludes)
				return g, "target"
			},
			expectedCount: 2,
			expectedTypes: []EdgeType{EdgeTriggers, EdgeIncludes},
		},
		{
			name: "node with multiple incoming edges of same type",
			setupGraph: func() (*Graph, string) {
				g := NewGraph()
				parent1 := NewWorkflowNode("parent1", "parent1", "parent1.yml", "owner/repo", []string{"push"})
				parent2 := NewWorkflowNode("parent2", "parent2", "parent2.yml", "owner/repo", []string{"push"})
				shared := NewWorkflowNode("shared", "shared", "shared.yml", "owner/repo", []string{"push"})
				g.AddNode(parent1)
				g.AddNode(parent2)
				g.AddNode(shared)
				g.AddEdge(parent1.ID(), shared.ID(), EdgeIncludes)
				g.AddEdge(parent2.ID(), shared.ID(), EdgeIncludes)
				return g, "shared"
			},
			expectedCount: 2,
			expectedTypes: []EdgeType{EdgeIncludes, EdgeIncludes},
		},
		{
			name: "job contained by workflow",
			setupGraph: func() (*Graph, string) {
				g := NewGraph()
				wf := NewWorkflowNode("wf1", "main", ".gitlab-ci.yml", "owner/repo", []string{"push"})
				job := NewJobNode("job1", "build", "docker")
				g.AddNode(wf)
				g.AddNode(job)
				g.AddEdge(wf.ID(), job.ID(), EdgeContains)
				return g, "job1"
			},
			expectedCount: 1,
			expectedTypes: []EdgeType{EdgeContains},
		},
		{
			name: "non-existent node",
			setupGraph: func() (*Graph, string) {
				g := NewGraph()
				return g, "nonexistent"
			},
			expectedCount: 0,
			expectedTypes: []EdgeType{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, nodeID := tt.setupGraph()
			incoming := g.GetIncomingEdges(nodeID)

			assert.Len(t, incoming, tt.expectedCount, "Unexpected number of incoming edges")

			if tt.expectedCount > 0 {
				// Verify edge types
				actualTypes := make([]EdgeType, len(incoming))
				for i, edge := range incoming {
					actualTypes[i] = edge.Type
					assert.Equal(t, nodeID, edge.To, "Edge should point to the target node")
				}

				// Check that all expected types are present
				for _, expectedType := range tt.expectedTypes {
					found := false
					for _, actualType := range actualTypes {
						if actualType == expectedType {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected edge type %s not found", expectedType)
				}
			}
		})
	}
}
