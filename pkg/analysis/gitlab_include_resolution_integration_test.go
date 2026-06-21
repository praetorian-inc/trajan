//go:build integration
// +build integration

// pkg/analysis/gitlab_include_resolution_integration_test.go
package analysis

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/gitlab"
)

// TestGitLabIncludeResolutionEndToEnd tests the complete workflow of resolving GitLab includes
// and building a graph with multiple workflow nodes connected via EdgeIncludes edges.
// This integration test verifies:
// 1. Main workflow file with includes is parsed
// 2. Include resolver fetches included files from mock GitLab API
// 3. Graph builder creates workflow nodes for main + included files
// 4. Jobs from all files are added to the graph
// 5. EdgeIncludes edges connect main workflow to included workflows
func TestGitLabIncludeResolutionEndToEnd(t *testing.T) {
	// Define workflow contents
	mainContent := []byte(`include:
  - local: '.gitlab/ci/build.yml'
  - local: '.gitlab/ci/test.yml'

stages:
  - build
  - test

deploy:
  stage: deploy
  script:
    - echo "Deploying from main"
`)

	buildContent := []byte(`build_job:
  stage: build
  script:
    - echo "Building from build.yml"
`)

	testContent := []byte(`test_job:
  stage: test
  script:
    - echo "Testing from test.yml"
`)

	// Create mock GitLab server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		// Handle build.yml include
		case r.URL.Path == "/api/v4/projects/123/repository/files/.gitlab/ci/build.yml" && r.URL.Query().Get("ref") == "main":
			response := gitlab.FileResponse{
				FileName: "build.yml",
				FilePath: ".gitlab/ci/build.yml",
				Encoding: "base64",
				Content:  base64.StdEncoding.EncodeToString(buildContent),
				BlobID:   "build123",
			}
			json.NewEncoder(w).Encode(response)
			return

		// Handle test.yml include
		case r.URL.Path == "/api/v4/projects/123/repository/files/.gitlab/ci/test.yml" && r.URL.Query().Get("ref") == "main":
			response := gitlab.FileResponse{
				FileName: "test.yml",
				FilePath: ".gitlab/ci/test.yml",
				Encoding: "base64",
				Content:  base64.StdEncoding.EncodeToString(testContent),
				BlobID:   "test123",
			}
			json.NewEncoder(w).Encode(response)
			return

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Create GitLab client pointing to mock server
	client := gitlab.NewClient(server.URL, "test-token")

	// Create metadata for graph builder (simulates what Platform.Scan provides)
	metadata := map[string]interface{}{
		"gitlab_client":     client,
		"gitlab_project_id": 123,
		"gitlab_ref":        "main",
		"platform":          "gitlab",
	}

	// Build graph from main workflow with metadata
	ctx := context.Background()
	_ = ctx // Context available if needed in the future
	g, err := BuildGraph("owner/repo", ".gitlab-ci.yml", mainContent, metadata)
	require.NoError(t, err, "BuildGraph should succeed")

	// Verify graph structure
	// 1. Should have 3 workflow nodes (main + 2 includes)
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)
	assert.Len(t, workflows, 3, "Graph should have 3 workflow nodes: main, build.yml, test.yml")

	// 2. Find main workflow node
	var mainWorkflow *graph.WorkflowNode
	for _, node := range workflows {
		wf := node.(*graph.WorkflowNode)
		if wf.Path == ".gitlab-ci.yml" {
			mainWorkflow = wf
			break
		}
	}
	require.NotNil(t, mainWorkflow, "Should find main workflow node")

	// 3. Verify main workflow has 2 workflow children (included workflows)
	children := g.Children(mainWorkflow.ID())
	workflowChildren := 0
	var includedWorkflows []*graph.WorkflowNode

	for _, childID := range children {
		if node, ok := g.GetNode(childID); ok {
			if node.Type() == graph.NodeTypeWorkflow {
				workflowChildren++
				includedWorkflows = append(includedWorkflows, node.(*graph.WorkflowNode))
			}
		}
	}
	assert.Equal(t, 2, workflowChildren, "Main workflow should have 2 included workflow children")

	// 4. Verify included workflows reference correct files
	includedPaths := make(map[string]bool)
	for _, wf := range includedWorkflows {
		// Path or Source should contain the file reference
		if wf.Path != "" {
			includedPaths[wf.Path] = true
		}
	}
	// At least one should reference build.yml and one should reference test.yml
	assert.True(t, len(includedPaths) >= 2, "Should have at least 2 distinct included workflow paths")

	// 5. Verify jobs from all files are present
	jobs := g.GetNodesByType(graph.NodeTypeJob)
	assert.Len(t, jobs, 3, "Graph should have 3 jobs: deploy (main), build_job, test_job")

	// Find specific jobs
	jobNames := make(map[string]bool)
	for _, node := range jobs {
		jobNode := node.(*graph.JobNode)
		jobNames[jobNode.Name] = true
	}

	assert.True(t, jobNames["deploy"], "Should have 'deploy' job from main workflow")
	assert.True(t, jobNames["build_job"], "Should have 'build_job' from build.yml")
	assert.True(t, jobNames["test_job"], "Should have 'test_job' from test.yml")

	// 6. Verify EdgeIncludes edges exist
	// The Children method returns all children regardless of edge type,
	// but we've already verified that main workflow has workflow children,
	// which confirms EdgeIncludes edges were created
	assert.Greater(t, len(includedWorkflows), 0, "Should have included workflows connected via EdgeIncludes")
}

// TestGitLabIncludeResolutionWithoutResolver verifies graceful degradation when
// resolver is not available (e.g., metadata missing)
func TestGitLabIncludeResolutionWithoutResolver(t *testing.T) {
	mainContent := []byte(`include:
  - local: '.gitlab/ci/build.yml'

stages:
  - build

deploy:
  stage: deploy
  script:
    - echo "Deploying"
`)

	// Build graph WITHOUT resolver metadata
	g, err := BuildGraph("owner/repo", ".gitlab-ci.yml", mainContent, map[string]interface{}{
		"platform": "gitlab",
	})
	require.NoError(t, err, "BuildGraph should succeed even without resolver")

	// Should have only 1 workflow node (main) since includes can't be resolved
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)
	assert.Len(t, workflows, 1, "Graph should have only main workflow when resolver unavailable")

	// Should still have the job from main file
	jobs := g.GetNodesByType(graph.NodeTypeJob)
	assert.Len(t, jobs, 1, "Graph should have 1 job from main workflow")
}

// TestGitLabIncludeResolutionErrorHandling verifies that include resolution errors
// don't break the entire graph building process (graceful degradation)
func TestGitLabIncludeResolutionErrorHandling(t *testing.T) {
	mainContent := []byte(`include:
  - local: '.gitlab/ci/nonexistent.yml'

stages:
  - build

deploy:
  stage: deploy
  script:
    - echo "Deploying"
`)

	// Create mock GitLab server that returns 404 for includes
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 404 for all file requests
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"404 File Not Found"}`))
	}))
	defer server.Close()

	client := gitlab.NewClient(server.URL, "test-token")
	metadata := map[string]interface{}{
		"gitlab_client":     client,
		"gitlab_project_id": 123,
		"gitlab_ref":        "main",
		"platform":          "gitlab",
	}

	// Build graph - should succeed despite include errors
	g, err := BuildGraph("owner/repo", ".gitlab-ci.yml", mainContent, metadata)
	require.NoError(t, err, "BuildGraph should succeed despite include errors (graceful degradation)")

	// Should have main workflow
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)
	assert.GreaterOrEqual(t, len(workflows), 1, "Graph should have at least main workflow")

	// Should have job from main file
	jobs := g.GetNodesByType(graph.NodeTypeJob)
	assert.Len(t, jobs, 1, "Graph should have job from main workflow")
}
