//go:build integration
// +build integration

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

func TestGitLabIncludeResolutionEndToEnd(t *testing.T) {
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
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

	client := gitlab.NewClient(server.URL, "test-token")

	metadata := map[string]interface{}{
		"gitlab_client":     client,
		"gitlab_project_id": 123,
		"gitlab_ref":        "main",
		"platform":          "gitlab",
	}

	ctx := context.Background()
	_ = ctx
	g, err := BuildGraph("owner/repo", ".gitlab-ci.yml", mainContent, metadata)
	require.NoError(t, err, "BuildGraph should succeed")

	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)
	assert.Len(t, workflows, 3, "Graph should have 3 workflow nodes: main, build.yml, test.yml")

	var mainWorkflow *graph.WorkflowNode
	for _, node := range workflows {
		wf := node.(*graph.WorkflowNode)
		if wf.Path == ".gitlab-ci.yml" {
			mainWorkflow = wf
			break
		}
	}
	require.NotNil(t, mainWorkflow, "Should find main workflow node")

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

	includedPaths := make(map[string]bool)
	for _, wf := range includedWorkflows {
		if wf.Path != "" {
			includedPaths[wf.Path] = true
		}
	}
	assert.True(t, len(includedPaths) >= 2, "Should have at least 2 distinct included workflow paths")

	jobs := g.GetNodesByType(graph.NodeTypeJob)
	assert.Len(t, jobs, 3, "Graph should have 3 jobs: deploy (main), build_job, test_job")

	jobNames := make(map[string]bool)
	for _, node := range jobs {
		jobNode := node.(*graph.JobNode)
		jobNames[jobNode.Name] = true
	}

	assert.True(t, jobNames["deploy"], "Should have 'deploy' job from main workflow")
	assert.True(t, jobNames["build_job"], "Should have 'build_job' from build.yml")
	assert.True(t, jobNames["test_job"], "Should have 'test_job' from test.yml")

	assert.Greater(t, len(includedWorkflows), 0, "Should have included workflows connected via EdgeIncludes")
}

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

	g, err := BuildGraph("owner/repo", ".gitlab-ci.yml", mainContent, map[string]interface{}{
		"platform": "gitlab",
	})
	require.NoError(t, err, "BuildGraph should succeed even without resolver")

	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)
	assert.Len(t, workflows, 1, "Graph should have only main workflow when resolver unavailable")

	jobs := g.GetNodesByType(graph.NodeTypeJob)
	assert.Len(t, jobs, 1, "Graph should have 1 job from main workflow")
}

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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	g, err := BuildGraph("owner/repo", ".gitlab-ci.yml", mainContent, metadata)
	require.NoError(t, err, "BuildGraph should succeed despite include errors (graceful degradation)")

	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)
	assert.GreaterOrEqual(t, len(workflows), 1, "Graph should have at least main workflow")

	jobs := g.GetNodesByType(graph.NodeTypeJob)
	assert.Len(t, jobs, 1, "Graph should have job from main workflow")
}
