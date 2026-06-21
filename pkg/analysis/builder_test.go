// pkg/analysis/builder_test.go
package analysis

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/analysis/parser"
	"github.com/praetorian-inc/trajan/pkg/gitlab"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// TestBuildGraphFromNormalized_AzureWorkflowNameFallsBackToPath verifies that when
// the NormalizedWorkflow.Name is empty (as is the case for Azure pipelines which have
// no mandatory name field), the WorkflowNode.Name falls back to the file path.
func TestBuildGraphFromNormalized_AzureWorkflowNameFallsBackToPath(t *testing.T) {
	wf := &parser.NormalizedWorkflow{
		Platform: "azure",
		Name:     "", // Azure pipelines have no mandatory name field
		Triggers: []string{"ci"},
		Jobs:     make(map[string]*parser.NormalizedJob),
	}

	g, err := BuildGraphFromNormalized("owner/repo", "my-pipeline.yml", wf)
	require.NoError(t, err)

	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)
	require.Len(t, workflows, 1)
	wfNode := workflows[0].(*graph.WorkflowNode)
	assert.Equal(t, "my-pipeline.yml", wfNode.Name, "WorkflowNode.Name should fall back to path when workflow Name is empty")
}

func TestBuildGraph_Basic(t *testing.T) {
	yaml := `
name: Build
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: make build
`

	g, err := BuildGraph("owner/repo", "build.yml", []byte(yaml))
	require.NoError(t, err)

	// Should have workflow, job, and steps
	assert.Greater(t, g.NodeCount(), 3)

	// Should have workflow node
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)
	require.Len(t, workflows, 1)
	wf := workflows[0].(*graph.WorkflowNode)
	assert.Equal(t, "Build", wf.Name)
}

func TestBuildGraph_PullRequestTarget(t *testing.T) {
	yaml := `
name: PR Handler
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`

	g, err := BuildGraph("owner/repo", "pr.yml", []byte(yaml))
	require.NoError(t, err)

	// Should tag workflow with pull_request_target
	prtNodes := g.GetNodesByTag(graph.TagPullRequestTarget)
	assert.Len(t, prtNodes, 1)

	// Should tag step with unsafe checkout
	unsafeNodes := g.GetNodesByTag(graph.TagUnsafeCheckout)
	assert.Len(t, unsafeNodes, 1)
}

func TestBuildGraph_InjectionDetection(t *testing.T) {
	yaml := `
name: Injection Test
on: issue_comment
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Echo Comment
        run: echo "${{ github.event.comment.body }}"
`

	g, err := BuildGraph("owner/repo", "injection.yml", []byte(yaml))
	require.NoError(t, err)

	// Should tag workflow with issue_comment
	icNodes := g.GetNodesByTag(graph.TagIssueComment)
	assert.Len(t, icNodes, 1)

	// Should tag step with injectable
	injectableNodes := g.GetNodesByTag(graph.TagInjectable)
	assert.Len(t, injectableNodes, 1)
}

func TestBuildGraph_SelfHostedRunner(t *testing.T) {
	yaml := `
name: Self-hosted
on: push
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo test
`

	g, err := BuildGraph("owner/repo", "selfhosted.yml", []byte(yaml))
	require.NoError(t, err)

	// Should tag job with self-hosted runner
	shNodes := g.GetNodesByTag(graph.TagSelfHostedRunner)
	assert.Len(t, shNodes, 1)
}

func TestBuildGraph_ArtifactActions(t *testing.T) {
	yaml := `
name: Artifacts
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v4
        with:
          name: build
          path: dist/
  test:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: build
`

	g, err := BuildGraph("owner/repo", "artifacts.yml", []byte(yaml))
	require.NoError(t, err)

	uploadNodes := g.GetNodesByTag(graph.TagArtifactUpload)
	assert.Len(t, uploadNodes, 1)

	downloadNodes := g.GetNodesByTag(graph.TagArtifactDownload)
	assert.Len(t, downloadNodes, 1)
}

func TestBuildGraph_GraphStructure(t *testing.T) {
	yaml := `
name: Pipeline
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make build
`

	g, err := BuildGraph("owner/repo", "pipeline.yml", []byte(yaml))
	require.NoError(t, err)

	// Verify graph structure: Workflow -> Job -> Steps
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)
	require.Len(t, workflows, 1)
	wfID := workflows[0].ID()

	// Workflow should have children (jobs)
	children := g.Children(wfID)
	require.Len(t, children, 1)

	// Job should have children (steps)
	jobChildren := g.Children(children[0])
	assert.Len(t, jobChildren, 2)
}

func TestBuildGraphFromNormalized_Basic(t *testing.T) {
	// Create a NormalizedWorkflow for testing
	nw := &parser.NormalizedWorkflow{
		Platform: "github",
		Name:     "Build",
		Triggers: []string{"push", "pull_request"},
		Jobs: map[string]*parser.NormalizedJob{
			"build": {
				ID:     "build",
				Name:   "Build Job",
				RunsOn: "ubuntu-latest",
				Steps: []*parser.NormalizedStep{
					{
						Name: "Checkout",
						Uses: "actions/checkout@v4",
					},
					{
						Name: "Build",
						Run:  "make build",
					},
				},
			},
		},
	}

	g, err := BuildGraphFromNormalized("owner/repo", "build.yml", nw)
	require.NoError(t, err)

	// Should have workflow, job, and steps
	assert.Greater(t, g.NodeCount(), 3)

	// Should have workflow node
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)
	require.Len(t, workflows, 1)
	wf := workflows[0].(*graph.WorkflowNode)
	assert.Equal(t, "Build", wf.Name)
	assert.Equal(t, []string{"push", "pull_request"}, wf.Triggers)
}

func TestBuildGraphFromNormalized_PullRequestTarget(t *testing.T) {
	nw := &parser.NormalizedWorkflow{
		Platform: "github",
		Name:     "PR Handler",
		Triggers: []string{"pull_request_target"},
		Jobs: map[string]*parser.NormalizedJob{
			"test": {
				ID:     "test",
				RunsOn: "ubuntu-latest",
				Steps: []*parser.NormalizedStep{
					{
						Uses: "actions/checkout@v4",
						With: map[string]string{
							"ref": "${{ github.event.pull_request.head.sha }}",
						},
					},
				},
			},
		},
	}

	g, err := BuildGraphFromNormalized("owner/repo", "pr.yml", nw)
	require.NoError(t, err)

	// Should tag workflow with pull_request_target
	prtNodes := g.GetNodesByTag(graph.TagPullRequestTarget)
	assert.Len(t, prtNodes, 1)

	// Should tag step with unsafe checkout
	unsafeNodes := g.GetNodesByTag(graph.TagUnsafeCheckout)
	assert.Len(t, unsafeNodes, 1)
}

func TestBuildGraphFromNormalized_InjectionDetection(t *testing.T) {
	nw := &parser.NormalizedWorkflow{
		Platform: "github",
		Name:     "Injection Test",
		Triggers: []string{"issue_comment"},
		Jobs: map[string]*parser.NormalizedJob{
			"test": {
				ID:     "test",
				RunsOn: "ubuntu-latest",
				Steps: []*parser.NormalizedStep{
					{
						Name: "Echo Comment",
						Run:  "echo \"${{ github.event.comment.body }}\"",
					},
				},
			},
		},
	}

	g, err := BuildGraphFromNormalized("owner/repo", "injection.yml", nw)
	require.NoError(t, err)

	// Should tag workflow with issue_comment
	icNodes := g.GetNodesByTag(graph.TagIssueComment)
	assert.Len(t, icNodes, 1)

	// Should tag step with injectable
	injectableNodes := g.GetNodesByTag(graph.TagInjectable)
	assert.Len(t, injectableNodes, 1)
}

func TestBuildGraphFromNormalized_GitLabIncludes(t *testing.T) {
	// Create a NormalizedWorkflow with GitLab includes
	gitlabCI := &parser.GitLabCI{
		Includes: []parser.GitLabInclude{
			{
				Type: parser.IncludeTypeLocal,
				Path: ".gitlab/templates/build.yml",
			},
			{
				Type:   parser.IncludeTypeRemote,
				Remote: "https://example.com/templates/test.yml",
			},
			{
				Type:    parser.IncludeTypeProject,
				Project: "group/shared-ci",
				Path:    "templates/deploy.yml",
				Ref:     "main",
			},
			{
				Type:     parser.IncludeTypeTemplate,
				Template: "Security/SAST.gitlab-ci.yml",
			},
		},
	}

	nw := &parser.NormalizedWorkflow{
		Platform: "gitlab",
		Name:     "GitLab Pipeline",
		Triggers: []string{"push"},
		Raw:      gitlabCI,
		Jobs: map[string]*parser.NormalizedJob{
			"build": {
				ID:     "build",
				RunsOn: "docker",
				Steps: []*parser.NormalizedStep{
					{
						Name: "Build",
						Run:  "make build",
					},
				},
			},
		},
	}

	g, err := BuildGraphFromNormalized("owner/repo", ".gitlab-ci.yml", nw)
	require.NoError(t, err)

	// Get workflow node
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)
	require.Len(t, workflows, 1)
	wf := workflows[0].(*graph.WorkflowNode)

	// Verify includes are populated
	require.Len(t, wf.Includes, 4, "Should have 4 includes")

	// Verify local include
	assert.Equal(t, "local", wf.Includes[0].Type)
	assert.Equal(t, ".gitlab/templates/build.yml", wf.Includes[0].Path)

	// Verify remote include
	assert.Equal(t, "remote", wf.Includes[1].Type)
	assert.Equal(t, "https://example.com/templates/test.yml", wf.Includes[1].Remote)

	// Verify project include
	assert.Equal(t, "project", wf.Includes[2].Type)
	assert.Equal(t, "group/shared-ci", wf.Includes[2].Project)
	assert.Equal(t, "templates/deploy.yml", wf.Includes[2].Path)
	assert.Equal(t, "main", wf.Includes[2].Ref)

	// Verify template include
	assert.Equal(t, "template", wf.Includes[3].Type)
	assert.Equal(t, "Security/SAST.gitlab-ci.yml", wf.Includes[3].Template)
}

func TestBuildGraphWithGitLabResolver(t *testing.T) {
	content := []byte(`include:
  - local: '.gitlab/ci/build.yml'

stages:
  - test

test:
  stage: test
  script:
    - echo hello`)

	// Create a real gitlab.Client (empty is fine for this test)
	mockClient := gitlab.NewClient("https://gitlab.com", "test-token")

	metadata := map[string]interface{}{
		"gitlab_client":     mockClient, // Use real *gitlab.Client
		"gitlab_project_id": 123,
		"gitlab_ref":        "main",
	}

	gr, err := BuildGraph("owner/repo", ".gitlab-ci.yml", content, metadata)
	require.NoError(t, err)
	require.NotNil(t, gr)

	// Verify graph has workflow node
	nodes := gr.Nodes()
	require.Greater(t, len(nodes), 0, "expected nodes in graph")

	// Verify metadata is set on graph
	clientMeta, ok := gr.GetMetadata("gitlab_client")
	assert.True(t, ok, "expected gitlab_client in metadata")
	assert.Equal(t, mockClient, clientMeta)

	projectIDMeta, ok := gr.GetMetadata("gitlab_project_id")
	assert.True(t, ok, "expected gitlab_project_id in metadata")
	assert.Equal(t, 123, projectIDMeta)

	refMeta, ok := gr.GetMetadata("gitlab_ref")
	assert.True(t, ok, "expected gitlab_ref in metadata")
	assert.Equal(t, "main", refMeta)

	// TODO: In a future task, we'll verify the resolver actually resolved includes
	// For now, just verify the graph builds without errors
}

func TestBuildGraphWithoutGitLabResolver(t *testing.T) {
	content := []byte(`name: test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello`)

	// No metadata or non-GitLab platform
	gr, err := BuildGraph("owner/repo", ".github/workflows/test.yml", content)
	require.NoError(t, err)
	require.NotNil(t, gr)

	// Should still build graph successfully without resolver
	nodes := gr.Nodes()
	require.Greater(t, len(nodes), 0, "expected nodes in graph")

	// Verify no GitLab metadata
	_, ok := gr.GetMetadata("gitlab_client")
	assert.False(t, ok, "should not have gitlab_client in metadata for GitHub workflow")
}

// mockGitLabClient implements the GitLab client interface for testing include resolution
type mockGitLabClient struct {
	files map[string][]byte
}

func (m *mockGitLabClient) GetWorkflowFile(ctx context.Context, projectID int, path, ref string) ([]byte, error) {
	key := fmt.Sprintf("%d:%s:%s", projectID, path, ref)
	if content, ok := m.files[key]; ok {
		return content, nil
	}
	return nil, fmt.Errorf("file not found: %s", key)
}

func (m *mockGitLabClient) GetProject(ctx context.Context, path string) (*gitlab.Project, error) {
	// Mock project lookup - return dummy project with ID 456
	return &gitlab.Project{ID: 456, PathWithNamespace: path}, nil
}

func (m *mockGitLabClient) GetTemplate(ctx context.Context, name string) ([]byte, error) {
	key := fmt.Sprintf("template:%s", name)
	if content, ok := m.files[key]; ok {
		return content, nil
	}
	return nil, fmt.Errorf("template not found: %s", name)
}

// TestResolveGitLabIncludes tests the include resolution during graph building
func TestResolveGitLabIncludes(t *testing.T) {
	_ = &mockGitLabClient{
		files: map[string][]byte{
			// Local include file
			"123:.gitlab/ci/build.yml:main": []byte(`build:
  stage: build
  script:
    - make build`),
		},
	}

	content := []byte(`include:
  - local: '.gitlab/ci/build.yml'

stages:
  - test

test:
  stage: test
  script:
    - make test`)

	// Create a real gitlab.Client wrapper around our mock
	// We need to use the actual *gitlab.Client type
	realClient := gitlab.NewClient("https://gitlab.com", "test-token")

	// Wrap the mock to intercept calls
	// For this test, we'll use a different approach: directly test normalizedGraphBuilder
	gitlabParser := parser.NewGitLabParser()
	normalized, err := gitlabParser.Parse(content)
	require.NoError(t, err)

	// Create resolver manually
	_ = gitlab.NewIncludeResolver(realClient, 123, "main")

	// For testing, we need to inject the mock client into the resolver
	// Since the resolver is not exported, we'll test through the public API

	// Actually, let's test the integration through BuildGraph with proper metadata
	// But we can't inject a mock into NewIncludeResolver...
	// Let's instead verify that the includes are populated correctly in the workflow node
	// and test the actual resolution logic separately

	g, err := BuildGraphFromNormalized("owner/repo", ".gitlab-ci.yml", normalized, map[string]interface{}{
		"gitlab_client":     realClient,
		"gitlab_project_id": 123,
		"gitlab_ref":        "main",
	})
	require.NoError(t, err)

	// Verify graph has main workflow node with includes populated
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)
	require.Len(t, workflows, 1)
	wfNode := workflows[0].(*graph.WorkflowNode)

	// Verify includes are populated from the parsed GitLabCI
	require.Len(t, wfNode.Includes, 1, "Should have 1 include in workflow node")
	assert.Equal(t, "local", wfNode.Includes[0].Type)
	assert.Equal(t, ".gitlab/ci/build.yml", wfNode.Includes[0].Path)

	// TODO: After implementing resolveGitLabIncludes, test that:
	// 1. Included workflow nodes are created
	// 2. Edges are created from parent to included workflow (EdgeIncludes)
	// 3. Jobs from included workflows are part of the graph
}

// TestResolveGitLabIncludesWithActualResolution tests that includes are actually resolved
func TestResolveGitLabIncludesWithActualResolution(t *testing.T) {
	// Setup mock GitLab server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle GetWorkflowFile request for local include
		if r.URL.Path == "/api/v4/projects/123/repository/files/.gitlab/ci/build.yml" && r.URL.Query().Get("ref") == "main" {
			mockContent := []byte(`build:
  stage: build
  script:
    - make build`)
			response := gitlab.FileResponse{
				FileName: ".gitlab/ci/build.yml",
				FilePath: ".gitlab/ci/build.yml",
				Encoding: "base64",
				Content:  base64.StdEncoding.EncodeToString(mockContent),
				BlobID:   "abc123",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	// Create client pointing to mock server
	client := gitlab.NewClient(server.URL, "test-token")

	content := []byte(`include:
  - local: '.gitlab/ci/build.yml'

stages:
  - test

test:
  stage: test
  script:
    - make test`)

	gitlabParser := parser.NewGitLabParser()
	normalized, err := gitlabParser.Parse(content)
	require.NoError(t, err)

	g, err := BuildGraphFromNormalized("owner/repo", ".gitlab-ci.yml", normalized, map[string]interface{}{
		"gitlab_client":     client,
		"gitlab_project_id": 123,
		"gitlab_ref":        "main",
	})
	require.NoError(t, err)

	// After implementation, we expect:
	// 1. Main workflow node
	// 2. Included workflow node for .gitlab/ci/build.yml
	// 3. An EdgeIncludes edge from main -> included
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)
	assert.GreaterOrEqual(t, len(workflows), 2, "Should have at least 2 workflow nodes (main + included)")

	// Find the main workflow (the one with the original path)
	var mainWorkflow *graph.WorkflowNode
	for _, node := range workflows {
		wfNode := node.(*graph.WorkflowNode)
		if wfNode.Path == ".gitlab-ci.yml" {
			mainWorkflow = wfNode
			break
		}
	}
	require.NotNil(t, mainWorkflow, "Should find main workflow node")

	// Check for EdgeIncludes edges
	children := g.Children(mainWorkflow.ID())

	hasIncludedWorkflow := false
	for _, childID := range children {
		if node, ok := g.GetNode(childID); ok {
			if node.Type() == graph.NodeTypeWorkflow {
				hasIncludedWorkflow = true
				// Verify it's the included workflow
				includedWf := node.(*graph.WorkflowNode)
				assert.True(t, strings.Contains(includedWf.Path, "build.yml") || strings.Contains(includedWf.Path, "local:123"),
					"Included workflow should reference build.yml")
				break
			}
		}
	}
	assert.True(t, hasIncludedWorkflow, "Main workflow should have included workflow as child")

	// Verify that jobs from included workflow are in the graph
	jobs := g.GetNodesByType(graph.NodeTypeJob)
	assert.GreaterOrEqual(t, len(jobs), 2, "Should have at least 2 jobs (test + build)")

	// Find the build job from the included workflow
	var buildJob *graph.JobNode
	for _, node := range jobs {
		jobNode := node.(*graph.JobNode)
		if jobNode.Name == "build" {
			buildJob = jobNode
			break
		}
	}
	assert.NotNil(t, buildJob, "Should have build job from included workflow")
}

// TestResolveGitLabIncludesNested tests nested include resolution
func TestResolveGitLabIncludesNested(t *testing.T) {
	// Setup mock GitLab server with nested includes
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle first level include
		if r.URL.Path == "/api/v4/projects/123/repository/files/.gitlab/ci/build.yml" && r.URL.Query().Get("ref") == "main" {
			// This included file itself includes another file
			mockContent := []byte(`include:
  - local: '.gitlab/ci/test.yml'

build:
  stage: build
  script:
    - make build`)
			response := gitlab.FileResponse{
				FileName: ".gitlab/ci/build.yml",
				FilePath: ".gitlab/ci/build.yml",
				Encoding: "base64",
				Content:  base64.StdEncoding.EncodeToString(mockContent),
				BlobID:   "abc123",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}

		// Handle second level (nested) include
		if r.URL.Path == "/api/v4/projects/123/repository/files/.gitlab/ci/test.yml" && r.URL.Query().Get("ref") == "main" {
			mockContent := []byte(`test:
  stage: test
  script:
    - npm test`)
			response := gitlab.FileResponse{
				FileName: ".gitlab/ci/test.yml",
				FilePath: ".gitlab/ci/test.yml",
				Encoding: "base64",
				Content:  base64.StdEncoding.EncodeToString(mockContent),
				BlobID:   "def456",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	// Create client pointing to mock server
	client := gitlab.NewClient(server.URL, "test-token")

	content := []byte(`include:
  - local: '.gitlab/ci/build.yml'

stages:
  - build
  - test
  - deploy

deploy:
  stage: deploy
  script:
    - kubectl apply`)

	gitlabParser := parser.NewGitLabParser()
	normalized, err := gitlabParser.Parse(content)
	require.NoError(t, err)

	g, err := BuildGraphFromNormalized("owner/repo", ".gitlab-ci.yml", normalized, map[string]interface{}{
		"gitlab_client":     client,
		"gitlab_project_id": 123,
		"gitlab_ref":        "main",
	})
	require.NoError(t, err)

	// We expect:
	// 1. Main workflow node
	// 2. First level included workflow (.gitlab/ci/build.yml)
	// 3. Second level included workflow (.gitlab/ci/test.yml)
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)
	assert.GreaterOrEqual(t, len(workflows), 3, "Should have at least 3 workflow nodes (main + 2 nested includes)")

	// Verify all jobs are present
	jobs := g.GetNodesByType(graph.NodeTypeJob)
	assert.GreaterOrEqual(t, len(jobs), 3, "Should have at least 3 jobs (deploy + build + test)")

	// Find specific jobs
	jobNames := make(map[string]bool)
	for _, node := range jobs {
		jobNode := node.(*graph.JobNode)
		jobNames[jobNode.Name] = true
	}

	assert.True(t, jobNames["deploy"], "Should have deploy job from main workflow")
	assert.True(t, jobNames["build"], "Should have build job from first include")
	assert.True(t, jobNames["test"], "Should have test job from nested include")
}

// TestResolveGitLabIncludesMultipleTypes tests resolution of different include types
func TestResolveGitLabIncludesMultipleTypes(t *testing.T) {
	// Setup mock GitLab server with multiple include types
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle local include
		if r.URL.Path == "/api/v4/projects/123/repository/files/.gitlab/ci/build.yml" && r.URL.Query().Get("ref") == "main" {
			mockContent := []byte(`build:
  stage: build
  script:
    - make build`)
			response := gitlab.FileResponse{
				FileName: ".gitlab/ci/build.yml",
				FilePath: ".gitlab/ci/build.yml",
				Encoding: "base64",
				Content:  base64.StdEncoding.EncodeToString(mockContent),
				BlobID:   "abc123",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}

		// Handle GetProject for project include
		if r.URL.Path == "/api/v4/projects/other/shared-ci" {
			response := gitlab.Project{
				ID:                456,
				PathWithNamespace: "other/shared-ci",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}

		// Handle GetWorkflowFile for project include
		if r.URL.Path == "/api/v4/projects/456/repository/files/templates/deploy.yml" && r.URL.Query().Get("ref") == "v1.0" {
			mockContent := []byte(`deploy:
  stage: deploy
  script:
    - kubectl apply`)
			response := gitlab.FileResponse{
				FileName: "templates/deploy.yml",
				FilePath: "templates/deploy.yml",
				Encoding: "base64",
				Content:  base64.StdEncoding.EncodeToString(mockContent),
				BlobID:   "def456",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}

		// Handle GetProject for gitlab-org/gitlab (template repository)
		if r.URL.Path == "/api/v4/projects/gitlab-org/gitlab" {
			response := gitlab.Project{
				ID:                999,
				PathWithNamespace: "gitlab-org/gitlab",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}

		// Handle GetWorkflowFile for template
		if r.URL.Path == "/api/v4/projects/999/repository/files/lib/gitlab/ci/templates/Security/SAST.gitlab-ci.yml" && r.URL.Query().Get("ref") == "master" {
			mockContent := []byte(`sast:
  stage: test
  script:
    - semgrep scan`)
			response := gitlab.FileResponse{
				FileName: "SAST.gitlab-ci.yml",
				FilePath: "lib/gitlab/ci/templates/Security/SAST.gitlab-ci.yml",
				Encoding: "base64",
				Content:  base64.StdEncoding.EncodeToString(mockContent),
				BlobID:   "xyz789",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	// Create client pointing to mock server
	client := gitlab.NewClient(server.URL, "test-token")

	content := []byte(`include:
  - local: '.gitlab/ci/build.yml'
  - project: 'other/shared-ci'
    file: 'templates/deploy.yml'
    ref: 'v1.0'
  - template: 'Security/SAST.gitlab-ci.yml'

stages:
  - build
  - test
  - deploy

test:
  stage: test
  script:
    - npm test`)

	gitlabParser := parser.NewGitLabParser()
	normalized, err := gitlabParser.Parse(content)
	require.NoError(t, err)

	g, err := BuildGraphFromNormalized("owner/repo", ".gitlab-ci.yml", normalized, map[string]interface{}{
		"gitlab_client":     client,
		"gitlab_project_id": 123,
		"gitlab_ref":        "main",
	})
	require.NoError(t, err)

	// We expect:
	// 1. Main workflow node
	// 2. Local include workflow
	// 3. Project include workflow
	// 4. Template include workflow
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)
	assert.GreaterOrEqual(t, len(workflows), 4, "Should have at least 4 workflow nodes (main + 3 includes)")

	// Verify all jobs are present
	jobs := g.GetNodesByType(graph.NodeTypeJob)
	assert.GreaterOrEqual(t, len(jobs), 4, "Should have at least 4 jobs")

	// Find specific jobs
	jobNames := make(map[string]bool)
	for _, node := range jobs {
		jobNode := node.(*graph.JobNode)
		jobNames[jobNode.Name] = true
	}

	assert.True(t, jobNames["test"], "Should have test job from main workflow")
	assert.True(t, jobNames["build"], "Should have build job from local include")
	assert.True(t, jobNames["deploy"], "Should have deploy job from project include")
	assert.True(t, jobNames["sast"], "Should have sast job from template include")
}

// TestIncludedWorkflowsStoredInGraphMetadata tests that included workflows are stored
// as platforms.Workflow objects in graph metadata and accessible via GetIncludedWorkflows
func TestIncludedWorkflowsStoredInGraphMetadata(t *testing.T) {
	// Setup mock GitLab server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle GetWorkflowFile request for local include
		if r.URL.Path == "/api/v4/projects/123/repository/files/.gitlab/ci/build.yml" && r.URL.Query().Get("ref") == "main" {
			mockContent := []byte(`build:
  stage: build
  script:
    - make build`)
			response := gitlab.FileResponse{
				FileName: ".gitlab/ci/build.yml",
				FilePath: ".gitlab/ci/build.yml",
				Encoding: "base64",
				Content:  base64.StdEncoding.EncodeToString(mockContent),
				BlobID:   "abc123",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	// Create client pointing to mock server
	client := gitlab.NewClient(server.URL, "test-token")

	content := []byte(`include:
  - local: '.gitlab/ci/build.yml'

stages:
  - test

test:
  stage: test
  script:
    - make test`)

	gitlabParser := parser.NewGitLabParser()
	normalized, err := gitlabParser.Parse(content)
	require.NoError(t, err)

	g, err := BuildGraphFromNormalized("owner/repo", ".gitlab-ci.yml", normalized, map[string]interface{}{
		"gitlab_client":     client,
		"gitlab_project_id": 123,
		"gitlab_ref":        "main",
	})
	require.NoError(t, err)

	// Verify included workflows are stored in metadata using GetIncludedWorkflows
	includedWorkflows := g.GetIncludedWorkflows("owner/repo")
	require.GreaterOrEqual(t, len(includedWorkflows), 1, "Should have at least 1 included workflow")

	// Find the build.yml workflow
	var buildWorkflow *platforms.Workflow
	for i, wf := range includedWorkflows {
		if strings.Contains(wf.Path, "build.yml") {
			buildWorkflow = &includedWorkflows[i]
			break
		}
	}
	require.NotNil(t, buildWorkflow, "Should find build.yml in included workflows")

	// Verify the workflow has the correct properties
	assert.NotEmpty(t, buildWorkflow.Content, "Workflow should have content")
	assert.Contains(t, string(buildWorkflow.Content), "make build", "Content should contain the build command")
	assert.Equal(t, "owner/repo", buildWorkflow.RepoSlug, "RepoSlug should match")

	// Verify Path is clean path, not cache key
	assert.Equal(t, ".gitlab/ci/build.yml", buildWorkflow.Path, "Path should be clean file path, not cache key")
	assert.NotContains(t, buildWorkflow.Path, "local:", "Path should not contain cache key prefix")
	assert.NotContains(t, buildWorkflow.Path, ":main", "Path should not contain ref suffix")
}
