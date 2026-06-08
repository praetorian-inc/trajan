// pkg/github/github_test.go
package github

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestGitHubPlatform_Name(t *testing.T) {
	p := NewPlatform()
	assert.Equal(t, "github", p.Name())
}

func TestGitHubPlatform_Init(t *testing.T) {
	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: "https://api.github.com",
	})
	require.NoError(t, err)
	assert.NotNil(t, p.Client())
}

func TestGitHubPlatform_ScanRepo(t *testing.T) {
	workflowContent := "name: CI\non: push"
	encodedContent := base64.StdEncoding.EncodeToString([]byte(workflowContent))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.Header().Set("X-RateLimit-Limit", "5000")

		switch r.URL.Path {
		case "/repos/owner/repo":
			w.Write([]byte(`{
				"full_name": "owner/repo",
				"owner": {"login": "owner"},
				"name": "repo",
				"default_branch": "main",
				"private": false,
				"archived": false,
				"html_url": "https://github.com/owner/repo"
			}`))
		case "/repos/owner/repo/contents/.github/workflows":
			w.Write([]byte(`[
				{"name": "ci.yml", "path": ".github/workflows/ci.yml", "sha": "abc123"}
			]`))
		case "/repos/owner/repo/contents/.github/workflows/ci.yml":
			w.Write([]byte(`{
				"name": "ci.yml",
				"path": ".github/workflows/ci.yml",
				"content": "` + encodedContent + `",
				"encoding": "base64"
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	result, err := p.Scan(context.Background(), platforms.Target{
		Type:  platforms.TargetRepo,
		Value: "owner/repo",
	})
	require.NoError(t, err)

	assert.Len(t, result.Repositories, 1)
	assert.Equal(t, "owner", result.Repositories[0].Owner)
	assert.Equal(t, "repo", result.Repositories[0].Name)

	workflows, ok := result.Workflows["owner/repo"]
	require.True(t, ok)
	assert.Len(t, workflows, 1)
	assert.Equal(t, "ci.yml", workflows[0].Name)
	assert.Equal(t, workflowContent, string(workflows[0].Content))
}

func TestGitHubPlatform_ScanOrg(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.Header().Set("X-RateLimit-Limit", "5000")

		switch {
		case r.URL.Path == "/orgs/myorg/repos" && r.URL.Query().Get("page") == "2":
			w.Write([]byte(`[]`))
		case r.URL.Path == "/orgs/myorg/repos":
			w.Write([]byte(`[
				{"full_name": "myorg/repo1", "owner": {"login": "myorg"}, "name": "repo1", "default_branch": "main"},
				{"full_name": "myorg/repo2", "owner": {"login": "myorg"}, "name": "repo2", "default_branch": "main"}
			]`))
		case r.URL.Path == "/repos/myorg/repo1/contents/.github/workflows":
			w.WriteHeader(http.StatusNotFound)
		case r.URL.Path == "/repos/myorg/repo2/contents/.github/workflows":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	result, err := p.Scan(context.Background(), platforms.Target{
		Type:  platforms.TargetOrg,
		Value: "myorg",
	})
	require.NoError(t, err)

	assert.Len(t, result.Repositories, 2)
	// No workflows since mock returns 404
	assert.Empty(t, result.Workflows)
}

func TestGitHubPlatform_InvalidRepoFormat(t *testing.T) {
	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: "https://api.github.com",
	})
	require.NoError(t, err)

	_, err = p.Scan(context.Background(), platforms.Target{
		Type:  platforms.TargetRepo,
		Value: "invalid-no-slash",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid repo format")
}

func TestGitHubPlatform_Registration(t *testing.T) {
	// Import triggers init() which registers the platform
	p, err := registry.GetPlatform("github")
	require.NoError(t, err)
	assert.Equal(t, "github", p.Name())
}

func TestPlatform_ScanSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/orgs/test-org/actions/secrets"):
			w.WriteHeader(200)
			w.Write([]byte(`{
				"total_count": 1,
				"secrets": [{"name": "ORG_SECRET", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z"}]
			}`))
		case strings.Contains(r.URL.Path, "/repos/") && strings.Contains(r.URL.Path, "/actions/organization-secrets"):
			// Org secrets accessible to repo
			w.WriteHeader(200)
			w.Write([]byte(`{
				"total_count": 1,
				"secrets": [{"name": "ORG_ACCESSIBLE_SECRET", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z"}]
			}`))
		case strings.Contains(r.URL.Path, "/repos/") && strings.Contains(r.URL.Path, "/environments"):
			// Environment secrets or environment listing
			w.WriteHeader(404)
			w.Write([]byte(`{"message": "Not Found"}`))
		case strings.Contains(r.URL.Path, "/repos/"):
			// Repo-level secrets
			w.WriteHeader(200)
			w.Write([]byte(`{
				"total_count": 1,
				"secrets": [{"name": "REPO_SECRET", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z"}]
			}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	// Test org target
	result, err := p.ScanSecrets(context.Background(), platforms.Target{
		Type:  platforms.TargetOrg,
		Value: "test-org",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.ActionsSecrets, 1)
	orgSecrets, ok := result.ActionsSecrets["test-org"]
	require.True(t, ok)
	assert.Len(t, orgSecrets, 1)
	assert.Equal(t, "ORG_SECRET", orgSecrets[0].Name)

	// Test repo target
	result, err = p.ScanSecrets(context.Background(), platforms.Target{
		Type:  platforms.TargetRepo,
		Value: "test-owner/test-repo",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.ActionsSecrets, 1)
	repoSecrets, ok := result.ActionsSecrets["test-owner/test-repo"]
	require.True(t, ok)
	assert.Len(t, repoSecrets, 2) // Now includes repo secret + org secret accessible to repo
	assert.Equal(t, "REPO_SECRET", repoSecrets[0].Name)
	assert.Equal(t, "ORG_ACCESSIBLE_SECRET", repoSecrets[1].Name)
}

func TestPlatform_ScanRunners(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/orgs/test-org/actions/runners") && !strings.Contains(r.URL.Path, "runner-groups"):
			w.WriteHeader(200)
			w.Write([]byte(`{
				"total_count": 1,
				"runners": [{"id": 1, "name": "org-runner", "os": "linux", "status": "online", "busy": false, "labels": []}]
			}`))
		case strings.Contains(r.URL.Path, "/orgs/test-org/actions/runner-groups"):
			w.WriteHeader(200)
			w.Write([]byte(`{
				"total_count": 1,
				"runner_groups": [{"id": 1, "name": "Default", "visibility": "all", "default": true}]
			}`))
		case strings.Contains(r.URL.Path, "/repos/"):
			w.WriteHeader(200)
			w.Write([]byte(`{
				"total_count": 1,
				"runners": [{"id": 2, "name": "repo-runner", "os": "linux", "status": "online", "busy": false, "labels": []}]
			}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	// Test org target
	result, err := p.ScanRunners(context.Background(), platforms.Target{
		Type:  platforms.TargetOrg,
		Value: "test-org",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Runners, 1)
	assert.Len(t, result.RunnerGroups, 1)
}

func TestPlatform_ScanSecrets_WorkflowExtraction(t *testing.T) {
	// Mock workflow content with secrets
	workflowContent := `name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      API_KEY: ${{ secrets.DEPLOY_KEY }}
    steps:
      - name: Deploy
        run: echo "Deploying with ${{ secrets.GITHUB_TOKEN }}"
      - name: Notify
        with:
          slack_token: ${{ secrets.SLACK_TOKEN }}
`
	encodedContent := base64.StdEncoding.EncodeToString([]byte(workflowContent))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.Header().Set("X-RateLimit-Limit", "5000")

		switch {
		case strings.Contains(r.URL.Path, "/repos/owner/repo/actions/secrets"):
			// Return API secrets
			w.WriteHeader(200)
			w.Write([]byte(`{
				"total_count": 1,
				"secrets": [{"name": "API_SECRET", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z"}]
			}`))
		case r.URL.Path == "/repos/owner/repo":
			w.Write([]byte(`{
				"full_name": "owner/repo",
				"owner": {"login": "owner"},
				"name": "repo",
				"default_branch": "main"
			}`))
		case r.URL.Path == "/repos/owner/repo/contents/.github/workflows":
			w.Write([]byte(`[
				{"name": "deploy.yml", "path": ".github/workflows/deploy.yml", "sha": "abc123"}
			]`))
		case r.URL.Path == "/repos/owner/repo/contents/.github/workflows/deploy.yml":
			w.Write([]byte(`{
				"name": "deploy.yml",
				"path": ".github/workflows/deploy.yml",
				"content": "` + encodedContent + `",
				"encoding": "base64"
			}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	result, err := p.ScanSecrets(context.Background(), platforms.Target{
		Type:  platforms.TargetRepo,
		Value: "owner/repo",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify API secrets are populated with Source="api"
	assert.Len(t, result.ActionsSecrets, 1)
	apiSecrets, ok := result.ActionsSecrets["owner/repo"]
	require.True(t, ok)
	assert.Len(t, apiSecrets, 1)
	assert.Equal(t, "API_SECRET", apiSecrets[0].Name)
	assert.Equal(t, "api", apiSecrets[0].Source)

	// Verify WorkflowSecrets are populated with Source="workflow"
	assert.Len(t, result.WorkflowSecrets, 1)
	workflowSecrets, ok := result.WorkflowSecrets["owner/repo"]
	require.True(t, ok)
	assert.Len(t, workflowSecrets, 3) // DEPLOY_KEY, GITHUB_TOKEN, SLACK_TOKEN

	// Verify all workflow secrets have correct source
	secretNames := make(map[string]bool)
	for _, s := range workflowSecrets {
		assert.Equal(t, "workflow", s.Source)
		secretNames[s.Name] = true
	}
	assert.True(t, secretNames["DEPLOY_KEY"])
	assert.True(t, secretNames["GITHUB_TOKEN"])
	assert.True(t, secretNames["SLACK_TOKEN"])
}

func TestPlatform_ScanTokenInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user" {
			w.Header().Set("X-OAuth-Scopes", "repo, workflow")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"login": "testuser", "name": "Test User"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	platform := NewPlatform()
	err := platform.Init(context.Background(), platforms.Config{
		BaseURL: server.URL,
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	result, err := platform.ScanTokenInfo(context.Background())
	if err != nil {
		t.Fatalf("ScanTokenInfo() error = %v", err)
	}

	if result.TokenInfo == nil {
		t.Error("ScanTokenInfo().TokenInfo = nil, want non-nil")
	}
	if result.TokenInfo.User != "testuser" {
		t.Errorf("ScanTokenInfo().TokenInfo.User = %q, want %q", result.TokenInfo.User, "testuser")
	}
}

func TestPlatform_Scan_GitHubAppAllAccessible(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/installation/repositories":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"total_count":1,"repository_selection":"all","repositories":[
				{"name":"a","full_name":"acme/a","owner":{"login":"acme","type":"Organization"}}]}`)
		case "/repos/acme/a/contents/.github/workflows":
			w.WriteHeader(http.StatusNotFound) // no workflows
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := NewPlatform()
	if err := p.Init(context.Background(), platforms.Config{BaseURL: server.URL, Token: "ghs_test"}); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	result, err := p.Scan(context.Background(), platforms.Target{Type: platforms.TargetUser, Value: ""})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(result.Repositories) != 1 || result.Repositories[0].Name != "a" {
		t.Errorf("Repositories = %+v, want [a]", result.Repositories)
	}
}
