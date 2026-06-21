// pkg/github/github_workflow_errors_test.go
package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// TestGitHubPlatform_ScanCollectsWorkflowErrors tests that workflow fetching errors are collected
// This test will FAIL with current code (errors are silently ignored)
func TestGitHubPlatform_ScanCollectsWorkflowErrors(t *testing.T) {
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
			// Return 3 workflow files
			w.Write([]byte(`[
				{"name": "success.yml", "path": ".github/workflows/success.yml", "sha": "abc123"},
				{"name": "forbidden.yml", "path": ".github/workflows/forbidden.yml", "sha": "def456"},
				{"name": "ratelimit.yml", "path": ".github/workflows/ratelimit.yml", "sha": "ghi789"}
			]`))
		case "/repos/owner/repo/contents/.github/workflows/success.yml":
			// This one succeeds
			content := "bmFtZTogU3VjY2VzcwpvbjogcHVzaA==" // base64: "name: Success\non: push"
			w.Write([]byte(`{
				"name": "success.yml",
				"path": ".github/workflows/success.yml",
				"content": "` + content + `",
				"encoding": "base64"
			}`))
		case "/repos/owner/repo/contents/.github/workflows/forbidden.yml":
			// This one returns 403 Forbidden (insufficient permissions)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"message": "Resource not accessible by personal access token"}`))
		case "/repos/owner/repo/contents/.github/workflows/ratelimit.yml":
			// This one returns 429 Rate Limit
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"message": "API rate limit exceeded"}`))
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

	// Should have 1 repository
	assert.Len(t, result.Repositories, 1)

	// Should have workflows (only the successful one)
	workflows, ok := result.Workflows["owner/repo"]
	require.True(t, ok)
	assert.Len(t, workflows, 1, "should have 1 successful workflow")
	assert.Equal(t, "success.yml", workflows[0].Name)

	// NEW ASSERTION: Should collect errors for the 2 failed workflows
	assert.Len(t, result.Errors, 2, "should collect 2 errors for the 2 failed workflow fetches")

	// Errors should mention the repository and the failed workflow paths
	if len(result.Errors) >= 2 {
		assert.Contains(t, result.Errors[0].Error(), "owner/repo", "error should mention the repository")
		assert.Contains(t, result.Errors[0].Error(), "forbidden.yml", "error should mention the failed file")
		assert.Contains(t, result.Errors[1].Error(), "owner/repo", "error should mention the repository")
		assert.Contains(t, result.Errors[1].Error(), "ratelimit.yml", "error should mention the failed file")
	}
}

// TestGetWorkflowsReturnsPartialResults tests that getWorkflows returns both successes and errors
// This test will FAIL with current code (getWorkflows returns nil error even when some workflows fail)
func TestGetWorkflowsReturnsPartialResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.Header().Set("X-RateLimit-Limit", "5000")

		switch r.URL.Path {
		case "/repos/owner/repo/contents/.github/workflows":
			w.Write([]byte(`[
				{"name": "good.yml", "path": ".github/workflows/good.yml", "sha": "abc"},
				{"name": "bad.yml", "path": ".github/workflows/bad.yml", "sha": "def"}
			]`))
		case "/repos/owner/repo/contents/.github/workflows/good.yml":
			content := "bmFtZTogR29vZApvbjogcHVzaA==" // base64: "name: Good\non: push"
			w.Write([]byte(`{
				"name": "good.yml",
				"path": ".github/workflows/good.yml",
				"content": "` + content + `",
				"encoding": "base64"
			}`))
		case "/repos/owner/repo/contents/.github/workflows/bad.yml":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"message": "Not accessible"}`))
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

	// Call getWorkflows directly to test the internal function
	workflows, errors := p.getWorkflows(context.Background(), "owner", "repo")

	// Should return workflows (not nil) even when some fail
	assert.NotNil(t, workflows, "should return workflows array")
	assert.Len(t, workflows, 1, "should have 1 successful workflow")
	assert.Equal(t, "good.yml", workflows[0].Name)

	// NEW BEHAVIOR: getWorkflows should return errors slice with workflow fetch failures
	assert.Len(t, errors, 1, "should have 1 error for the failed workflow")
	if len(errors) > 0 {
		assert.Contains(t, errors[0].Error(), "bad.yml", "error should mention the failed workflow file")
	}
}
