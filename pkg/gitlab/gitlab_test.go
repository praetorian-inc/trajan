// pkg/gitlab/gitlab_test.go
package gitlab

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestGitLabPlatform_Name(t *testing.T) {
	p := NewPlatform()
	assert.Equal(t, "gitlab", p.Name())
}

func TestGitLabPlatform_Init(t *testing.T) {
	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{
		GitLab: &platforms.GitLabAuth{
			Token: "test-token",
		},
		BaseURL: "https://gitlab.com/api/v4",
	})
	require.NoError(t, err)
	assert.NotNil(t, p.Client())
}

func TestGitLabPlatform_ScanProject(t *testing.T) {
	ciContent := "stages:\n  - build\n  - test"
	encodedContent := base64.StdEncoding.EncodeToString([]byte(ciContent))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("RateLimit-Remaining", "1999")
		w.Header().Set("RateLimit-Limit", "2000")

		switch r.URL.Path {
		case "/api/v4/projects/owner/project":
			w.Write([]byte(`{
				"id": 123,
				"name": "project",
				"path": "project",
				"path_with_namespace": "owner/project",
				"default_branch": "main",
				"visibility": "private",
				"archived": false,
				"web_url": "https://gitlab.com/owner/project",
				"namespace": {
					"name": "owner",
					"full_path": "owner"
				}
			}`))
		case "/api/v4/projects/123/repository/files/.gitlab-ci.yml":
			w.Write([]byte(`{
				"file_name": ".gitlab-ci.yml",
				"file_path": ".gitlab-ci.yml",
				"content": "` + encodedContent + `",
				"encoding": "base64",
				"blob_id": "abc123"
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{
		GitLab: &platforms.GitLabAuth{
			Token: "test-token",
		},
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	result, err := p.Scan(context.Background(), platforms.Target{
		Type:  platforms.TargetRepo,
		Value: "owner/project",
	})
	require.NoError(t, err)

	assert.Len(t, result.Repositories, 1)
	assert.Equal(t, "owner", result.Repositories[0].Owner)
	assert.Equal(t, "project", result.Repositories[0].Name)

	workflows, ok := result.Workflows["owner/project"]
	require.True(t, ok)
	assert.Len(t, workflows, 1)
	assert.Equal(t, ".gitlab-ci.yml", workflows[0].Name)
	assert.Equal(t, ciContent, string(workflows[0].Content))
}

func TestGitLabPlatform_ScanGroup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("RateLimit-Remaining", "1999")
		w.Header().Set("RateLimit-Limit", "2000")

		switch {
		case r.URL.Path == "/api/v4/groups/mygroup/projects" && r.URL.Query().Get("page") == "2":
			w.Write([]byte(`[]`))
		case r.URL.Path == "/api/v4/groups/mygroup/projects":
			w.Write([]byte(`[
				{
					"id": 1,
					"name": "project1",
					"path": "project1",
					"path_with_namespace": "mygroup/project1",
					"default_branch": "main",
					"visibility": "public",
					"namespace": {
						"name": "mygroup",
						"full_path": "mygroup"
					}
				},
				{
					"id": 2,
					"name": "project2",
					"path": "project2",
					"path_with_namespace": "mygroup/project2",
					"default_branch": "main",
					"visibility": "private",
					"namespace": {
						"name": "mygroup",
						"full_path": "mygroup"
					}
				}
			]`))
		case strings.HasPrefix(r.URL.Path, "/api/v4/projects/"):
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{
		GitLab: &platforms.GitLabAuth{
			Token: "test-token",
		},
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	result, err := p.Scan(context.Background(), platforms.Target{
		Type:  platforms.TargetOrg,
		Value: "mygroup",
	})
	require.NoError(t, err)

	assert.Len(t, result.Repositories, 2)
	// No workflows since mock returns 404
	assert.Empty(t, result.Workflows)
}

func TestGitLabPlatform_InvalidProjectFormat(t *testing.T) {
	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{
		GitLab: &platforms.GitLabAuth{
			Token: "test-token",
		},
		BaseURL: "https://gitlab.com/api/v4",
	})
	require.NoError(t, err)

	_, err = p.Scan(context.Background(), platforms.Target{
		Type:  platforms.TargetRepo,
		Value: "invalid-no-slash",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid repo format")
}

func TestGitLabPlatform_Registration(t *testing.T) {
	// Import triggers init() which registers the platform
	p, err := registry.GetPlatform("gitlab")
	require.NoError(t, err)
	assert.Equal(t, "gitlab", p.Name())
}

func TestScanAttachesResolverMetadata(t *testing.T) {
	// This test verifies metadata is attached to workflows
	// Actual resolution is tested in builder tests

	ciContent := "stages:\n  - build\n  - test"
	encodedContent := base64.StdEncoding.EncodeToString([]byte(ciContent))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("RateLimit-Remaining", "1999")
		w.Header().Set("RateLimit-Limit", "2000")

		switch r.URL.Path {
		case "/api/v4/projects/owner/repo":
			w.Write([]byte(`{
				"id": 123,
				"name": "repo",
				"path": "repo",
				"path_with_namespace": "owner/repo",
				"default_branch": "main",
				"visibility": "private",
				"archived": false,
				"web_url": "https://gitlab.com/owner/repo",
				"namespace": {
					"name": "owner",
					"full_path": "owner"
				}
			}`))
		case "/api/v4/projects/123/repository/files/.gitlab-ci.yml":
			w.Write([]byte(`{
				"file_name": ".gitlab-ci.yml",
				"file_path": ".gitlab-ci.yml",
				"content": "` + encodedContent + `",
				"encoding": "base64",
				"blob_id": "abc123"
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	platform := NewPlatform()
	err := platform.Init(context.Background(), platforms.Config{
		GitLab: &platforms.GitLabAuth{
			Token: "test-token",
		},
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	ctx := context.Background()
	target := platforms.Target{
		Type:  platforms.TargetRepo,
		Value: "owner/repo",
	}

	result, err := platform.Scan(ctx, target)
	require.NoError(t, err)

	// Check that workflows have metadata
	for _, workflows := range result.Workflows {
		for _, wf := range workflows {
			require.NotNil(t, wf.Metadata, "expected metadata, got nil")

			_, hasClient := wf.Metadata["gitlab_client"]
			assert.True(t, hasClient, "expected gitlab_client in metadata")

			projectID, hasProjectID := wf.Metadata["gitlab_project_id"]
			assert.True(t, hasProjectID, "expected gitlab_project_id in metadata")
			assert.Equal(t, 123, projectID, "expected project ID to be 123")

			ref, hasRef := wf.Metadata["gitlab_ref"]
			assert.True(t, hasRef, "expected gitlab_ref in metadata")
			assert.Equal(t, "main", ref, "expected ref to be 'main'")
		}
	}
}
