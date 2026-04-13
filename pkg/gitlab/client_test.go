package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClient_GetProject tests fetching a single project
func TestClient_GetProject(t *testing.T) {
	mockProject := Project{
		ID:                1234,
		Name:              "Test Project",
		Path:              "test-project",
		PathWithNamespace: "owner/test-project",
		DefaultBranch:     "main",
		Visibility:        "public",
		Archived:          false,
		WebURL:            "https://gitlab.com/owner/test-project",
		Namespace: Namespace{
			Name:     "owner",
			FullPath: "owner",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Note: r.URL.Path is automatically decoded by httptest server
		// We encode "owner/test-project" as "owner%2Ftest-project" but it appears decoded here
		assert.Equal(t, "/api/v4/projects/owner/test-project", r.URL.Path)
		assert.Equal(t, "GET", r.Method)

		// Verify authentication header (GitLab uses PRIVATE-TOKEN)
		assert.NotEmpty(t, r.Header.Get("PRIVATE-TOKEN"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockProject)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	project, err := client.GetProject(ctx, "owner/test-project")
	require.NoError(t, err)
	require.NotNil(t, project)

	assert.Equal(t, 1234, project.ID)
	assert.Equal(t, "Test Project", project.Name)
	assert.Equal(t, "test-project", project.Path)
	assert.Equal(t, "owner/test-project", project.PathWithNamespace)
	assert.Equal(t, "main", project.DefaultBranch)
	assert.Equal(t, "public", project.Visibility)
	assert.False(t, project.Archived)
	assert.Equal(t, "owner", project.Namespace.Name)
}

// TestClient_ListGroupProjects tests listing projects in a group
func TestClient_ListGroupProjects(t *testing.T) {
	mockProjects := []Project{
		{
			ID:                1,
			Name:              "Project 1",
			Path:              "project1",
			PathWithNamespace: "group/project1",
			DefaultBranch:     "main",
			Visibility:        "public",
		},
		{
			ID:                2,
			Name:              "Project 2",
			Path:              "project2",
			PathWithNamespace: "group/project2",
			DefaultBranch:     "main",
			Visibility:        "private",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v4/groups/testgroup/projects", r.URL.Path)
		assert.Equal(t, "GET", r.Method)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockProjects)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	projects, err := client.ListGroupProjects(ctx, "testgroup")
	require.NoError(t, err)
	require.Len(t, projects, 2)

	assert.Equal(t, "Project 1", projects[0].Name)
	assert.Equal(t, "project1", projects[0].Path)
	assert.Equal(t, "public", projects[0].Visibility)

	assert.Equal(t, "Project 2", projects[1].Name)
	assert.Equal(t, "project2", projects[1].Path)
	assert.Equal(t, "private", projects[1].Visibility)
}

// TestClient_ListUserProjects tests listing user projects
func TestClient_ListUserProjects(t *testing.T) {
	mockProjects := []Project{
		{
			ID:                1,
			Name:              "User Project",
			Path:              "user-project",
			PathWithNamespace: "username/user-project",
			DefaultBranch:     "main",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v4/users/username/projects", r.URL.Path)
		assert.Equal(t, "GET", r.Method)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockProjects)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	projects, err := client.ListUserProjects(ctx, "username")
	require.NoError(t, err)
	require.Len(t, projects, 1)

	assert.Equal(t, "User Project", projects[0].Name)
	assert.Equal(t, "user-project", projects[0].Path)
}

// TestClient_GetWorkflowFile tests fetching .gitlab-ci.yml
func TestClient_GetWorkflowFile(t *testing.T) {
	mockContent := `stages:
  - build
  - test

build:
  stage: build
  script:
    - npm install
    - npm run build

test:
  stage: test
  script:
    - npm test
`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v4/projects/1234/repository/files/.gitlab-ci.yml", r.URL.Path)
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "main", r.URL.Query().Get("ref"))

		w.Header().Set("Content-Type", "application/json")
		// GitLab returns base64-encoded content
		response := map[string]string{
			"content": mockContent,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	content, err := client.GetWorkflowFile(ctx, 1234, ".gitlab-ci.yml", "main")
	require.NoError(t, err)
	require.NotNil(t, content)

	assert.Contains(t, string(content), "stages:")
	assert.Contains(t, string(content), "npm install")
}

// TestClient_RateLimitHandling tests rate limit header parsing
func TestClient_RateLimitHandling(t *testing.T) {
	mockProject := Project{ID: 1, Name: "test"}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set GitLab rate limit headers (NO X- prefix!)
		w.Header().Set("RateLimit-Limit", "2000")
		w.Header().Set("RateLimit-Remaining", "1500")
		w.Header().Set("RateLimit-Reset", "1735776000") // 2025-01-02 00:00:00 UTC

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockProject)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	_, err := client.GetProject(ctx, "owner/test")
	require.NoError(t, err)

	// Verify rate limiter was updated
	assert.Equal(t, 2000, client.rateLimiter.Limit())
	assert.Equal(t, 1500, client.rateLimiter.Remaining())
}

// TestClient_429RateLimitRetry tests automatic retry on 429 with Retry-After header
func TestClient_429RateLimitRetry(t *testing.T) {
	mockProject := Project{ID: 1, Name: "test"}
	requestCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		// Return 429 on first 2 requests
		if requestCount <= 2 {
			w.Header().Set("Retry-After", "1") // 1 second
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"message": "Rate limited"}`))
			return
		}

		// Return success on 3rd request
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockProject)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	// Should succeed after retries
	project, err := client.GetProject(ctx, "owner/test")
	require.NoError(t, err)
	require.NotNil(t, project)

	// Verify it retried (3 requests total: 2 failures + 1 success)
	assert.Equal(t, 3, requestCount)
	assert.Equal(t, 1, project.ID)
}

// TestClient_429RetryAfterHeader tests parsing of Retry-After header
func TestClient_429RetryAfterHeader(t *testing.T) {
	tests := []struct {
		name       string
		retryAfter string
		expectWait bool
	}{
		{
			name:       "Valid Retry-After header",
			retryAfter: "2",
			expectWait: true,
		},
		{
			name:       "Missing Retry-After header",
			retryAfter: "",
			expectWait: true, // Should default to 60 seconds
		},
		{
			name:       "Invalid Retry-After header",
			retryAfter: "invalid",
			expectWait: true, // Should default to 60 seconds
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockProject := Project{ID: 1, Name: "test"}
			requestCount := 0

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestCount++

				if requestCount == 1 {
					if tt.retryAfter != "" {
						w.Header().Set("Retry-After", tt.retryAfter)
					}
					w.WriteHeader(http.StatusTooManyRequests)
					w.Write([]byte(`{"message": "Rate limited"}`))
					return
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(mockProject)
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-token")
			ctx := context.Background()

			start := time.Now()
			project, err := client.GetProject(ctx, "owner/test")
			elapsed := time.Since(start)

			require.NoError(t, err)
			require.NotNil(t, project)
			assert.Equal(t, 2, requestCount)

			if tt.expectWait {
				// Should have waited at least some time
				assert.Greater(t, elapsed.Milliseconds(), int64(500))
			}
		})
	}
}

// TestClient_429MaxRetries tests retry limit to prevent infinite loops
func TestClient_429MaxRetries(t *testing.T) {
	requestCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		// Always return 429
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"message": "Rate limited"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	// Should fail after max retries
	_, err := client.GetProject(ctx, "owner/test")
	require.Error(t, err)

	// Should have tried exactly 3 times (initial + 2 retries = max 3 attempts)
	assert.Equal(t, 3, requestCount)
	assert.Contains(t, err.Error(), "429")
}

// TestGetProjectMember tests fetching project member access level
func TestGetProjectMember(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v4/projects/123/members/all/456", r.URL.Path)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ProjectMember{
			ID:          456,
			Username:    "testuser",
			AccessLevel: 30,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	member, err := client.GetProjectMember(context.Background(), 123, "456")
	assert.NoError(t, err)
	assert.Equal(t, 30, member.AccessLevel)
	assert.Equal(t, "Developer", member.RoleName)
}

// TestDeleteJobLogs tests erasing job trace
func TestDeleteJobLogs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v4/projects/123/jobs/456/erase", r.URL.Path)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":        456,
			"erased_at": "2026-02-24T12:00:00Z",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	err := client.DeleteJobLogs(context.Background(), 123, 456)
	assert.NoError(t, err)
}

// TestDeleteBranch tests deleting a repository branch
func TestDeleteBranch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/api/v4/projects/123/repository/branches/test-branch", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	err := client.DeleteBranch(context.Background(), 123, "test-branch")
	assert.NoError(t, err)
}

// TestDeletePipeline tests deleting a pipeline
func TestDeletePipeline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/api/v4/projects/123/pipelines/456", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	err := client.DeletePipeline(context.Background(), 123, 456)
	assert.NoError(t, err)
}

// TestCreateBranch tests creating a new branch
func TestCreateBranch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v4/projects/123/repository/branches", r.URL.Path)
		assert.Equal(t, "test-branch", r.URL.Query().Get("branch"))
		assert.Equal(t, "abc123", r.URL.Query().Get("ref"))

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(Branch{
			Name: "test-branch",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	err := client.CreateBranch(context.Background(), 123, "test-branch", "abc123")
	assert.NoError(t, err)
}

// TestGetBranch tests fetching branch information
func TestGetBranch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v4/projects/123/repository/branches/main", r.URL.Path)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Branch{
			Name: "main",
			Commit: struct {
				ID string `json:"id"`
			}{
				ID: "abc123def456",
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	branch, err := client.GetBranch(context.Background(), 123, "main")
	assert.NoError(t, err)
	assert.Equal(t, "main", branch.Name)
	assert.Equal(t, "abc123def456", branch.Commit.ID)
}

// TestCreateCommit tests creating a commit with file actions
func TestCreateCommit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v4/projects/123/repository/commits", r.URL.Path)

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(Commit{
			ID:      "def789",
			ShortID: "def789ab",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	actions := []CommitAction{
		{
			Action:   "create",
			FilePath: ".gitlab-ci.yml",
			Content:  "test: content",
		},
	}

	commit, err := client.CreateCommit(context.Background(), 123, "test-branch", actions, "Test commit")
	assert.NoError(t, err)
	assert.Equal(t, "def789", commit.ID)
}

// TestListPipelines tests listing pipelines with branch filter
func TestListPipelines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v4/projects/123/pipelines", r.URL.Path)
		assert.Equal(t, "test-branch", r.URL.Query().Get("ref"))

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]Pipeline{
			{
				ID:     456,
				Ref:    "test-branch",
				Status: "success",
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	pipelines, err := client.ListPipelines(context.Background(), 123, "test-branch")
	assert.NoError(t, err)
	assert.Len(t, pipelines, 1)
	assert.Equal(t, 456, pipelines[0].ID)
	assert.Equal(t, "test-branch", pipelines[0].Ref)
}

// TestListPipelineJobs tests fetching jobs for a pipeline
func TestListPipelineJobs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v4/projects/123/pipelines/456/jobs", r.URL.Path)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]Job{
			{
				ID:     789,
				Name:   "build_job",
				Status: "success",
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	jobs, err := client.ListPipelineJobs(context.Background(), 123, 456)
	assert.NoError(t, err)
	assert.Len(t, jobs, 1)
	assert.Equal(t, 789, jobs[0].ID)
	assert.Equal(t, "build_job", jobs[0].Name)
}

// TestGetJobTrace tests downloading job logs
func TestGetJobTrace(t *testing.T) {
	mockLogs := "Job log output\nWith multiple lines\n$encrypted$data$"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v4/projects/123/jobs/789/trace", r.URL.Path)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockLogs))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	logs, err := client.GetJobTrace(context.Background(), 123, 789)
	assert.NoError(t, err)
	assert.Equal(t, mockLogs, logs)
}

func TestClient_GetJobTrace_410Gone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "410 Gone - Logs have been deleted",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	trace, err := client.GetJobTrace(context.Background(), 123, 789)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "410")
	assert.Empty(t, trace)
}

func TestClient_ListRecentPipelines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v4/projects/123/pipelines" {
			pipelines := []Pipeline{
				{ID: 1, Status: "success", Ref: "main"},
				{ID: 2, Status: "failed", Ref: "develop"},
			}
			json.NewEncoder(w).Encode(pipelines)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	pipelines, err := client.ListRecentPipelines(context.Background(), 123, 5)

	require.NoError(t, err)
	assert.Len(t, pipelines, 2)
	assert.Equal(t, 1, pipelines[0].ID)
	assert.Equal(t, "success", pipelines[0].Status)
}

// TestClient_GetTemplate_Caching tests that GetTemplate caches the project ID
// to avoid redundant GetProject calls for each template fetch
func TestClient_GetTemplate_Caching(t *testing.T) {
	getProjectCallCount := 0
	getFileCallCount := 0

	mockProject := Project{
		ID:                278964,
		Name:              "GitLab",
		PathWithNamespace: "gitlab-org/gitlab",
	}

	mockTemplateContent := `# Docker template
stages:
  - build
  - test

build:
  image: docker:latest
  script:
    - docker build -t myapp .
`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Track GetProject calls
		if r.URL.Path == "/api/v4/projects/gitlab-org/gitlab" {
			getProjectCallCount++
			json.NewEncoder(w).Encode(mockProject)
			return
		}

		// Track GetWorkflowFile calls for templates
		// The path will look like /api/v4/projects/278964/repository/files/lib/gitlab/ci/templates/Docker.gitlab-ci.yml
		// Note: httptest.NewServer auto-decodes URL paths, so we check for decoded path
		if strings.Contains(r.URL.Path, "/repository/files/lib/gitlab/ci/templates/") {
			getFileCallCount++
			assert.Equal(t, "master", r.URL.Query().Get("ref"))

			response := FileResponse{
				Content:  mockTemplateContent,
				Encoding: "",
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		t.Logf("Unhandled request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	// Fetch 3 different templates
	templates := []string{"Docker.gitlab-ci.yml", "Nodejs.gitlab-ci.yml", "Python.gitlab-ci.yml"}

	for _, templateName := range templates {
		content, err := client.GetTemplate(ctx, templateName)
		require.NoError(t, err)
		require.NotEmpty(t, content)
		assert.Contains(t, string(content), "stages:")
	}

	// CRITICAL: GetProject should be called only ONCE (cached), not 3 times
	assert.Equal(t, 1, getProjectCallCount, "GetProject should be called only once due to caching")

	// But GetWorkflowFile should be called 3 times (once per template)
	assert.Equal(t, 3, getFileCallCount, "GetWorkflowFile should be called for each template")
}

// TestClient_GetTemplate_ConcurrentCaching tests thread-safety of template project caching
// Ensures lazy initialization works correctly when multiple goroutines fetch templates simultaneously
func TestClient_GetTemplate_ConcurrentCaching(t *testing.T) {
	getProjectCallCount := 0
	var mu sync.Mutex

	mockProject := Project{
		ID:                278964,
		PathWithNamespace: "gitlab-org/gitlab",
	}

	mockTemplateContent := "stages:\n  - test\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/v4/projects/gitlab-org/gitlab" {
			mu.Lock()
			getProjectCallCount++
			mu.Unlock()
			// Add small delay to increase chance of race condition if locking is broken
			time.Sleep(10 * time.Millisecond)
			json.NewEncoder(w).Encode(mockProject)
			return
		}

		if strings.Contains(r.URL.Path, "/repository/files/lib/gitlab/ci/templates/") {
			response := FileResponse{Content: mockTemplateContent}
			json.NewEncoder(w).Encode(response)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	// Launch 10 concurrent template fetches
	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			templateName := fmt.Sprintf("Template-%d.gitlab-ci.yml", idx)
			_, err := client.GetTemplate(ctx, templateName)
			require.NoError(t, err)
		}(i)
	}

	wg.Wait()

	// With proper locking, GetProject should be called exactly once
	// Without locking, it could be called multiple times
	mu.Lock()
	count := getProjectCallCount
	mu.Unlock()

	assert.Equal(t, 1, count, "GetProject should be called exactly once even with concurrent access")
}

// BenchmarkGetTemplate_WithCaching benchmarks template fetching with caching enabled
func BenchmarkGetTemplate_WithCaching(b *testing.B) {
	mockProject := Project{
		ID:                278964,
		PathWithNamespace: "gitlab-org/gitlab",
	}

	mockTemplateContent := "stages:\n  - test\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/v4/projects/gitlab-org/gitlab" {
			json.NewEncoder(w).Encode(mockProject)
			return
		}

		if strings.Contains(r.URL.Path, "/repository/files/lib/gitlab/ci/templates/") {
			response := FileResponse{Content: mockTemplateContent}
			json.NewEncoder(w).Encode(response)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	// Reset the timer to exclude setup time
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Fetch different templates to simulate real usage
		templateName := fmt.Sprintf("Template-%d.gitlab-ci.yml", i%5)
		_, err := client.GetTemplate(ctx, templateName)
		if err != nil {
			b.Fatalf("GetTemplate failed: %v", err)
		}
	}
}

// TestClient_APIErrorTyped verifies that doRequest returns a typed *APIError
// on non-2xx responses, enabling callers to use errors.As for structured inspection.
func TestClient_APIErrorTyped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"404 Project Not Found"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.GetProject(context.Background(), "owner/missing")
	require.Error(t, err)

	// Error must be inspectable as *APIError through the wrapping chain
	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr), "expected *APIError in chain, got: %T — %v", err, err)
	assert.Equal(t, 404, apiErr.StatusCode)
	assert.Contains(t, apiErr.Body, "404 Project Not Found")

	// Helper must work
	assert.True(t, IsNotFoundError(err))
	assert.False(t, IsPermissionError(err))
}

// TestClient_APIErrorTyped_WriteMethod verifies that doRequestWithBody (POST/PUT/DELETE) returns
// a typed *APIError on non-2xx responses, enabling callers to use errors.As for structured inspection.
// This tests the POST path (CreateCommit -> postJSON -> doRequestWithBody).
func TestClient_APIErrorTyped_WriteMethod(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"404 Project Not Found"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	actions := []CommitAction{
		{
			Action:   "create",
			FilePath: ".gitlab-ci.yml",
			Content:  "test: content",
		},
	}
	_, err := client.CreateCommit(context.Background(), 123, "test-branch", actions, "Test commit")
	require.Error(t, err)

	// Error must be inspectable as *APIError through the wrapping chain
	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr), "expected *APIError in chain, got: %T — %v", err, err)
	assert.Equal(t, 404, apiErr.StatusCode)
	assert.Contains(t, apiErr.Body, "404 Project Not Found")
}
