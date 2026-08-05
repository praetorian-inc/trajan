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
		// httptest decodes the path, so the encoded "owner%2Ftest-project" arrives split.
		assert.Equal(t, "/api/v4/projects/owner/test-project", r.URL.Path)
		assert.Equal(t, "GET", r.Method)

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

func TestClient_RateLimitHandling(t *testing.T) {
	mockProject := Project{ID: 1, Name: "test"}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// GitLab omits the X- prefix on these headers.
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

	assert.Equal(t, 2000, client.rateLimiter.Limit())
	assert.Equal(t, 1500, client.rateLimiter.Remaining())
}

func TestClient_429RateLimitRetry(t *testing.T) {
	mockProject := Project{ID: 1, Name: "test"}
	requestCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		if requestCount <= 2 {
			w.Header().Set("Retry-After", "1")
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

	project, err := client.GetProject(ctx, "owner/test")
	require.NoError(t, err)
	require.NotNil(t, project)

	// 2 failures + 1 success.
	assert.Equal(t, 3, requestCount)
	assert.Equal(t, 1, project.ID)
}

// A wrong fallback here means a 429 either hammers GitLab immediately or stalls a
// scan far longer than the server asked for, and both retry loops depend on it.
func TestRetryAfterSeconds(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  int
	}{
		{"valid", "2", 2},
		{"absent", "", 60},
		{"unparseable", "invalid", 60},
		{"http-date form is not supported", "Wed, 21 Oct 2026 07:28:00 GMT", 60},
		{"zero means retry immediately", "0", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			if tt.value != "" {
				h.Set("Retry-After", tt.value)
			}
			assert.Equal(t, tt.want, retryAfterSeconds(h))
		})
	}
}

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
		// Only the valid case runs end-to-end: the fallback is a real 60s sleep with
		// no clock to inject. TestRetryAfterSeconds covers the parse itself instead.
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
				assert.Greater(t, elapsed.Milliseconds(), int64(500))
			}
		})
	}
}

func TestClient_429MaxRetries(t *testing.T) {
	requestCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"message": "Rate limited"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	_, err := client.GetProject(ctx, "owner/test")
	require.Error(t, err)

	// initial attempt + 2 retries.
	assert.Equal(t, 3, requestCount)
	assert.Contains(t, err.Error(), "429")
}

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

		if r.URL.Path == "/api/v4/projects/gitlab-org/gitlab" {
			getProjectCallCount++
			json.NewEncoder(w).Encode(mockProject)
			return
		}

		// httptest decodes the path, so match on the decoded form.
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

	templates := []string{"Docker.gitlab-ci.yml", "Nodejs.gitlab-ci.yml", "Python.gitlab-ci.yml"}

	for _, templateName := range templates {
		content, err := client.GetTemplate(ctx, templateName)
		require.NoError(t, err)
		require.NotEmpty(t, content)
		assert.Contains(t, string(content), "stages:")
	}

	assert.Equal(t, 1, getProjectCallCount, "GetProject should be called only once due to caching")

	assert.Equal(t, 3, getFileCallCount, "GetWorkflowFile should be called for each template")
}

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
			// Widen the race window so broken locking shows up.
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

	// Correct locking fetches the project exactly once.
	mu.Lock()
	count := getProjectCallCount
	mu.Unlock()

	assert.Equal(t, 1, count, "GetProject should be called exactly once even with concurrent access")
}

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

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		templateName := fmt.Sprintf("Template-%d.gitlab-ci.yml", i%5)
		_, err := client.GetTemplate(ctx, templateName)
		if err != nil {
			b.Fatalf("GetTemplate failed: %v", err)
		}
	}
}

func TestClient_APIErrorTyped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"404 Project Not Found"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.GetProject(context.Background(), "owner/missing")
	require.Error(t, err)

	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr), "expected *APIError in chain, got: %T — %v", err, err)
	assert.Equal(t, 404, apiErr.StatusCode)
	assert.Contains(t, apiErr.Body, "404 Project Not Found")

	assert.True(t, IsNotFoundError(err))
	assert.False(t, IsPermissionError(err))
}

// Exercises the POST path: CreateCommit -> postJSON -> doRequestWithBody.
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

	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr), "expected *APIError in chain, got: %T — %v", err, err)
	assert.Equal(t, 404, apiErr.StatusCode)
	assert.Contains(t, apiErr.Body, "404 Project Not Found")
}
