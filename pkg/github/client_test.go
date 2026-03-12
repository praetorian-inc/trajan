// pkg/github/client_test.go
package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_GetUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/user", r.URL.Path)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"login":"testuser","id":12345}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	user, err := client.GetUser(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Login)
	assert.Equal(t, 12345, user.ID)
}

func TestClient_GetRepository(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/owner/repo", r.URL.Path)
		w.Header().Set("X-RateLimit-Remaining", "4998")
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"full_name":"owner/repo",
			"owner":{"login":"owner"},
			"name":"repo",
			"default_branch":"main",
			"private":false,
			"archived":false
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	repo, err := client.GetRepository(context.Background(), "owner", "repo")
	require.NoError(t, err)
	assert.Equal(t, "owner", repo.Owner.Login)
	assert.Equal(t, "repo", repo.Name)
	assert.Equal(t, "main", repo.DefaultBranch)
}

func TestClient_ListOrgRepos(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/orgs/myorg/repos")
		w.Header().Set("X-RateLimit-Remaining", "4997")
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.WriteHeader(http.StatusOK)
		// Return empty array on page 2+ to terminate pagination
		if r.URL.Query().Get("page") == "2" {
			w.Write([]byte(`[]`))
			return
		}
		w.Write([]byte(`[
			{"full_name":"myorg/repo1","owner":{"login":"myorg"},"name":"repo1","default_branch":"main"},
			{"full_name":"myorg/repo2","owner":{"login":"myorg"},"name":"repo2","default_branch":"main"}
		]`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	repos, err := client.ListOrgRepos(context.Background(), "myorg")
	require.NoError(t, err)
	assert.Len(t, repos, 2)
}

func TestClient_ListUserRepos(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/users/testuser/repos")
		w.Header().Set("X-RateLimit-Remaining", "4996")
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.WriteHeader(http.StatusOK)
		// Return empty array on page 2+ to terminate pagination
		if r.URL.Query().Get("page") == "2" {
			w.Write([]byte(`[]`))
			return
		}
		w.Write([]byte(`[
			{"full_name":"testuser/repo1","owner":{"login":"testuser"},"name":"repo1","default_branch":"main"}
		]`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	repos, err := client.ListUserRepos(context.Background(), "testuser")
	require.NoError(t, err)
	assert.Len(t, repos, 1)
}

func TestClient_GetWorkflowFiles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/owner/repo/contents/.github/workflows", r.URL.Path)
		w.Header().Set("X-RateLimit-Remaining", "4995")
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{"name":"ci.yml","path":".github/workflows/ci.yml","sha":"abc123"},
			{"name":"deploy.yaml","path":".github/workflows/deploy.yaml","sha":"def456"},
			{"name":"README.md","path":".github/workflows/README.md","sha":"ghi789"}
		]`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	files, err := client.GetWorkflowFiles(context.Background(), "owner", "repo")
	require.NoError(t, err)
	// Should filter to only .yml/.yaml files
	assert.Len(t, files, 2)
	assert.Equal(t, "ci.yml", files[0].Name)
	assert.Equal(t, "deploy.yaml", files[1].Name)
}

func TestClient_GetWorkflowContent(t *testing.T) {
	expectedContent := "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest"
	encodedContent := base64.StdEncoding.EncodeToString([]byte(expectedContent))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/owner/repo/contents/.github/workflows/ci.yml", r.URL.Path)
		w.Header().Set("X-RateLimit-Remaining", "4994")
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"name":"ci.yml",
			"path":".github/workflows/ci.yml",
			"content":"` + encodedContent + `",
			"encoding":"base64"
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	content, err := client.GetWorkflowContent(context.Background(), "owner", "repo", ".github/workflows/ci.yml")
	require.NoError(t, err)
	assert.Equal(t, expectedContent, string(content))
}

func TestClient_RateLimiterIntegration(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("X-RateLimit-Remaining", "100")
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"login":"testuser"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.GetUser(context.Background())
	require.NoError(t, err)

	// Verify rate limiter was updated
	assert.Equal(t, 100, client.RateLimiter().Remaining())
	assert.Equal(t, 5000, client.RateLimiter().Limit())
}

func TestClient_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.GetRepository(context.Background(), "owner", "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestClient_ConcurrencyLimit(t *testing.T) {
	var currentConcurrent atomic.Int32
	var maxConcurrent atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Track concurrent requests
		current := currentConcurrent.Add(1)
		defer currentConcurrent.Add(-1)

		// Track max concurrent
		for {
			max := maxConcurrent.Load()
			if current <= max || maxConcurrent.CompareAndSwap(max, current) {
				break
			}
		}

		// Simulate some work
		time.Sleep(10 * time.Millisecond)

		w.WriteHeader(200)
		w.Write([]byte(`[]`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	// Make 150 concurrent requests
	var wg sync.WaitGroup
	for i := 0; i < 150; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = client.do(context.Background(), http.MethodGet, "/test", nil)
		}()
	}

	wg.Wait()

	// Verify max concurrent stayed under limit (90)
	max := maxConcurrent.Load()
	if max > 90 {
		t.Errorf("Max concurrent requests = %d, want <= 90", max)
	}

	t.Logf("Max concurrent requests observed: %d", max)
}

func TestClient_DoWithRetry_429(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			// First 2 attempts return 429
			w.Header().Set("Retry-After", "0") // Immediate retry for test
			w.WriteHeader(429)
			w.Write([]byte(`{"message": "rate limit exceeded"}`))
			return
		}
		// Third attempt succeeds
		w.WriteHeader(200)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	var result map[string]string
	err := client.getWithRetry(context.Background(), "/test", &result, 5)

	if err != nil {
		t.Errorf("getWithRetry() error = %v", err)
	}

	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

func TestClient_DoWithRetry_MaxRetries(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(429)
		w.Write([]byte(`{"message": "rate limit exceeded"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	var result map[string]string
	err := client.getWithRetry(context.Background(), "/test", &result, 3)

	if err == nil {
		t.Error("getWithRetry() expected error after max retries")
	}

	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

func TestClient_DoWithRetry_5xxBackoff(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(503)
			w.Write([]byte(`{"message": "service unavailable"}`))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	var result map[string]string
	err := client.getWithRetry(context.Background(), "/test", &result, 3)

	if err != nil {
		t.Errorf("getWithRetry() error = %v", err)
	}

	if attempts != 2 {
		t.Errorf("attempts = %d, want 2", attempts)
	}
}

func TestClient_String_RedactsToken(t *testing.T) {
	tests := []struct {
		name   string
		token  string
		format string
	}{
		{
			name:   "with %v format",
			token:  "ghp_secretToken123456789",
			format: "%v",
		},
		{
			name:   "with %+v format",
			token:  "ghp_secretToken123456789",
			format: "%+v",
		},
		{
			name:   "with %#v format",
			token:  "ghp_secretToken123456789",
			format: "%#v",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient("https://api.github.com", tt.token)

			output := fmt.Sprintf(tt.format, client)

			// Token should NOT appear in output
			assert.NotContains(t, output, tt.token, "token should be redacted in String() output")

			// Output should contain [REDACTED]
			assert.Contains(t, output, "[REDACTED]", "output should contain [REDACTED] for token")

			// Output should show useful debug info
			assert.Contains(t, output, "Client", "output should identify as Client")
		})
	}
}

// === Collaborator Operations Tests ===

func TestClient_InviteCollaborator(t *testing.T) {
	tests := []struct {
		name          string
		permission    CollaboratorPermission
		statusCode    int
		responseBody  string
		expectError   bool
		errorContains string
	}{
		{
			name:         "invite with admin permission (201)",
			permission:   PermissionAdmin,
			statusCode:   http.StatusCreated,
			responseBody: `{"id": 1}`,
			expectError:  false,
		},
		{
			name:         "invite with push permission (204)",
			permission:   PermissionPush,
			statusCode:   http.StatusNoContent,
			responseBody: "",
			expectError:  false,
		},
		{
			name:          "invite fails with 403",
			permission:    PermissionAdmin,
			statusCode:    http.StatusForbidden,
			responseBody:  `{"message": "Resource not accessible by integration"}`,
			expectError:   true,
			errorContains: "403",
		},
		{
			name:          "invite fails with 404",
			permission:    PermissionPull,
			statusCode:    http.StatusNotFound,
			responseBody:  `{"message": "Not Found"}`,
			expectError:   true,
			errorContains: "404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/repos/owner/repo/collaborators/testuser", r.URL.Path)
				assert.Equal(t, http.MethodPut, r.Method)
				assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

				// Verify request body
				var body map[string]string
				err := json.NewDecoder(r.Body).Decode(&body)
				require.NoError(t, err)
				assert.Equal(t, string(tt.permission), body["permission"])

				w.Header().Set("X-RateLimit-Remaining", "4999")
				w.Header().Set("X-RateLimit-Limit", "5000")
				w.WriteHeader(tt.statusCode)
				if tt.responseBody != "" {
					w.Write([]byte(tt.responseBody))
				}
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-token")
			err := client.InviteCollaborator(context.Background(), "owner", "repo", "testuser", tt.permission)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestClient_GetWorkflowContentAtRef(t *testing.T) {
	expectedContent := "name: Reusable\non: workflow_call\njobs:\n  build:\n    runs-on: self-hosted"
	encodedContent := base64.StdEncoding.EncodeToString([]byte(expectedContent))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/owner/repo/contents/.github/workflows/reusable.yml", r.URL.Path)
		assert.Equal(t, "v1.0.0", r.URL.Query().Get("ref"))
		w.Header().Set("X-RateLimit-Remaining", "4993")
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"name":"reusable.yml",
			"path":".github/workflows/reusable.yml",
			"content":"` + encodedContent + `",
			"encoding":"base64"
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	content, err := client.GetWorkflowContentAtRef(context.Background(), "owner", "repo", ".github/workflows/reusable.yml", "v1.0.0")
	require.NoError(t, err)
	assert.Equal(t, expectedContent, string(content))
}

func TestClient_RemoveCollaborator(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		responseBody  string
		expectError   bool
		errorContains string
	}{
		{
			name:        "remove collaborator success (204)",
			statusCode:  http.StatusNoContent,
			expectError: false,
		},
		{
			name:          "remove fails with 403",
			statusCode:    http.StatusForbidden,
			responseBody:  `{"message": "Must have admin rights to Repository"}`,
			expectError:   true,
			errorContains: "403",
		},
		{
			name:          "remove fails with 404",
			statusCode:    http.StatusNotFound,
			responseBody:  `{"message": "Not Found"}`,
			expectError:   true,
			errorContains: "404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/repos/owner/repo/collaborators/testuser", r.URL.Path)
				assert.Equal(t, http.MethodDelete, r.Method)
				assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

				w.Header().Set("X-RateLimit-Remaining", "4999")
				w.Header().Set("X-RateLimit-Limit", "5000")
				w.WriteHeader(tt.statusCode)
				if tt.responseBody != "" {
					w.Write([]byte(tt.responseBody))
				}
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-token")
			err := client.RemoveCollaborator(context.Background(), "owner", "repo", "testuser")

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
