//go:build integration
// +build integration

package secretsdump

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/gitlab"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestExecuteIntegration(t *testing.T) {
	// Mock GitLab API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v4/projects/namespace%2Fproject":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":                  123,
				"path_with_namespace": "namespace/project",
				"default_branch":      "main",
				"jobs_enabled":        true,
				"archived":            false,
			})
		case r.URL.Path == "/api/v4/projects/123/members/all":
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":           456,
					"username":     "testuser",
					"access_level": 30,
				},
			})
		case r.URL.Path == "/api/v4/projects/123/repository/branches/main":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"name": "main",
				"commit": map[string]interface{}{
					"id": "abc123",
				},
			})
		default:
			t.Logf("Unhandled request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	}))
	defer server.Close()

	// Create client pointing to mock server
	client := gitlab.NewClient(server.URL, "test-token")

	// Create platform manually since we can't use registry in tests
	platform := &gitlab.Platform{}
	// Set client via reflection or create platform differently

	// Execute plugin in dry-run mode
	plugin := New()
	opts := attacks.AttackOptions{
		Platform:  platform,
		Target:    platforms.Target{Type: "repo", Value: "namespace/project"},
		SessionID: "test-session",
		DryRun:    true,
	}

	result, err := plugin.Execute(context.Background(), opts)

	// Should succeed in dry-run
	assert.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "DRY RUN")
}
