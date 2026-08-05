package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestClient_ListProtectedBranches_EmptyList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]BranchProtection{})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	protections, err := client.ListProtectedBranches(context.Background(), 123)

	require.NoError(t, err)
	assert.Empty(t, protections)
}

func TestPlatform_EnumerateBranchProtections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/projects/company/api":
			json.NewEncoder(w).Encode(Project{
				ID:                1,
				Name:              "api",
				PathWithNamespace: "company/api",
				DefaultBranch:     "main",
				Namespace:         Namespace{FullPath: "company"},
			})

		case "/api/v4/projects/1/protected_branches":
			json.NewEncoder(w).Encode([]BranchProtection{
				{
					Name:                      "main",
					AllowForcePush:            false,
					CodeOwnerApprovalRequired: true,
					MergeAccessLevels: []AccessLevel{
						{AccessLevel: 40, AccessLevelDescription: "Maintainers"},
					},
					PushAccessLevels: []AccessLevel{
						{AccessLevel: 40, AccessLevelDescription: "Maintainers"},
					},
					UnprotectAccessLevels: []AccessLevel{
						{AccessLevel: 40, AccessLevelDescription: "Maintainers"},
					},
				},
				{
					Name:           "release/*",
					AllowForcePush: false,
					MergeAccessLevels: []AccessLevel{
						{AccessLevel: 40, AccessLevelDescription: "Maintainers"},
					},
					PushAccessLevels: []AccessLevel{
						{AccessLevel: 0, AccessLevelDescription: "No one"},
					},
					UnprotectAccessLevels: []AccessLevel{
						{AccessLevel: 40, AccessLevelDescription: "Maintainers"},
					},
				},
			})

		default:
			t.Logf("Unexpected path: %s", r.URL.Path)
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

	result, err := p.EnumerateBranchProtections(context.Background(), platforms.Target{
		Type:  platforms.TargetRepo,
		Value: "company/api",
	})
	require.NoError(t, err)

	assert.Equal(t, "company/api", result.Project)
	assert.Equal(t, 1, result.ProjectID)
	assert.Equal(t, "main", result.DefaultBranch)

	assert.Len(t, result.Protections, 2)
	assert.Equal(t, "main", result.Protections[0].Name)
	assert.True(t, result.Protections[0].CodeOwnerApprovalRequired)
	assert.Equal(t, "release/*", result.Protections[1].Name)
	assert.Equal(t, 0, result.Protections[1].PushAccessLevels[0].AccessLevel)

	assert.Empty(t, result.Errors)
}

func TestPlatform_EnumerateBranchProtections_NoProject(t *testing.T) {
	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: "http://unused",
	})
	require.NoError(t, err)

	result, err := p.EnumerateBranchProtections(context.Background(), platforms.Target{
		Type: platforms.TargetOrg, // Wrong type
	})
	require.NoError(t, err)

	assert.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors[0], "must specify --project")
}

func TestPlatform_EnumerateBranchProtections_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/projects/company/api":
			json.NewEncoder(w).Encode(Project{
				ID:                1,
				Name:              "api",
				PathWithNamespace: "company/api",
				DefaultBranch:     "main",
			})

		case "/api/v4/projects/1/protected_branches":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"message":"403 Forbidden"}`))

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

	result, err := p.EnumerateBranchProtections(context.Background(), platforms.Target{
		Type:  platforms.TargetRepo,
		Value: "company/api",
	})
	require.NoError(t, err)

	assert.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors[0], "listing protected branches")
	assert.Contains(t, result.Errors[0], "403")
	assert.Empty(t, result.Protections)
}

func TestPlatform_EnumerateBranchProtections_ProjectNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"404 Not Found"}`))
	}))
	defer server.Close()

	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	result, err := p.EnumerateBranchProtections(context.Background(), platforms.Target{
		Type:  platforms.TargetRepo,
		Value: "nonexistent/project",
	})
	require.NoError(t, err)

	assert.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors[0], "getting project")
}
