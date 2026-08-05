package azuredevops

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClient_String tests String() method for safe logging (no token exposure)
func TestClient_String(t *testing.T) {
	client := NewClient("https://dev.azure.com/test-org", "super-secret-token-12345")

	str := client.String()

	// Should contain org URL
	assert.Contains(t, str, "https://dev.azure.com/test-org")
	// Should NOT contain actual token
	assert.NotContains(t, str, "super-secret-token-12345")
	// Should indicate token is redacted
	assert.Contains(t, str, "[REDACTED]")
}

// TestClient_GoString tests GoString() method for %#v format (no token exposure)
func TestClient_GoString(t *testing.T) {
	client := NewClient("https://dev.azure.com/test-org", "super-secret-token-12345")

	str := client.GoString()

	// Should contain org URL
	assert.Contains(t, str, "https://dev.azure.com/test-org")
	// Should NOT contain actual token
	assert.NotContains(t, str, "super-secret-token-12345")
	// Should indicate token is redacted
	assert.Contains(t, str, "[REDACTED]")
}

// TestClient_NilClient tests that nil client doesn't panic when formatted
func TestClient_NilClient(t *testing.T) {
	var client *Client

	// Should not panic
	assert.NotPanics(t, func() {
		_ = client.String()
		_ = client.GoString()
	})

	assert.Contains(t, client.String(), "nil")
	assert.Contains(t, client.GoString(), "nil")
}

// TestClient_PrepareRequest_JSONAcceptHeader tests that JSON requests use application/json Accept header
func TestClient_PrepareRequest_JSONAcceptHeader(t *testing.T) {
	client := NewClient("https://dev.azure.com/test-org", "test-token")

	req, err := client.prepareRequest(t.Context(), "GET", "/test")
	require.NoError(t, err)

	assert.Equal(t, "application/json", req.Header.Get("Accept"),
		"JSON requests should use application/json Accept header")
	assert.Contains(t, req.Header.Get("Authorization"), "Basic",
		"Authorization header should use Basic auth")
}

func TestCreateBranch_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.URL.Path, "/_apis/git/repositories/")

		var updates []GitRefUpdate
		require.NoError(t, json.NewDecoder(r.Body).Decode(&updates))
		assert.Len(t, updates, 1)
		assert.Equal(t, "refs/heads/feature-branch", updates[0].Name)

		resp := GitRefList{
			Value: []GitRef{{
				Name:         "refs/heads/feature-branch",
				ObjectID:     "abc123",
				Success:      true,
				UpdateStatus: "succeeded",
			}},
			Count: 1,
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-pat",
		WithHTTPClient(server.Client()))

	err := client.CreateBranch(context.Background(), "project", "repo", "feature-branch", "abc123")
	require.NoError(t, err)
}

func TestCreateBranch_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := GitRefList{Value: []GitRef{}, Count: 0}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-pat",
		WithHTTPClient(server.Client()))

	err := client.CreateBranch(context.Background(), "project", "repo", "test-branch", "abc123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty response")
}

func TestDeleteBranch_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := GitRefList{Value: []GitRef{}, Count: 0}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-pat",
		WithHTTPClient(server.Client()))

	err := client.DeleteBranch(context.Background(), "project", "repo", "test-branch", "abc123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty response")
}

func TestCreateBranch_Rejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := GitRefList{
			Value: []GitRef{{
				Name:         "refs/heads/protected-branch",
				ObjectID:     "",
				Success:      false,
				UpdateStatus: "rejectedByPolicy",
			}},
			Count: 1,
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-pat",
		WithHTTPClient(server.Client()))

	err := client.CreateBranch(context.Background(), "project", "repo", "protected-branch", "abc123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "protected-branch")
	assert.Contains(t, err.Error(), "rejectedByPolicy")
}

func TestDeleteBranch_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)

		var updates []GitRefUpdate
		require.NoError(t, json.NewDecoder(r.Body).Decode(&updates))
		assert.Len(t, updates, 1)
		assert.Equal(t, "0000000000000000000000000000000000000000", updates[0].NewObjectID)

		resp := GitRefList{
			Value: []GitRef{{
				Name:         "refs/heads/stale-branch",
				ObjectID:     "0000000000000000000000000000000000000000",
				Success:      true,
				UpdateStatus: "succeeded",
			}},
			Count: 1,
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-pat",
		WithHTTPClient(server.Client()))

	err := client.DeleteBranch(context.Background(), "project", "repo", "stale-branch", "abc123")
	require.NoError(t, err)
}

func TestDeleteBranch_Rejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := GitRefList{
			Value: []GitRef{{
				Name:         "refs/heads/main",
				ObjectID:     "abc123",
				Success:      false,
				UpdateStatus: "rejectedByPolicy",
			}},
			Count: 1,
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-pat",
		WithHTTPClient(server.Client()))

	err := client.DeleteBranch(context.Background(), "project", "repo", "main", "abc123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "main")
	assert.Contains(t, err.Error(), "rejectedByPolicy")
}
