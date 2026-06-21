// pkg/search/sourcegraph_test.go
package search

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test SourceGraphSearchProvider implements SearchProvider interface
func TestSourceGraphSearchProvider_Interface(t *testing.T) {
	provider := NewSourceGraphSearchProvider("")

	assert.Equal(t, "sourcegraph", provider.Name())
	assert.NotNil(t, provider)
}

// Test SourceGraph search with SSE stream
func TestSourceGraphSearchProvider_SSE_Stream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.URL.Path, "/search/stream")
		assert.Contains(t, r.URL.Query().Get("q"), "self-hosted")

		// Return SSE stream
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		// Write SSE events
		w.Write([]byte("data: [{\"repository\": \"github.com/owner/repo1\"}]\n\n"))
		w.Write([]byte("data: [{\"repository\": \"github.com/owner/repo2\"}]\n\n"))
		w.Write([]byte("data: []\n\n")) // Empty array
	}))
	defer server.Close()

	provider := NewSourceGraphSearchProvider("")
	provider.baseURL = server.URL

	result, err := provider.Search(context.Background(), "self-hosted")
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Repositories, 2)
	assert.Equal(t, 2, result.TotalCount)
	assert.Contains(t, result.Repositories, "owner/repo1") // github.com/ prefix removed
	assert.Contains(t, result.Repositories, "owner/repo2")
}

// Test SourceGraph search with error response
func TestSourceGraphSearchProvider_Error_Response(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		// Write error event
		w.Write([]byte("data: {\"title\": \"Unable To Process Query\", \"description\": \"Query too complex\"}\n\n"))
	}))
	defer server.Close()

	provider := NewSourceGraphSearchProvider("")
	provider.baseURL = server.URL

	result, err := provider.Search(context.Background(), "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SourceGraph query error")
	assert.Contains(t, err.Error(), "Query too complex")
	assert.Nil(t, result)
}

// Test SourceGraph search with HTTP error
func TestSourceGraphSearchProvider_HTTP_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	provider := NewSourceGraphSearchProvider("")
	provider.baseURL = server.URL

	result, err := provider.Search(context.Background(), "test")
	assert.Error(t, err)
	assert.Nil(t, result)
}

// Test SourceGraph search with deduplication
func TestSourceGraphSearchProvider_Deduplication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		// Write duplicate repositories
		w.Write([]byte("data: [{\"repository\": \"github.com/owner/repo1\"}]\n\n"))
		w.Write([]byte("data: [{\"repository\": \"github.com/owner/repo1\"}]\n\n")) // Duplicate
		w.Write([]byte("data: [{\"repository\": \"github.com/owner/repo2\"}]\n\n"))
	}))
	defer server.Close()

	provider := NewSourceGraphSearchProvider("")
	provider.baseURL = server.URL

	result, err := provider.Search(context.Background(), "self-hosted")
	require.NoError(t, err)
	assert.Len(t, result.Repositories, 2) // Should deduplicate
}

// Test SourceGraph search with context cancellation
func TestSourceGraphSearchProvider_Context_Cancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // Block until context is canceled
	}))
	defer server.Close()

	provider := NewSourceGraphSearchProvider("")
	provider.baseURL = server.URL

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := provider.Search(ctx, "test")
	assert.Error(t, err)
	assert.Nil(t, result)
}

// Test SourceGraph search ignores non-data lines
func TestSourceGraphSearchProvider_Ignores_Non_Data_Lines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		// Write SSE with various line types
		w.Write([]byte("event: progress\n"))
		w.Write([]byte("id: 123\n"))
		w.Write([]byte(": comment line\n"))
		w.Write([]byte("data: [{\"repository\": \"github.com/owner/repo1\"}]\n\n"))
	}))
	defer server.Close()

	provider := NewSourceGraphSearchProvider("")
	provider.baseURL = server.URL

	result, err := provider.Search(context.Background(), "self-hosted")
	require.NoError(t, err)
	assert.Len(t, result.Repositories, 1)
}

// Test SourceGraph search handles empty data lines
func TestSourceGraphSearchProvider_Empty_Data_Lines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		// Write SSE with empty data
		w.Write([]byte("data:\n\n"))
		w.Write([]byte("data:   \n\n"))
		w.Write([]byte("data: [{\"repository\": \"github.com/owner/repo1\"}]\n\n"))
	}))
	defer server.Close()

	provider := NewSourceGraphSearchProvider("")
	provider.baseURL = server.URL

	result, err := provider.Search(context.Background(), "self-hosted")
	require.NoError(t, err)
	assert.Len(t, result.Repositories, 1)
}

// Test SourceGraph search handles malformed JSON
func TestSourceGraphSearchProvider_Malformed_JSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		// Write SSE with malformed JSON (should skip)
		w.Write([]byte("data: {invalid json}\n\n"))
		w.Write([]byte("data: [{\"repository\": \"github.com/owner/repo1\"}]\n\n"))
	}))
	defer server.Close()

	provider := NewSourceGraphSearchProvider("")
	provider.baseURL = server.URL

	result, err := provider.Search(context.Background(), "self-hosted")
	require.NoError(t, err)
	assert.Len(t, result.Repositories, 1) // Should skip malformed JSON
}

// Test DefaultSourceGraphQuery with organization
func TestDefaultSourceGraphQuery_WithOrg(t *testing.T) {
	query := DefaultSourceGraphQuery("myorg")

	assert.Contains(t, query, "self-hosted")
	assert.Contains(t, query, "repo:myorg/")
	assert.Contains(t, query, "lang:YAML")
	assert.Contains(t, query, "file:.github/workflows/")
	assert.Contains(t, query, "context:global")

	// Should exclude GitHub-hosted labels
	assert.Contains(t, query, "ubuntu-")
	assert.Contains(t, query, "windows-")
	assert.Contains(t, query, "macos-")
}

// Test DefaultSourceGraphQuery without organization
func TestDefaultSourceGraphQuery_WithoutOrg(t *testing.T) {
	query := DefaultSourceGraphQuery("")

	assert.Contains(t, query, "self-hosted")
	assert.NotContains(t, query, "repo:")
	assert.Contains(t, query, "lang:YAML")
	assert.Contains(t, query, "file:.github/workflows/")
}

// Test NewSourceGraphSearchProvider with default baseURL
func TestNewSourceGraphSearchProvider_DefaultBaseURL(t *testing.T) {
	provider := NewSourceGraphSearchProvider("")

	assert.NotEmpty(t, provider.baseURL)
	assert.Contains(t, provider.baseURL, "sourcegraph.com")
}

// Test NewSourceGraphSearchProvider with proxy
func TestNewSourceGraphSearchProvider_WithProxy(t *testing.T) {
	provider := NewSourceGraphSearchProvider("http://proxy:8080")

	assert.NotNil(t, provider)
	assert.NotNil(t, provider.httpClient)
}
