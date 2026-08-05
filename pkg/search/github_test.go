// pkg/search/github_test.go
package search

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test GitHub search with single page of results
func TestGitHubSearchProvider_SinglePage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.URL.Path, "/search/code")
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		assert.Contains(t, r.URL.Query().Get("q"), "self-hosted")

		// Return mock response
		response := map[string]interface{}{
			"total_count":        2,
			"incomplete_results": false,
			"items": []map[string]interface{}{
				{
					"repository": map[string]string{
						"full_name": "owner/repo1",
					},
				},
				{
					"repository": map[string]string{
						"full_name": "owner/repo2",
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := &http.Client{}
	provider := NewGitHubSearchProvider(client, "test-token")
	provider.baseURL = server.URL

	result, err := provider.Search(context.Background(), "self-hosted")
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Repositories, 2)
	assert.Equal(t, 2, result.TotalCount)
	assert.False(t, result.Incomplete)
	assert.Contains(t, result.Repositories, "owner/repo1")
	assert.Contains(t, result.Repositories, "owner/repo2")
}

// Test GitHub search with pagination
func TestGitHubSearchProvider_Pagination(t *testing.T) {
	page := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++

		if page == 1 {
			// First page with Link header
			response := map[string]interface{}{
				"total_count":        2,
				"incomplete_results": false,
				"items": []map[string]interface{}{
					{
						"repository": map[string]string{
							"full_name": "owner/repo1",
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Link", `<`+r.URL.String()+`?page=2>; rel="next"`)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
		} else {
			// Second page without Link header (last page)
			response := map[string]interface{}{
				"total_count":        2,
				"incomplete_results": false,
				"items": []map[string]interface{}{
					{
						"repository": map[string]string{
							"full_name": "owner/repo2",
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
		}
	}))
	defer server.Close()

	client := &http.Client{}
	provider := NewGitHubSearchProvider(client, "test-token")
	provider.baseURL = server.URL

	result, err := provider.Search(context.Background(), "self-hosted")
	require.NoError(t, err)
	assert.Len(t, result.Repositories, 2)
	assert.Equal(t, 2, page) // Verify two requests were made
}

// Test GitHub search with deduplication
func TestGitHubSearchProvider_Deduplication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return duplicate repositories
		response := map[string]interface{}{
			"total_count":        3,
			"incomplete_results": false,
			"items": []map[string]interface{}{
				{
					"repository": map[string]string{
						"full_name": "owner/repo1",
					},
				},
				{
					"repository": map[string]string{
						"full_name": "owner/repo1", // Duplicate
					},
				},
				{
					"repository": map[string]string{
						"full_name": "owner/repo2",
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := &http.Client{}
	provider := NewGitHubSearchProvider(client, "test-token")
	provider.baseURL = server.URL

	result, err := provider.Search(context.Background(), "self-hosted")
	require.NoError(t, err)
	assert.Len(t, result.Repositories, 2) // Should deduplicate
	assert.Equal(t, 3, result.TotalCount) // But preserve total count
}

// Test GitHub search with API error
func TestGitHubSearchProvider_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	client := &http.Client{}
	provider := NewGitHubSearchProvider(client, "test-token")
	provider.baseURL = server.URL

	result, err := provider.Search(context.Background(), "self-hosted")
	assert.Error(t, err)
	assert.NotNil(t, result) // Should still return partial result
}

// Test GitHub search with context cancellation
func TestGitHubSearchProvider_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(2 * time.Second)
	}))
	defer server.Close()

	client := &http.Client{}
	provider := NewGitHubSearchProvider(client, "test-token")
	provider.baseURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	result, err := provider.Search(ctx, "self-hosted")
	assert.Error(t, err)
	assert.NotNil(t, result) // Should return partial result
}
