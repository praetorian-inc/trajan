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

func TestGitHubSearchProvider_SinglePage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.URL.Path, "/search/code")
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		assert.Contains(t, r.URL.Query().Get("q"), "self-hosted")

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

func TestGitHubSearchProvider_Pagination(t *testing.T) {
	page := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++

		if page == 1 {
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
			// Last page: no Link header is what stops pagination.
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
	assert.Equal(t, 2, page)
}

func TestGitHubSearchProvider_Deduplication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	assert.Len(t, result.Repositories, 2) // deduplicated
	assert.Equal(t, 3, result.TotalCount) // TotalCount stays the raw match count
}

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
	assert.NotNil(t, result) // partial result survives the error
}

func TestGitHubSearchProvider_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	assert.NotNil(t, result) // partial result survives the cancellation
}
