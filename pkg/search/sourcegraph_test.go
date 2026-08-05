package search

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSourceGraphSearchProvider_SSE_Stream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.URL.Path, "/search/stream")
		assert.Contains(t, r.URL.Query().Get("q"), "self-hosted")

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		w.Write([]byte("data: [{\"repository\": \"github.com/owner/repo1\"}]\n\n"))
		w.Write([]byte("data: [{\"repository\": \"github.com/owner/repo2\"}]\n\n"))
		w.Write([]byte("data: []\n\n"))
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

func TestSourceGraphSearchProvider_Error_Response(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

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

func TestSourceGraphSearchProvider_Context_Cancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	provider := NewSourceGraphSearchProvider("")
	provider.baseURL = server.URL

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := provider.Search(ctx, "test")
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestSourceGraphSearchProvider_Ignores_Non_Data_Lines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

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

func TestSourceGraphSearchProvider_Empty_Data_Lines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

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

func TestSourceGraphSearchProvider_Malformed_JSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		w.Write([]byte("data: {invalid json}\n\n"))
		w.Write([]byte("data: [{\"repository\": \"github.com/owner/repo1\"}]\n\n"))
	}))
	defer server.Close()

	provider := NewSourceGraphSearchProvider("")
	provider.baseURL = server.URL

	result, err := provider.Search(context.Background(), "self-hosted")
	require.NoError(t, err)
	assert.Len(t, result.Repositories, 1) // the malformed line is skipped, the valid one kept
}
