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

func TestPlatform_AnalyzeProjectLogs(t *testing.T) {
	jobTrace := `Running with gitlab-runner 18.9.0 (abc) on test-runner (xyz)
Running on machine-1 via GitLab Runner
Executor: docker
`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/projects/123/pipelines":
			json.NewEncoder(w).Encode([]Pipeline{
				{ID: 1, Status: "success", Ref: "main"},
			})
		case "/api/v4/projects/123/pipelines/1/jobs":
			json.NewEncoder(w).Encode([]Job{
				{
					ID:         10,
					Name:       "test",
					Status:     "success",
					FinishedAt: "2026-02-23T10:00:00Z",
					Runner: map[string]interface{}{
						"description": "test-runner",
					},
				},
			})
		case "/api/v4/projects/123/jobs/10/trace":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(jobTrace))
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

	runners, err := p.AnalyzeProjectLogs(context.Background(), 123, 5)
	require.NoError(t, err)

	assert.Len(t, runners, 1)
	assert.Equal(t, "test-runner", runners[0].Description)
	assert.Equal(t, "18.9.0", runners[0].Version)
	assert.Equal(t, "logs", runners[0].Source)
	assert.Equal(t, "2026-02-23T10:00:00Z", runners[0].LastSeenAt)
}

func TestPlatform_AnalyzeProjectLogs_NoPipelines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v4/projects/123/pipelines" {
			json.NewEncoder(w).Encode([]Pipeline{})
		}
	}))
	defer server.Close()

	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	runners, err := p.AnalyzeProjectLogs(context.Background(), 123, 5)
	require.NoError(t, err)

	assert.Empty(t, runners)
}
