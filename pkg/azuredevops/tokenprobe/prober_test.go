package tokenprobe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/azuredevops"
)

func TestTokenProber_Probe_ValidPAT(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case strings.HasSuffix(path, "/_apis/connectionData"):
			resp := azuredevops.ConnectionData{}
			resp.AuthenticatedUser.ID = "user-123"
			resp.AuthenticatedUser.ProviderDisplayName = "Test User"
			json.NewEncoder(w).Encode(resp)

		case strings.HasSuffix(path, "/_apis/projects"):
			resp := azuredevops.ProjectList{
				Value: []azuredevops.Project{
					{ID: "proj-1", Name: "Project1", Visibility: "private"},
				},
				Count: 1,
			}
			json.NewEncoder(w).Encode(resp)

		case strings.Contains(path, "/_apis/git/repositories"):
			resp := azuredevops.RepositoryList{
				Value: []azuredevops.Repository{
					{ID: "repo-1", Name: "Repo1"},
				},
				Count: 1,
			}
			json.NewEncoder(w).Encode(resp)

		case strings.Contains(path, "/_apis/pipelines"):
			resp := azuredevops.PipelineList{
				Value: []azuredevops.Pipeline{
					{ID: 1, Name: "CI"},
				},
				Count: 1,
			}
			json.NewEncoder(w).Encode(resp)

		case strings.HasSuffix(path, "/_apis/distributedtask/pools"):
			resp := azuredevops.AgentPoolList{
				Value: []azuredevops.AgentPool{
					{ID: 1, Name: "Azure Pipelines", IsHosted: true},
					{ID: 2, Name: "Self-hosted", IsHosted: false},
				},
				Count: 2,
			}
			json.NewEncoder(w).Encode(resp)

		case strings.Contains(path, "/_apis/distributedtask/variablegroups"):
			resp := azuredevops.VariableGroupList{
				Value: []azuredevops.VariableGroup{
					{
						ID:   1,
						Name: "Secrets",
						Variables: map[string]azuredevops.VariableValue{
							"API_KEY": {IsSecret: true},
						},
					},
				},
				Count: 1,
			}
			json.NewEncoder(w).Encode(resp)

		case strings.Contains(path, "/_apis/serviceendpoint/endpoints"):
			resp := azuredevops.ServiceConnectionList{
				Value: []azuredevops.ServiceConnection{
					{ID: "conn-1", Name: "Azure"},
				},
				Count: 1,
			}
			json.NewEncoder(w).Encode(resp)

		case strings.HasSuffix(path, "/_apis/packaging/feeds"):
			resp := azuredevops.ArtifactFeedList{
				Value: []azuredevops.ArtifactFeed{
					{ID: "feed-1", Name: "Artifacts"},
				},
				Count: 1,
			}
			json.NewEncoder(w).Encode(resp)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := azuredevops.NewClient(server.URL, "test-pat")
	prober := NewProber(client)

	result, err := prober.Probe(context.Background())

	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.NotNil(t, result.User)
	assert.Equal(t, "Test User", result.User.DisplayName)

	assert.True(t, result.HasCapability(CapabilityIdentityRead))
	assert.True(t, result.HasCapability(CapabilityProjectsRead))
	assert.True(t, result.HasCapability(CapabilityRepositoriesRead))
	assert.True(t, result.HasCapability(CapabilityPipelinesRead))
	assert.True(t, result.HasCapability(CapabilityAgentPoolsRead))
	assert.True(t, result.HasCapability(CapabilityVariableGroupsRead))
	assert.True(t, result.HasCapability(CapabilityServiceConnectionsRead))
	assert.True(t, result.HasCapability(CapabilityArtifactsRead))

	assert.True(t, result.HasHighValueAccess())
	assert.True(t, result.HasSecretVariables)
	assert.True(t, result.HasSelfHostedAgents)

	assert.Equal(t, 1, result.ProjectCount)
	assert.Equal(t, 1, result.RepositoryCount)
	assert.Equal(t, 1, result.PipelineCount)
	assert.Equal(t, 2, result.AgentPoolCount)
	assert.Equal(t, 1, result.VariableGroupCount)
	assert.Equal(t, 1, result.ServiceConnectionCount)
	assert.Equal(t, 1, result.ArtifactFeedCount)
}

func TestTokenProber_Probe_InvalidPAT(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message": "Invalid PAT"}`))
	}))
	defer server.Close()

	client := azuredevops.NewClient(server.URL, "invalid-pat")
	prober := NewProber(client)

	result, err := prober.Probe(context.Background())

	require.NoError(t, err) // an invalid PAT is not an error, just an invalid result
	assert.False(t, result.Valid)
	assert.Nil(t, result.User)
	assert.Empty(t, result.Capabilities)
}

func TestTokenProber_Probe_LimitedAccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case strings.HasSuffix(path, "/_apis/connectionData"):
			resp := azuredevops.ConnectionData{}
			resp.AuthenticatedUser.ID = "user-123"
			resp.AuthenticatedUser.ProviderDisplayName = "Limited User"
			json.NewEncoder(w).Encode(resp)

		case strings.HasSuffix(path, "/_apis/projects"):
			resp := azuredevops.ProjectList{
				Value: []azuredevops.Project{
					{ID: "proj-1", Name: "Project1"},
				},
				Count: 1,
			}
			json.NewEncoder(w).Encode(resp)

		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer server.Close()

	client := azuredevops.NewClient(server.URL, "limited-pat")
	prober := NewProber(client)

	result, err := prober.Probe(context.Background())

	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.True(t, result.HasCapability(CapabilityIdentityRead))
	assert.True(t, result.HasCapability(CapabilityProjectsRead))
	assert.False(t, result.HasCapability(CapabilityPipelinesRead))
	assert.False(t, result.HasCapability(CapabilityAgentPoolsRead))
	assert.False(t, result.HasHighValueAccess())
}

func TestTokenProber_Probe_MultipleProjects(t *testing.T) {
	queriedProjects := make(map[string]bool)
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case strings.HasSuffix(path, "/_apis/connectionData"):
			resp := azuredevops.ConnectionData{}
			resp.AuthenticatedUser.ID = "user-123"
			resp.AuthenticatedUser.ProviderDisplayName = "Test User"
			json.NewEncoder(w).Encode(resp)

		case strings.HasSuffix(path, "/_apis/projects"):
			resp := azuredevops.ProjectList{
				Value: []azuredevops.Project{
					{ID: "proj-imladris", Name: "Imladris", Visibility: "private"},
					{ID: "proj-gondor", Name: "Gondor", Visibility: "private"},
					{ID: "proj-lothlorien", Name: "Lothlorien", Visibility: "private"},
					{ID: "proj-erebor", Name: "Erebor", Visibility: "private"},
					{ID: "proj-rohan", Name: "Rohan", Visibility: "private"},
					{ID: "proj-mordor", Name: "Mordor", Visibility: "private"},
					{ID: "proj-shire", Name: "Shire", Visibility: "private"},
					{ID: "proj-isengard", Name: "Isengard", Visibility: "private"},
				},
				Count: 8,
			}
			json.NewEncoder(w).Encode(resp)

		case strings.Contains(path, "/_apis/git/repositories"):
			projectName := ""
			if strings.Contains(path, "/Imladris/") {
				projectName = "Imladris"
			} else if strings.Contains(path, "/Erebor/") {
				projectName = "Erebor"
			} else if strings.Contains(path, "/Lothlorien/") {
				projectName = "Lothlorien"
			}

			if projectName != "" {
				mu.Lock()
				queriedProjects[projectName] = true
				mu.Unlock()
			}

			var repos []azuredevops.Repository
			switch projectName {
			case "Imladris":
				repos = []azuredevops.Repository{
					{ID: "repo-elrond", Name: "elrond_repo"},
				}
			case "Erebor":
				repos = []azuredevops.Repository{
					{ID: "repo-thorin", Name: "thorin_repo"},
				}
			case "Lothlorien":
				repos = []azuredevops.Repository{
					{ID: "repo-celeborn", Name: "celeborn_repo"},
				}
			default:
				repos = []azuredevops.Repository{}
			}

			resp := azuredevops.RepositoryList{
				Value: repos,
				Count: len(repos),
			}
			json.NewEncoder(w).Encode(resp)

		case strings.Contains(path, "/_apis/pipelines"):
			// Path format: /org/PROJECT/_apis/pipelines
			pathParts := strings.Split(path, "/")
			projectName := ""
			for i, part := range pathParts {
				if part == "_apis" && i > 0 {
					projectName = pathParts[i-1]
					break
				}
			}

			var pipelines []azuredevops.Pipeline
			if projectName != "" {
				pipelines = []azuredevops.Pipeline{
					{ID: 1, Name: projectName + "-CI"},
				}
			}

			resp := azuredevops.PipelineList{
				Value: pipelines,
				Count: len(pipelines),
			}
			json.NewEncoder(w).Encode(resp)

		case strings.Contains(path, "/_apis/distributedtask/variablegroups"):
			resp := azuredevops.VariableGroupList{
				Value: []azuredevops.VariableGroup{
					{ID: 1, Name: "Vars"},
				},
				Count: 1,
			}
			json.NewEncoder(w).Encode(resp)

		case strings.Contains(path, "/_apis/serviceendpoint/endpoints"):
			resp := azuredevops.ServiceConnectionList{
				Value: []azuredevops.ServiceConnection{
					{ID: "conn-1", Name: "Azure"},
				},
				Count: 1,
			}
			json.NewEncoder(w).Encode(resp)

		case strings.HasSuffix(path, "/_apis/distributedtask/pools"):
			resp := azuredevops.AgentPoolList{
				Value: []azuredevops.AgentPool{
					{ID: 1, Name: "Azure Pipelines", IsHosted: true},
				},
				Count: 1,
			}
			json.NewEncoder(w).Encode(resp)

		case strings.HasSuffix(path, "/_apis/packaging/feeds"):
			resp := azuredevops.ArtifactFeedList{
				Value: []azuredevops.ArtifactFeed{
					{ID: "feed-1", Name: "Artifacts"},
				},
				Count: 1,
			}
			json.NewEncoder(w).Encode(resp)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := azuredevops.NewClient(server.URL, "test-pat")
	prober := NewProber(client)

	result, err := prober.Probe(context.Background())

	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, 8, result.ProjectCount)

	mu.Lock()
	assert.True(t, queriedProjects["Imladris"], "Imladris should be queried for repos")
	assert.True(t, queriedProjects["Erebor"], "Erebor should be queried for repos")
	assert.True(t, queriedProjects["Lothlorien"], "Lothlorien should be queried for repos")
	mu.Unlock()

	assert.Equal(t, 3, result.RepositoryCount, "Should enumerate repos from ALL projects")

	// One of each per project, across 8 projects.
	assert.Equal(t, 8, result.PipelineCount, "Should enumerate pipelines from ALL projects")
	assert.Equal(t, 8, result.VariableGroupCount, "Should enumerate variable groups from ALL projects")
	assert.Equal(t, 8, result.ServiceConnectionCount, "Should enumerate service connections from ALL projects")
}
