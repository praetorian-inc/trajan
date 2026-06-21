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

func TestClient_ListProjectRunners(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("RateLimit-Limit", "2000")
		w.Header().Set("RateLimit-Remaining", "1800")

		if r.URL.Path == "/api/v4/projects/123/runners" {
			json.NewEncoder(w).Encode([]RunnerInfo{
				{
					ID:          1,
					Description: "Project Runner 1",
					RunnerType:  "project_type",
					Tags:        []string{"docker", "linux"},
					Online:      true,
					Status:      "online",
					Active:      true,
					Paused:      false,
					IsShared:    false,
				},
				{
					ID:          2,
					Description: "Project Runner 2",
					RunnerType:  "project_type",
					Tags:        []string{"kubernetes", "prod"},
					Online:      false,
					Status:      "offline",
					Active:      true,
					Paused:      false,
					IsShared:    false,
				},
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	runners, err := client.ListProjectRunners(context.Background(), 123)
	require.NoError(t, err)

	assert.Len(t, runners, 2)
	assert.Equal(t, "Project Runner 1", runners[0].Description)
	assert.Equal(t, []string{"docker", "linux"}, runners[0].Tags)
	assert.True(t, runners[0].Online)
	assert.Equal(t, "project_type", runners[0].RunnerType)
}

func TestClient_ListGroupRunners(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("RateLimit-Limit", "2000")
		w.Header().Set("RateLimit-Remaining", "1800")

		if r.URL.Path == "/api/v4/groups/456/runners" {
			json.NewEncoder(w).Encode([]RunnerInfo{
				{
					ID:          10,
					Description: "Group Runner",
					RunnerType:  "group_type",
					Tags:        []string{"shared", "staging"},
					Online:      true,
					Status:      "online",
					Active:      true,
					Paused:      false,
					IsShared:    false,
				},
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	runners, err := client.ListGroupRunners(context.Background(), 456)
	require.NoError(t, err)

	assert.Len(t, runners, 1)
	assert.Equal(t, "Group Runner", runners[0].Description)
	assert.Equal(t, "group_type", runners[0].RunnerType)
	assert.Equal(t, []string{"shared", "staging"}, runners[0].Tags)
}

func TestClient_ListInstanceRunners(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("RateLimit-Limit", "2000")
		w.Header().Set("RateLimit-Remaining", "1800")

		if r.URL.Path == "/api/v4/runners/all" {
			json.NewEncoder(w).Encode([]RunnerInfo{
				{
					ID:          100,
					Description: "Instance Runner",
					RunnerType:  "instance_type",
					Tags:        []string{"instance", "shared"},
					Online:      true,
					Status:      "online",
					Active:      true,
					Paused:      false,
					IsShared:    true,
				},
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	runners, err := client.ListInstanceRunners(context.Background())
	require.NoError(t, err)

	assert.Len(t, runners, 1)
	assert.Equal(t, "Instance Runner", runners[0].Description)
	assert.Equal(t, "instance_type", runners[0].RunnerType)
	assert.True(t, runners[0].IsShared)
}

func TestClient_ListInstanceRunners_AdminRequired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "403 Forbidden",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	runners, err := client.ListInstanceRunners(context.Background())

	// Should return error for 403
	assert.Error(t, err)
	assert.Nil(t, runners)
	assert.Contains(t, err.Error(), "403")
}

func TestPlatform_EnumerateRunners_ProjectRunners(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("RateLimit-Limit", "2000")
		w.Header().Set("RateLimit-Remaining", "1800")

		switch r.URL.Path {
		case "/api/v4/projects/my-org/my-repo":
			json.NewEncoder(w).Encode(Project{
				ID:                123,
				Name:              "my-repo",
				PathWithNamespace: "my-org/my-repo",
				Namespace: Namespace{
					Name:     "my-org",
					FullPath: "my-org",
				},
			})
		case "/api/v4/groups/my-org":
			json.NewEncoder(w).Encode(Group{
				ID:       10,
				Name:     "my-org",
				FullPath: "my-org",
			})
		case "/api/v4/projects/123/runners":
			// Handle pagination
			json.NewEncoder(w).Encode([]RunnerInfo{
				{
					ID:          1,
					Description: "Project Runner",
					RunnerType:  "project_type",
					Tags:        []string{"docker", "linux"},
					Online:      true,
					Status:      "online",
					Active:      true,
				},
			})
		case "/api/v4/groups/10/runners":
			// Handle pagination
			json.NewEncoder(w).Encode([]RunnerInfo{
				{
					ID:          2,
					Description: "Group Runner",
					RunnerType:  "group_type",
					Tags:        []string{"shared"},
					Online:      true,
					Status:      "online",
					Active:      true,
				},
			})
		case "/api/v4/runners/all":
			// Simulate admin access
			json.NewEncoder(w).Encode([]RunnerInfo{
				{
					ID:          100,
					Description: "Instance Runner",
					RunnerType:  "instance_type",
					Tags:        []string{"instance"},
					Online:      true,
					IsShared:    true,
				},
			})
		default:
			t.Logf("Unhandled path: %s", r.URL.Path)
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

	result, err := p.EnumerateRunners(context.Background(), "my-org/my-repo", true, true)
	require.NoError(t, err)

	// Should have all three types of runners
	assert.Len(t, result.ProjectRunners, 1)
	assert.Len(t, result.GroupRunners, 1)
	assert.Len(t, result.InstanceRunners, 1)

	// Verify summary
	assert.Equal(t, 3, result.Summary.Total)
	assert.Equal(t, 3, result.Summary.Online)
	assert.Equal(t, 1, result.Summary.Project)
	assert.Equal(t, 1, result.Summary.Group)
	assert.Equal(t, 1, result.Summary.Instance)

	assert.Empty(t, result.Errors)
}

func TestPlatform_EnumerateRunners_AdminRequired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("RateLimit-Limit", "2000")
		w.Header().Set("RateLimit-Remaining", "1800")

		switch r.URL.Path {
		case "/api/v4/projects/my-org/my-repo":
			json.NewEncoder(w).Encode(Project{
				ID:                123,
				Name:              "my-repo",
				PathWithNamespace: "my-org/my-repo",
			})
		case "/api/v4/projects/123/runners":
			json.NewEncoder(w).Encode([]RunnerInfo{})
		case "/api/v4/runners/all":
			// Non-admin returns 403
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"message": "403 Forbidden - Admin access required",
			})
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

	result, err := p.EnumerateRunners(context.Background(), "my-org/my-repo", false, true)
	require.NoError(t, err)

	// Should not have instance runners
	assert.Empty(t, result.InstanceRunners)

	// Should have permission error message
	assert.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], "403")
	assert.Contains(t, result.Errors[0], "admin")
}

func TestAnalyzeWorkflowTags(t *testing.T) {
	tests := []struct {
		name             string
		yamlContent      string
		availableRunners []RunnerInfo
		expectedRequired []string
		expectedMissing  []string
	}{
		{
			name: "single job with tags",
			yamlContent: `
stages:
  - test

test-job:
  stage: test
  tags:
    - docker
    - linux
  script:
    - echo "test"
`,
			availableRunners: []RunnerInfo{
				{Tags: []string{"docker", "linux"}},
			},
			expectedRequired: []string{"docker", "linux"},
			expectedMissing:  []string{},
		},
		{
			name: "multiple jobs with different tags",
			yamlContent: `
stages:
  - build
  - test

build:
  stage: build
  tags:
    - docker
  script:
    - make build

test:
  stage: test
  tags:
    - kubernetes
    - prod
  script:
    - make test
`,
			availableRunners: []RunnerInfo{
				{Tags: []string{"docker"}},
			},
			expectedRequired: []string{"docker", "kubernetes", "prod"},
			expectedMissing:  []string{"kubernetes", "prod"},
		},
		{
			name: "job without tags",
			yamlContent: `
stages:
  - test

test-job:
  stage: test
  script:
    - echo "test"
`,
			availableRunners: []RunnerInfo{
				{Tags: []string{"docker"}},
			},
			expectedRequired: []string{},
			expectedMissing:  []string{},
		},
		{
			name: "all tags available",
			yamlContent: `
deploy:
  tags:
    - production
    - deploy
  script:
    - deploy.sh
`,
			availableRunners: []RunnerInfo{
				{Tags: []string{"production", "deploy", "extra"}},
			},
			expectedRequired: []string{"production", "deploy"},
			expectedMissing:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPlatform()
			analysis, err := p.AnalyzeWorkflowTags(context.Background(), []byte(tt.yamlContent), tt.availableRunners)
			require.NoError(t, err)

			// Sort for consistent comparison
			assert.ElementsMatch(t, tt.expectedRequired, analysis.RequiredTags)
			assert.ElementsMatch(t, tt.expectedMissing, analysis.MissingTags)

			// Available tags should be from runners
			allAvailable := make(map[string]bool)
			for _, r := range tt.availableRunners {
				for _, tag := range r.Tags {
					allAvailable[tag] = true
				}
			}
			expectedAvailable := make([]string, 0, len(allAvailable))
			for tag := range allAvailable {
				expectedAvailable = append(expectedAvailable, tag)
			}
			assert.ElementsMatch(t, expectedAvailable, analysis.AvailableTags)
		})
	}
}

func TestExtractWorkflowTags(t *testing.T) {
	tests := []struct {
		name         string
		yamlContent  string
		expectedTags []string
	}{
		{
			name: "multiple jobs with tags",
			yamlContent: `
job1:
  tags:
    - docker
    - linux
  script:
    - echo "test"

job2:
  tags:
    - kubernetes
  script:
    - echo "test2"
`,
			expectedTags: []string{"docker", "linux", "kubernetes"},
		},
		{
			name: "no tags",
			yamlContent: `
job:
  script:
    - echo "test"
`,
			expectedTags: []string{},
		},
		{
			name: "duplicate tags",
			yamlContent: `
job1:
  tags:
    - docker
  script:
    - echo "test"

job2:
  tags:
    - docker
    - linux
  script:
    - echo "test2"
`,
			expectedTags: []string{"docker", "linux"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tags, err := extractWorkflowTags([]byte(tt.yamlContent))
			require.NoError(t, err)

			assert.ElementsMatch(t, tt.expectedTags, tags)
		})
	}
}
