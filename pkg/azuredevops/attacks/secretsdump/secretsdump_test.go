package secretsdump

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestNew(t *testing.T) {
	plugin := New()
	assert.NotNil(t, plugin)
	assert.Equal(t, "ado-secrets-dump", plugin.Name())
	assert.Equal(t, "azuredevops", plugin.Platform())
	assert.Equal(t, attacks.CategorySecrets, plugin.Category())
}

func TestCanAttack(t *testing.T) {
	plugin := New()

	tests := []struct {
		name     string
		findings []detections.Finding
		want     bool
	}{
		{
			name: "token_exposure - can attack",
			findings: []detections.Finding{
				{Type: detections.VulnTokenExposure},
			},
			want: true,
		},
		{
			name: "unredacted_secrets - can attack",
			findings: []detections.Finding{
				{Type: detections.VulnUnredactedSecrets},
			},
			want: true,
		},
		{
			name: "pull_request_secrets_exposure - can attack",
			findings: []detections.Finding{
				{Type: detections.VulnPullRequestSecretsExposure},
			},
			want: true,
		},
		{
			name:     "no findings - cannot attack",
			findings: []detections.Finding{},
			want:     false,
		},
		{
			name: "wrong finding type - cannot attack",
			findings: []detections.Finding{
				{Type: detections.VulnExcessivePermissions},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := plugin.CanAttack(tt.findings)
			assert.Equal(t, tt.want, got)
		})
	}
}

// newDryRunServer returns a mock HTTP server that serves the minimum ADO API
// responses needed for secretsdump.Execute to reach its DryRun check:
//   - ListVariableGroups  (distributedtask/variablegroups)
//   - GetRepository       (git/repositories/{repo})
//   - ListGitBranches     (git/repositories/{repo}/refs)
func newDryRunServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.Contains(r.URL.Path, "variablegroups"):
			json.NewEncoder(w).Encode(azuredevops.VariableGroupList{
				Value: []azuredevops.VariableGroup{},
				Count: 0,
			})

		case strings.Contains(r.URL.Path, "/refs"):
			json.NewEncoder(w).Encode(azuredevops.GitRefList{
				Value: []azuredevops.GitRef{
					{Name: "refs/heads/main", ObjectID: "abc123def456"},
				},
				Count: 1,
			})

		case strings.Contains(r.URL.Path, "git/repositories"):
			json.NewEncoder(w).Encode(azuredevops.Repository{
				ID:            "repo-id-1",
				Name:          "TestRepo",
				DefaultBranch: "refs/heads/main",
			})

		default:
			http.NotFound(w, r)
		}
	}))
}

func TestExecute_DryRun(t *testing.T) {
	server := newDryRunServer(t)
	defer server.Close()

	plugin := New()

	platform := azuredevops.NewPlatform()
	err := platform.Init(context.Background(), platforms.Config{
		BaseURL: server.URL,
		Token:   "test-pat",
	})
	require.NoError(t, err)

	opts := attacks.AttackOptions{
		SessionID: "test-session",
		Platform:  platform,
		Target: platforms.Target{
			Type:  platforms.TargetRepo,
			Value: "TestProject/TestRepo",
		},
		DryRun: true,
	}

	result, err := plugin.Execute(context.Background(), opts)
	assert.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "DRY RUN")
}

func TestExecute_DryRun_SpecificGroup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.Contains(r.URL.Path, "variablegroups"):
			json.NewEncoder(w).Encode(azuredevops.VariableGroupList{
				Value: []azuredevops.VariableGroup{
					{ID: 1, Name: "my-variable-group"},
				},
				Count: 1,
			})

		case strings.Contains(r.URL.Path, "/refs"):
			json.NewEncoder(w).Encode(azuredevops.GitRefList{
				Value: []azuredevops.GitRef{
					{Name: "refs/heads/main", ObjectID: "abc123def456"},
				},
				Count: 1,
			})

		case strings.Contains(r.URL.Path, "git/repositories"):
			json.NewEncoder(w).Encode(azuredevops.Repository{
				ID:            "repo-id-1",
				Name:          "TestRepo",
				DefaultBranch: "refs/heads/main",
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	plugin := New()

	platform := azuredevops.NewPlatform()
	err := platform.Init(context.Background(), platforms.Config{
		BaseURL: server.URL,
		Token:   "test-pat",
	})
	require.NoError(t, err)

	opts := attacks.AttackOptions{
		SessionID: "test-session",
		Platform:  platform,
		Target: platforms.Target{
			Type:  platforms.TargetRepo,
			Value: "TestProject/TestRepo",
		},
		DryRun: true,
		ExtraOpts: map[string]string{
			"group": "my-variable-group",
		},
	}

	result, err := plugin.Execute(context.Background(), opts)
	assert.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "DRY RUN")
	assert.Contains(t, result.Message, "my-variable-group")
}
