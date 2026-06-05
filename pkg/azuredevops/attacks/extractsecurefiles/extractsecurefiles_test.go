package extractsecurefiles

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	plugin := New()
	assert.NotNil(t, plugin)
	assert.Equal(t, "ado-extract-securefiles", plugin.Name())
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
			name: "secret scope risk - can attack",
			findings: []detections.Finding{
				{Type: detections.VulnSecretScopeRisk},
			},
			want: true,
		},
		{
			name: "pull request secrets exposure - can attack",
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

func TestGenerateSecureFileYAML(t *testing.T) {
	yaml := generateSecureFileYAML("my-cert.pfx")

	assert.Contains(t, yaml, "trigger: none")
	assert.Contains(t, yaml, "DownloadSecureFile@1")
	assert.Contains(t, yaml, "secureFile: 'my-cert.pfx'")
	assert.Contains(t, yaml, "PublishPipelineArtifact@1")
	assert.Contains(t, yaml, "$(Agent.TempDirectory)/my-cert.pfx")
	assert.Contains(t, yaml, "artifactName: 'extracted-secure-file'")
	// Should NOT contain double-base64 encoding
	assert.NotContains(t, yaml, "base64 | base64")
}

func TestGenerateAllSecureFilesYAML(t *testing.T) {
	yaml := generateAllSecureFilesYAML([]string{"cert.pem", "key.pfx", "ssh_key"})

	assert.Contains(t, yaml, "trigger: none")
	assert.Contains(t, yaml, "DownloadSecureFile@1")
	assert.Contains(t, yaml, "secureFile: 'cert.pem'")
	assert.Contains(t, yaml, "secureFile: 'key.pfx'")
	assert.Contains(t, yaml, "secureFile: 'ssh_key'")
	assert.Contains(t, yaml, "secureFile_0")
	assert.Contains(t, yaml, "secureFile_1")
	assert.Contains(t, yaml, "secureFile_2")
	assert.Contains(t, yaml, "mkdir -p $(Build.ArtifactStagingDirectory)/secure-files")
	assert.Contains(t, yaml, "cp \"$(Agent.TempDirectory)/cert.pem\"")
	assert.Contains(t, yaml, "cp \"$(Agent.TempDirectory)/key.pfx\"")
	assert.Contains(t, yaml, "cp \"$(Agent.TempDirectory)/ssh_key\"")
	assert.Contains(t, yaml, "PublishPipelineArtifact@1")
	assert.Contains(t, yaml, "artifactName: 'extracted-secure-files'")
}

func TestExecute_DryRun(t *testing.T) {
	plugin := New()

	// Create minimal Platform
	platform := azuredevops.NewPlatform()
	err := platform.Init(context.Background(), platforms.Config{
		BaseURL: "https://dev.azure.com/test-org",
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
			"file": "my-secure-file.pfx",
		},
	}

	result, err := plugin.Execute(context.Background(), opts)
	assert.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "DRY RUN")
	assert.Contains(t, result.Message, "my-secure-file.pfx")
}

func TestExecuteWithClient_DryRun(t *testing.T) {
	// Test dry run doesn't make API calls
	serverCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalled = true
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := azuredevops.NewClient(server.URL, "test-pat")
	plugin := New()

	opts := attacks.AttackOptions{
		SessionID: "test-session",
		Target: platforms.Target{
			Value: "test-project/test-repo",
		},
		DryRun: true,
		ExtraOpts: map[string]string{
			"file": "test-file.pfx",
		},
	}

	result, err := plugin.executeWithClient(context.Background(), client, opts)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "[DRY RUN]")
	assert.False(t, serverCalled, "API should not be called in dry run mode")
}

func TestExecuteWithClient_AllFiles_DryRun(t *testing.T) {
	serverCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalled = true
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := azuredevops.NewClient(server.URL, "test-pat")
	plugin := New()

	opts := attacks.AttackOptions{
		SessionID: "test-session",
		Target: platforms.Target{
			Value: "test-project/test-repo",
		},
		DryRun: true,
		// No ExtraOpts - should default to all files
	}

	result, err := plugin.executeWithClient(context.Background(), client, opts)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "[DRY RUN]")
	assert.Contains(t, result.Message, "all secure files")
	assert.False(t, serverCalled, "API should not be called in dry run mode")
}

func TestExecuteWithClient_FileNotFound(t *testing.T) {
	// Test when secure file doesn't exist in project
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "securefiles") {
			// Return empty secure files list
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []interface{}{
					map[string]interface{}{
						"id":   "guid-1",
						"name": "other-file.pfx",
					},
				},
				"count": 1,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := azuredevops.NewClient(server.URL, "test-pat")
	plugin := New()

	opts := attacks.AttackOptions{
		SessionID: "test-session",
		Target: platforms.Target{
			Value: "test-project/test-repo",
		},
		DryRun: false,
		ExtraOpts: map[string]string{
			"file": "nonexistent-file.pfx",
		},
	}

	result, err := plugin.executeWithClient(context.Background(), client, opts)

	require.Error(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "not found")
}

func TestExecuteWithClient_NoSecureFiles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "securefiles") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []interface{}{},
				"count": 0,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := azuredevops.NewClient(server.URL, "test-pat")
	plugin := New()

	opts := attacks.AttackOptions{
		SessionID: "test-session",
		Target: platforms.Target{
			Value: "test-project/test-repo",
		},
		DryRun: false,
		// No file specified - defaults to all, but project has none
	}

	result, err := plugin.executeWithClient(context.Background(), client, opts)

	require.Error(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "no secure files found")
}

func TestCleanup(t *testing.T) {
	// Track which cleanup calls were made
	deletedPipelines := []string{}
	deletedBranches := []string{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// DELETE pipeline definition
		if r.Method == "DELETE" && strings.Contains(r.URL.Path, "definitions") {
			deletedPipelines = append(deletedPipelines, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// POST to refs (branch deletion)
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/refs") {
			deletedBranches = append(deletedBranches, r.URL.Path)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{"name": "refs/heads/deleted", "objectId": "0000000000000000000000000000000000000000", "success": true, "updateStatus": "succeeded"},
				},
				"count": 1,
			})
			return
		}

		// GET branches for deletion (need commit ID)
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/refs") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []interface{}{
					map[string]interface{}{
						"name":     "refs/heads/trajan-extract-file-test-session",
						"objectId": "abc123",
					},
				},
				"count": 1,
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	client := azuredevops.NewClient(server.URL, "test-pat")
	plugin := New()

	session := &attacks.Session{
		ID: "test-session",
		Target: platforms.Target{
			Value: "test-project/test-repo",
		},
		Results: []*attacks.AttackResult{
			{
				Plugin: "ado-extract-securefiles",
				CleanupActions: []attacks.CleanupAction{
					{
						Type:       attacks.ArtifactWorkflow,
						Identifier: "pipeline:42",
						Action:     "delete",
					},
					{
						Type:       attacks.ArtifactBranch,
						Identifier: "trajan-extract-file-test-session",
						Action:     "delete",
					},
				},
			},
		},
	}

	err := plugin.cleanupWithClient(context.Background(), client, session)
	require.NoError(t, err)

	// Verify both cleanup actions were executed
	assert.Len(t, deletedPipelines, 1, "should have deleted one pipeline")
	assert.Len(t, deletedBranches, 1, "should have deleted one branch")
}
