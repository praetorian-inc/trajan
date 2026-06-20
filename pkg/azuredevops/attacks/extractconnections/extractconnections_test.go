package extractconnections

import (
	"context"
	"encoding/json"
	"fmt"
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

const testPubKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWe
GLAG6M+Xm3DGuNO/T9IpfKHXGMnxGGTGHRPHhLkIMRQCL4bYVAQmVaJP1VsMT5B
-----END PUBLIC KEY-----`

func TestNew(t *testing.T) {
	plugin := New()
	assert.NotNil(t, plugin)
	assert.Equal(t, "ado-extract-connections", plugin.Name())
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
			name: "overexposed service connections - can attack",
			findings: []detections.Finding{
				{Type: detections.VulnOverexposedServiceConnections},
			},
			want: true,
		},
		{
			name: "service connection hijacking - can attack",
			findings: []detections.Finding{
				{Type: detections.VulnServiceConnectionHijacking},
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

func TestGenerateAzureYAML(t *testing.T) {
	plugin := New()
	yaml := plugin.generateExtractionYAML("azure", "my-azure-conn", testPubKeyPEM, nil)

	assert.Contains(t, yaml, "trigger: none")
	assert.Contains(t, yaml, "AzureCLI@2")
	assert.Contains(t, yaml, "azureSubscription: 'my-azure-conn'")
	assert.Contains(t, yaml, "ARM_CLIENT_ID")
	assert.Contains(t, yaml, "ARM_CLIENT_SECRET")
	assert.Contains(t, yaml, "ARM_TENANT_ID")
	assert.Contains(t, yaml, "ARM_SUBSCRIPTION_ID")
	assert.Contains(t, yaml, "output.json")
	assert.Contains(t, yaml, "openssl enc -aes-256-cbc")
	assert.Contains(t, yaml, "openssl pkeyutl -encrypt")
	assert.Contains(t, yaml, "PublishPipelineArtifact@1")
	assert.Contains(t, yaml, "encrypted-secrets")
	assert.NotContains(t, yaml, "base64 -w0 | base64 -w0")
	assert.NotContains(t, yaml, "branches:")
}

func TestGenerateGitHubYAML(t *testing.T) {
	plugin := New()
	yaml := plugin.generateExtractionYAML("github", "my-github-conn", testPubKeyPEM, nil)

	assert.Contains(t, yaml, "trigger: none")
	assert.Contains(t, yaml, "resources:")
	assert.Contains(t, yaml, "repository: github_target")
	assert.Contains(t, yaml, "type: github")
	assert.Contains(t, yaml, "endpoint: 'my-github-conn'")
	assert.Contains(t, yaml, "name: 'octocat/Hello-World'")
	assert.Contains(t, yaml, "checkout: github_target")
	assert.Contains(t, yaml, "persistCredentials: true")
	assert.Contains(t, yaml, "git_config")
	assert.Contains(t, yaml, "SYSTEM_ACCESSTOKEN")
	assert.Contains(t, yaml, "output.json")
	assert.Contains(t, yaml, "openssl enc -aes-256-cbc")
	assert.Contains(t, yaml, "PublishPipelineArtifact@1")
	assert.NotContains(t, yaml, "base64 -w0 | base64 -w0")
	assert.NotContains(t, yaml, "branches:")
}

func TestGenerateGitHubYAML_CustomRepo(t *testing.T) {
	plugin := New()
	extraOpts := map[string]string{
		"github_repo": "myorg/my-private-repo",
	}
	yaml := plugin.generateExtractionYAML("github", "my-github-conn", testPubKeyPEM, extraOpts)

	assert.Contains(t, yaml, "name: 'myorg/my-private-repo'")
	assert.NotContains(t, yaml, "octocat/Hello-World")
	assert.Contains(t, yaml, "endpoint: 'my-github-conn'")
	assert.Contains(t, yaml, "checkout: github_target")
	assert.Contains(t, yaml, "persistCredentials: true")
	assert.Contains(t, yaml, "output.json")
	assert.Contains(t, yaml, "openssl enc -aes-256-cbc")
}

func TestGenerateGitHubYAML_EmptyRepoInExtraOpts(t *testing.T) {
	plugin := New()
	extraOpts := map[string]string{
		"github_repo": "",
	}
	yaml := plugin.generateExtractionYAML("github", "my-github-conn", testPubKeyPEM, extraOpts)

	assert.Contains(t, yaml, "octocat/Hello-World")
	assert.NotContains(t, yaml, "name: ''")
}

func TestGenerateAWSYAML(t *testing.T) {
	plugin := New()
	yaml := plugin.generateExtractionYAML("aws", "my-aws-conn", testPubKeyPEM, nil)

	assert.Contains(t, yaml, "trigger: none")
	assert.Contains(t, yaml, "AWSShellScript@1")
	assert.Contains(t, yaml, "awsCredentials: 'my-aws-conn'")
	assert.Contains(t, yaml, "AWS_ACCESS_KEY_ID")
	assert.Contains(t, yaml, "AWS_SECRET_ACCESS_KEY")
	assert.Contains(t, yaml, "AWS_SESSION_TOKEN")
	assert.Contains(t, yaml, "output.json")
	assert.Contains(t, yaml, "openssl enc -aes-256-cbc")
	assert.Contains(t, yaml, "PublishPipelineArtifact@1")
	assert.NotContains(t, yaml, "base64 -w0 | base64 -w0")
	assert.NotContains(t, yaml, "branches:")
}

func TestGenerateKubernetesYAML(t *testing.T) {
	plugin := New()
	yaml := plugin.generateExtractionYAML("kubernetes", "my-k8s-conn", testPubKeyPEM, nil)

	assert.Contains(t, yaml, "trigger: none")
	assert.Contains(t, yaml, "Kubernetes@1")
	assert.Contains(t, yaml, "kubernetesServiceConnection: 'my-k8s-conn'")
	assert.Contains(t, yaml, "KUBECONFIG")
	assert.Contains(t, yaml, "output.json")
	assert.Contains(t, yaml, "openssl enc -aes-256-cbc")
	assert.Contains(t, yaml, "PublishPipelineArtifact@1")
	assert.NotContains(t, yaml, "base64 -w0 | base64 -w0")
	assert.NotContains(t, yaml, "branches:")
}

func TestGenerateDockerYAML(t *testing.T) {
	plugin := New()
	yaml := plugin.generateExtractionYAML("docker", "my-docker-conn", testPubKeyPEM, nil)

	assert.Contains(t, yaml, "trigger: none")
	assert.Contains(t, yaml, "Docker@2")
	assert.Contains(t, yaml, "containerRegistry: 'my-docker-conn'")
	assert.Contains(t, yaml, "docker_config")
	assert.Contains(t, yaml, "output.json")
	assert.Contains(t, yaml, "openssl enc -aes-256-cbc")
	assert.Contains(t, yaml, "PublishPipelineArtifact@1")
	assert.NotContains(t, yaml, "base64 -w0 | base64 -w0")
	assert.NotContains(t, yaml, "branches:")
}

func TestGenerateSSHYAML(t *testing.T) {
	plugin := New()
	yaml := plugin.generateExtractionYAML("ssh", "my-ssh-conn", testPubKeyPEM, nil)

	assert.Contains(t, yaml, "trigger: none")
	assert.Contains(t, yaml, "SSH@0")
	assert.Contains(t, yaml, "sshEndpoint: 'my-ssh-conn'")
	assert.Contains(t, yaml, "ssh_private_key")
	assert.Contains(t, yaml, "output.json")
	assert.Contains(t, yaml, "openssl enc -aes-256-cbc")
	assert.Contains(t, yaml, "PublishPipelineArtifact@1")
	assert.NotContains(t, yaml, "base64 -w0 | base64 -w0")
	assert.NotContains(t, yaml, "branches:")
}

func TestGenerateSonarQubeYAML(t *testing.T) {
	plugin := New()
	yaml := plugin.generateExtractionYAML("sonarqube", "my-sonar-conn", testPubKeyPEM, nil)

	assert.Contains(t, yaml, "trigger: none")
	assert.Contains(t, yaml, "SonarQubePrepare@5")
	assert.Contains(t, yaml, "SonarQube: 'my-sonar-conn'")
	assert.Contains(t, yaml, "SONAR_TOKEN")
	assert.Contains(t, yaml, "output.json")
	assert.Contains(t, yaml, "openssl enc -aes-256-cbc")
	assert.Contains(t, yaml, "PublishPipelineArtifact@1")
	assert.NotContains(t, yaml, "base64 -w0 | base64 -w0")
	assert.NotContains(t, yaml, "branches:")
}

func TestGenerateGenericYAML(t *testing.T) {
	plugin := New()
	yaml := plugin.generateExtractionYAML("generic", "my-generic-conn", testPubKeyPEM, nil)

	assert.Contains(t, yaml, "trigger: none")
	assert.Contains(t, yaml, "SYSTEM_ACCESSTOKEN")
	assert.Contains(t, yaml, "serviceendpoint/endpoints")
	assert.Contains(t, yaml, "endpointNames=my-generic-conn")
	assert.Contains(t, yaml, "output.json")
	assert.Contains(t, yaml, "openssl enc -aes-256-cbc")
	assert.Contains(t, yaml, "PublishPipelineArtifact@1")
	assert.NotContains(t, yaml, "base64 -w0 | base64 -w0")
	assert.NotContains(t, yaml, "branches:")
}

func TestGenerateUnsupportedType(t *testing.T) {
	plugin := New()
	yaml := plugin.generateExtractionYAML("unsupported", "conn", testPubKeyPEM, nil)

	assert.Empty(t, yaml)
}

func TestEncryptionSuffix(t *testing.T) {
	suffix := encryptionSuffix(testPubKeyPEM)

	assert.Contains(t, suffix, "openssl rand -hex 32")
	assert.Contains(t, suffix, "openssl enc -aes-256-cbc -pbkdf2")
	assert.Contains(t, suffix, "openssl pkeyutl -encrypt")
	assert.Contains(t, suffix, "rsa_padding_mode:pkcs1")
	assert.Contains(t, suffix, "PublishPipelineArtifact@1")
	assert.Contains(t, suffix, "encrypted-secrets")
	assert.Contains(t, suffix, "BEGIN PUBLIC KEY")
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
			"type":       "azure",
			"connection": "my-azure-connection",
		},
	}

	result, err := plugin.Execute(context.Background(), opts)
	assert.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "DRY RUN")
	assert.Contains(t, result.Message, "azure")
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
			"type":       "github",
			"connection": "my-github-conn",
		},
	}

	result, err := plugin.executeWithClient(context.Background(), client, opts)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "[DRY RUN]")
	assert.False(t, serverCalled, "API should not be called in dry run mode")
}

func TestExecuteWithClient_MissingExtraOpts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		DryRun:    true,
		ExtraOpts: nil,
	}

	result, err := plugin.executeWithClient(context.Background(), client, opts)

	require.Error(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "missing connection type and name")
}

func TestExecuteWithClient_MissingType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			// Missing "type"
			"connection": "my-conn",
		},
	}

	result, err := plugin.executeWithClient(context.Background(), client, opts)

	require.Error(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, strings.ToLower(result.Message), "type")
}

func TestExecuteWithClient_MissingConnection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			"type": "azure",
			// Missing "connection"
		},
	}

	result, err := plugin.executeWithClient(context.Background(), client, opts)

	require.Error(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, strings.ToLower(result.Message), "connection")
}

func TestExecuteWithClient_ConnectionNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "serviceendpoint/endpoints") {
			resp := azuredevops.ServiceConnectionList{
				Value: []azuredevops.ServiceConnection{
					{ID: "abc-123", Name: "other-conn", Type: "azure"},
				},
				Count: 1,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
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
			"type":       "azure",
			"connection": "nonexistent-conn",
		},
	}

	result, err := plugin.executeWithClient(context.Background(), client, opts)

	require.Error(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "not found")
}

func TestCleanupWithClient(t *testing.T) {
	deletedPipeline := false
	deletedBranch := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle pipeline deletion
		if r.Method == "DELETE" && strings.Contains(r.URL.Path, "build/definitions/42") {
			deletedPipeline = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Handle ListGitBranches for branch deletion
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/refs") {
			resp := azuredevops.GitRefList{
				Value: []azuredevops.GitRef{
					{Name: "refs/heads/trajan-extract-conn-test", ObjectID: "abc123"},
				},
				Count: 1,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		// Handle branch deletion (POST to refs)
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/refs") {
			deletedBranch = true
			resp := azuredevops.GitRefList{
				Value: []azuredevops.GitRef{
					{Name: "refs/heads/trajan-extract-conn-test", ObjectID: "0000000000000000000000000000000000000000", Success: true, UpdateStatus: "succeeded"},
				},
				Count: 1,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := azuredevops.NewClient(server.URL, "test-pat")
	plugin := New()

	session := &attacks.Session{
		Target: platforms.Target{
			Value: "test-project/test-repo",
		},
		Results: []*attacks.AttackResult{
			{
				Plugin: "ado-extract-connections",
				CleanupActions: []attacks.CleanupAction{
					{
						Type:       attacks.ArtifactWorkflow,
						Identifier: fmt.Sprintf("pipeline:%d", 42),
						Action:     "delete",
					},
					{
						Type:       attacks.ArtifactBranch,
						Identifier: "trajan-extract-conn-test",
						Action:     "delete",
					},
				},
			},
		},
	}

	err := plugin.cleanupWithClient(context.Background(), client, session)
	assert.NoError(t, err)
	assert.True(t, deletedPipeline, "Pipeline should have been deleted")
	assert.True(t, deletedBranch, "Branch should have been deleted")
}
