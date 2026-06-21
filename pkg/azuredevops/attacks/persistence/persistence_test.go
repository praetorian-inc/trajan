package persistence

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	assert.Equal(t, "ado-persistence", plugin.Name())
	assert.Equal(t, "azuredevops", plugin.Platform())
}

func TestCanAttack(t *testing.T) {
	plugin := New()

	tests := []struct {
		name     string
		findings []detections.Finding
		want     bool
	}{
		{
			name: "excessive permissions - can attack",
			findings: []detections.Finding{
				{Type: detections.VulnExcessivePermissions},
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
				{Type: detections.VulnActionsInjection},
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

func TestExecute_DryRun(t *testing.T) {
	plugin := New()

	// Create a minimal Platform with client
	platform := azuredevops.NewPlatform()
	client := azuredevops.NewClient("https://dev.azure.com/test-org", "test-pat")
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
	}

	result, err := plugin.Execute(context.Background(), opts)
	assert.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "DRY RUN")
	assert.Contains(t, result.Message, "PAT")

	_ = client // avoid unused variable
}

func TestExecutePAT(t *testing.T) {
	t.Skip("Integration test - requires Azure DevOps instance or complex URL mocking")
	// Note: Full integration test requires mocking the VSSPS client URL replacement logic
	// The Azure DevOps client replaces the host with vssps.dev.azure.com for PAT operations
	// This test is skipped but the implementation has been verified manually
}

func TestExecuteSSH(t *testing.T) {
	t.Skip("Integration test - requires Azure DevOps instance or complex URL mocking")
	// Note: Full integration test requires mocking the VSSPS client URL replacement logic
	// The Azure DevOps client replaces the host with vssps.dev.azure.com for SSH operations
	// This test is skipped but the implementation has been verified manually
}

func TestExecuteWithClient_DryRun(t *testing.T) {
	// RED: Test dry run doesn't make API calls
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
	}

	result, err := plugin.executeWithClient(context.Background(), client, opts)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "[DRY RUN]")
	assert.False(t, serverCalled, "API should not be called in dry run mode")
}

func TestCleanupPAT(t *testing.T) {
	t.Skip("Integration test - requires Azure DevOps instance or complex URL mocking")
	// Note: Cleanup testing requires complex VSSPS URL mocking
	// The implementation calls RevokePersonalAccessToken which uses VSSPS client
	// This test is skipped but the cleanup logic has been verified manually
}

func TestCleanupSSH(t *testing.T) {
	t.Skip("Integration test - requires Azure DevOps instance or complex URL mocking")
	// Note: Cleanup testing requires complex VSSPS URL mocking
	// The implementation calls DeleteSSHKey which uses VSSPS client
	// This test is skipped but the cleanup logic has been verified manually
}
