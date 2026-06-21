package privesc

import (
	"context"
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
	assert.Equal(t, "ado-privesc", plugin.Name())
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
		ExtraOpts: map[string]string{
			"user_descriptor": "aad.test-user",
		},
		DryRun: true,
	}

	result, err := plugin.Execute(context.Background(), opts)
	assert.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "DRY RUN")
}

func TestExecutePrivesc(t *testing.T) {
	t.Skip("Integration test - requires Azure DevOps instance or complex URL mocking")
	// Note: Full integration test requires mocking the VSSPS Graph API
	// The Azure DevOps client uses different endpoints for group resolution and membership
	// This test is skipped but the implementation has been verified manually
}

func TestExecutePrivescDryRun(t *testing.T) {
	plugin := New()

	// Create a minimal Platform with client
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
			Value: "test-project/test-repo",
		},
		ExtraOpts: map[string]string{
			"group":           "project-admin",
			"user_descriptor": "aad.test-user-descriptor",
		},
		DryRun: true,
	}

	result, err := plugin.Execute(context.Background(), opts)
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "[DRY RUN]")
	assert.Contains(t, result.Message, "Project Administrators")
}

func TestCleanupPrivesc(t *testing.T) {
	t.Skip("Integration test - requires Azure DevOps instance or complex URL mocking")
	// Note: Cleanup testing requires complex VSSPS URL mocking
	// The implementation calls RemoveMembership which uses Graph API
	// This test is skipped but the cleanup logic has been verified manually
}
