package prattack

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
	assert.Equal(t, "ado-pr-attack", plugin.Name())
	assert.Equal(t, "Trigger malicious pipeline via pull request build validation on Azure DevOps", plugin.Description())
	assert.Equal(t, "azuredevops", plugin.Platform())
	assert.Equal(t, attacks.CategoryCICD, plugin.Category())
}

func TestCanAttack(t *testing.T) {
	plugin := New()

	tests := []struct {
		name     string
		findings []detections.Finding
		expected bool
	}{
		{
			name: "VulnPullRequestSecretsExposure finding present",
			findings: []detections.Finding{
				{Type: detections.VulnPullRequestSecretsExposure},
			},
			expected: true,
		},
		{
			name: "VulnTriggerExploitation finding present",
			findings: []detections.Finding{
				{Type: detections.VulnTriggerExploitation},
			},
			expected: true,
		},
		{
			name: "wrong finding type",
			findings: []detections.Finding{
				{Type: detections.VulnPwnRequest},
			},
			expected: false,
		},
		{
			name:     "Empty findings",
			findings: []detections.Finding{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.CanAttack(tt.findings)
			assert.Equal(t, tt.expected, result)
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
		SessionID: "test-session-123",
		Platform:  platform,
		Target: platforms.Target{
			Type:  platforms.TargetRepo,
			Value: "TestProject/TestRepo",
		},
		DryRun: true,
	}

	result, err := plugin.Execute(context.Background(), opts)

	// Dry run should not error
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "DRY RUN")
	assert.Equal(t, "ado-pr-attack", result.Plugin)
	assert.Equal(t, "test-session-123", result.SessionID)

	// Check artifacts
	assert.Len(t, result.Artifacts, 2)
	assert.Equal(t, attacks.ArtifactBranch, result.Artifacts[0].Type)
	assert.Contains(t, result.Artifacts[0].Identifier, "trajan-pr-attack-test-session-123")
	assert.Equal(t, attacks.ArtifactWorkflow, result.Artifacts[1].Type)
	assert.Equal(t, "azure-pipelines-pr-attack.yml", result.Artifacts[1].Identifier)
}
