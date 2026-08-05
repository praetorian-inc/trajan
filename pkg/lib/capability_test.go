package lib

import (
	"context"
	"testing"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestSDKCapability_Match_PlatformOverride(t *testing.T) {
	capInstance := NewSDKCapability()
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "platform", Value: "jenkins"},
		},
	}
	err := capInstance.Match(ctx, capmodel.Repository{URL: "https://custom.corp.com/org/repo"})
	assert.NoError(t, err)
}

func TestSDKCapability_Invoke_Success(t *testing.T) {
	// Save and restore original ScanFunc
	orig := InvokeScanFunc
	defer func() { InvokeScanFunc = orig }()

	InvokeScanFunc = func(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
		return &ScanResult{
			Findings: []detections.Finding{
				{
					Type:       detections.VulnActionsInjection,
					Severity:   detections.SeverityHigh,
					Confidence: detections.ConfidenceHigh,
					Platform:   "github",
					Class:      detections.ClassInjection,
					Repository: "org/repo",
					Workflow:   "ci.yml",
					Evidence:   "uses ${{ github.event.issue.title }}",
				},
			},
			Workflows: []platforms.Workflow{
				{Name: "CI", Path: ".github/workflows/ci.yml"},
			},
		}, nil
	}

	capInstance := NewSDKCapability()
	var emitted []any
	out := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "token", Value: "test-token"},
		},
	}
	input := capmodel.Repository{
		URL:  "https://github.com/org/repo",
		Org:  "org",
		Name: "repo",
	}

	err := capInstance.Invoke(ctx, input, out)
	require.NoError(t, err)
	require.Len(t, emitted, 2, "expected 1 asset + 1 risk")

	// First emitted: asset (workflow)
	asset, ok := emitted[0].(capmodel.Asset)
	require.True(t, ok)
	assert.Equal(t, "https://github.com/org/repo", asset.DNS)
	assert.Contains(t, asset.Name, ".github/workflows/ci.yml")

	// Second emitted: risk (finding)
	risk, ok := emitted[1].(capmodel.Risk)
	require.True(t, ok)
	assert.Equal(t, "cicd-actions_injection", risk.Name)
	assert.Equal(t, TriageHigh, risk.Status)
	assert.Equal(t, "trajan", risk.Source)
	assert.NotEmpty(t, risk.Proof)
}

func TestSDKCapability_Invoke_CircleCI_Skipped(t *testing.T) {
	capInstance := NewSDKCapability()
	var emitted []any
	out := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "platform", Value: "circleci"},
		},
	}

	err := capInstance.Invoke(ctx, capmodel.Repository{URL: "https://circleci.com/org/repo"}, out)
	require.NoError(t, err)
	assert.Empty(t, emitted, "CircleCI should emit nothing")
}

func TestDetectPlatform(t *testing.T) {
	tests := []struct {
		url      string
		want     string
		detected bool
	}{
		{"https://github.com/org/repo", "github", true},
		{"https://gitlab.com/org/repo", "gitlab", true},
		{"https://dev.azure.com/org/repo", "azuredevops", true},
		{"https://bitbucket.org/org/repo", "bitbucket", true},
		{"https://circleci.com/org/repo", "circleci", true},
		{"https://unknown.com/org/repo", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got, ok := DetectPlatform(tt.url)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.detected, ok)
		})
	}
}

func TestSeverityToStatus(t *testing.T) {
	assert.Equal(t, TriageHigh, SeverityToStatus(detections.SeverityCritical))
	assert.Equal(t, TriageHigh, SeverityToStatus(detections.SeverityHigh))
	assert.Equal(t, TriageMedium, SeverityToStatus(detections.SeverityMedium))
	assert.Equal(t, TriageLow, SeverityToStatus(detections.SeverityLow))
	assert.Equal(t, TriageInfo, SeverityToStatus(detections.SeverityInfo))
}
