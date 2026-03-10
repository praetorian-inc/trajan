package lib

import (
	"context"
	"fmt"
	"testing"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSDKCapability_InterfaceCompliance(t *testing.T) {
	var _ capability.Capability[capmodel.Repository] = (*SDKCapability)(nil)
}

func TestSDKCapability_Metadata(t *testing.T) {
	cap := NewSDKCapability()
	assert.Equal(t, "trajan", cap.Name())
	assert.Contains(t, cap.Description(), "CI/CD")
	_, ok := cap.Input().(capmodel.Repository)
	assert.True(t, ok)
}

func TestSDKCapability_Parameters(t *testing.T) {
	cap := NewSDKCapability()
	params := cap.Parameters()
	require.Len(t, params, 13)
	assert.Equal(t, "token", params[0].Name)
	assert.Equal(t, "platform", params[1].Name)
	assert.Contains(t, params[1].Options, "github")
	assert.Contains(t, params[1].Options, "jenkins")
	assert.Equal(t, "base_url", params[2].Name)
	assert.Equal(t, "active_mode", params[3].Name)
	assert.Equal(t, "bool", params[3].Type)
	assert.Equal(t, "attack_plugins", params[4].Name)
	assert.Equal(t, "[]string", params[4].Type)
	assert.NotEmpty(t, params[4].Options)
	assert.Equal(t, "dry_run", params[5].Name)
	assert.Equal(t, "attack_timeout", params[6].Name)
}

func TestSDKCapability_Match_ValidURL(t *testing.T) {
	cap := NewSDKCapability()
	ctx := capability.ExecutionContext{}
	err := cap.Match(ctx, capmodel.Repository{URL: "https://github.com/org/repo"})
	assert.NoError(t, err)
}

func TestSDKCapability_Match_EmptyURL(t *testing.T) {
	cap := NewSDKCapability()
	ctx := capability.ExecutionContext{}
	err := cap.Match(ctx, capmodel.Repository{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "repository URL is required")
}

func TestSDKCapability_Match_UnsupportedURL(t *testing.T) {
	cap := NewSDKCapability()
	ctx := capability.ExecutionContext{}
	err := cap.Match(ctx, capmodel.Repository{URL: "https://unknown.com/org/repo"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported CI/CD platform")
}

func TestSDKCapability_Match_PlatformOverride(t *testing.T) {
	cap := NewSDKCapability()
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "platform", Value: "jenkins"},
		},
	}
	err := cap.Match(ctx, capmodel.Repository{URL: "https://custom.corp.com/org/repo"})
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

	cap := NewSDKCapability()
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

	err := cap.Invoke(ctx, input, out)
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
	cap := NewSDKCapability()
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

	err := cap.Invoke(ctx, capmodel.Repository{URL: "https://circleci.com/org/repo"}, out)
	require.NoError(t, err)
	assert.Empty(t, emitted, "CircleCI should emit nothing")
}

func TestSDKCapability_Invoke_NoFindings(t *testing.T) {
	orig := InvokeScanFunc
	defer func() { InvokeScanFunc = orig }()

	InvokeScanFunc = func(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
		return &ScanResult{}, nil
	}

	cap := NewSDKCapability()
	var emitted []any
	out := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "token", Value: "t"},
		},
	}

	err := cap.Invoke(ctx, capmodel.Repository{
		URL: "https://github.com/org/repo", Org: "org", Name: "repo",
	}, out)
	require.NoError(t, err)
	assert.Empty(t, emitted)
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

func TestBuildFindingProof(t *testing.T) {
	f := detections.Finding{
		Type:       detections.VulnActionsInjection,
		Severity:   detections.SeverityHigh,
		Confidence: detections.ConfidenceHigh,
		Platform:   "github",
		Class:      detections.ClassInjection,
		Repository: "org/repo",
		Workflow:   "ci.yml",
		Evidence:   "test evidence",
	}
	proof := BuildFindingProof(f)
	require.NotEmpty(t, proof)
	assert.Contains(t, string(proof), "actions_injection")
	assert.Contains(t, string(proof), "test evidence")
}

func TestSDKCapability_Invoke_AllAttackPluginsFail_ReturnsError(t *testing.T) {
	origScan := InvokeScanFunc
	origAttack := InvokeAttackFunc
	defer func() {
		InvokeScanFunc = origScan
		InvokeAttackFunc = origAttack
	}()

	InvokeScanFunc = func(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
		return &ScanResult{}, nil
	}
	InvokeAttackFunc = func(ctx context.Context, cfg AttackConfig) (*AttackResult, error) {
		return &AttackResult{
			Errors: []error{
				fmt.Errorf("401 unauthorized: invalid token"),
			},
			Results: []attacks.AttackResult{
				{Plugin: "plugin1", Success: false, Message: "auth failed"},
			},
		}, nil
	}

	cap := NewSDKCapability()
	var emitted []any
	out := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "token", Value: "bad-token"},
			{Name: "active_mode", Value: "true"},
			{Name: "attack_plugins", Value: "plugin1"},
		},
	}
	input := capmodel.Repository{
		URL:  "https://github.com/org/repo",
		Org:  "org",
		Name: "repo",
	}

	err := cap.Invoke(ctx, input, out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all attack plugins failed")
	assert.Contains(t, err.Error(), "401 unauthorized")
	assert.Empty(t, emitted, "no risks should be emitted when all plugins fail")
}

func TestSDKCapability_Invoke_ExtraOptsForwarded(t *testing.T) {
	origScan := InvokeScanFunc
	origAttack := InvokeAttackFunc
	defer func() {
		InvokeScanFunc = origScan
		InvokeAttackFunc = origAttack
	}()

	InvokeScanFunc = func(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
		return &ScanResult{}, nil
	}

	var capturedConfig AttackConfig
	InvokeAttackFunc = func(ctx context.Context, cfg AttackConfig) (*AttackResult, error) {
		capturedConfig = cfg
		return &AttackResult{
			Results: []attacks.AttackResult{
				{Plugin: "plugin1", Success: true, Message: "success"},
			},
		}, nil
	}

	cap := NewSDKCapability()
	out := capability.EmitterFunc(func(models ...any) error { return nil })

	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "token", Value: "test-token"},
			{Name: "active_mode", Value: "true"},
			{Name: "attack_plugins", Value: "plugin1"},
			{Name: "c2_repo", Value: "owner/my-c2-repo"},
			{Name: "target_os", Value: "linux"},
			{Name: "delivery", Value: "pr"},
			{Name: "persistence_method", Value: "workflow"},
		},
	}
	input := capmodel.Repository{
		URL:  "https://github.com/org/repo",
		Org:  "org",
		Name: "repo",
	}

	err := cap.Invoke(ctx, input, out)
	require.NoError(t, err)

	assert.Equal(t, "owner/my-c2-repo", capturedConfig.ExtraOpts["c2_repo"])
	assert.Equal(t, "linux", capturedConfig.ExtraOpts["target_os"])
	assert.Equal(t, "pr", capturedConfig.ExtraOpts["delivery"])
	assert.Equal(t, "workflow", capturedConfig.ExtraOpts["method"], "persistence_method should be remapped to 'method'")
	assert.NotContains(t, capturedConfig.ExtraOpts, "persistence_method", "original key should be removed after remapping")
}

func TestSDKCapability_Invoke_PartialAttackSuccess_ReturnsNil(t *testing.T) {
	origScan := InvokeScanFunc
	origAttack := InvokeAttackFunc
	defer func() {
		InvokeScanFunc = origScan
		InvokeAttackFunc = origAttack
	}()

	InvokeScanFunc = func(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
		return &ScanResult{}, nil
	}
	InvokeAttackFunc = func(ctx context.Context, cfg AttackConfig) (*AttackResult, error) {
		return &AttackResult{
			Errors: []error{
				fmt.Errorf("plugin2: connection refused"),
			},
			Results: []attacks.AttackResult{
				{Plugin: "plugin1", Success: true, Message: "compromised"},
				{Plugin: "plugin2", Success: false, Message: "failed"},
			},
		}, nil
	}

	cap := NewSDKCapability()
	var emitted []any
	out := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "token", Value: "test-token"},
			{Name: "active_mode", Value: "true"},
			{Name: "attack_plugins", Value: "plugin1,plugin2"},
		},
	}
	input := capmodel.Repository{
		URL:  "https://github.com/org/repo",
		Org:  "org",
		Name: "repo",
	}

	err := cap.Invoke(ctx, input, out)
	require.NoError(t, err, "partial success should not return error")
	require.Len(t, emitted, 1, "only the successful plugin risk should be emitted")
	risk, ok := emitted[0].(capmodel.Risk)
	require.True(t, ok)
	assert.Equal(t, "cicd-attack-plugin1", risk.Name)
}
