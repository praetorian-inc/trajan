package c2setup

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/github"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestNew(t *testing.T) {
	plugin := New()

	assert.NotNil(t, plugin)
	assert.Equal(t, "c2-setup", plugin.Name())
	assert.NotEmpty(t, plugin.Description())
	assert.Equal(t, attacks.CategoryC2, plugin.Category())
	assert.Equal(t, "github", plugin.Platform())
}

func TestCanAttack(t *testing.T) {
	plugin := New()

	testCases := []struct {
		name     string
		findings []detections.Finding
		expected bool
	}{
		{
			name:     "with no findings",
			findings: []detections.Finding{},
			expected: true,
		},
		{
			name:     "with pwn request vulnerability",
			findings: []detections.Finding{{Type: detections.VulnPwnRequest}},
			expected: true,
		},
		{
			name:     "with any findings",
			findings: []detections.Finding{{Type: detections.VulnActionsInjection}},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := plugin.CanAttack(tc.findings)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExecute_DryRun(t *testing.T) {
	plugin := New()

	opts := attacks.AttackOptions{
		SessionID: "test-session",
		DryRun:    true,
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "test/repo"},
		ExtraOpts: map[string]string{},
	}

	result, err := plugin.Execute(context.Background(), opts)

	assert.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "[DRY RUN]")
	assert.Contains(t, result.Message, "Would create C2 repository")
	assert.Len(t, result.Artifacts, 2) // Repository and Workflow
	assert.Equal(t, attacks.ArtifactRepository, result.Artifacts[0].Type)
	assert.Equal(t, attacks.ArtifactWorkflow, result.Artifacts[1].Type)
	assert.Equal(t, ".github/workflows/webshell.yml", result.Artifacts[1].Identifier)

	// Verify artifact identifier is in "owner/repo" format
	repoArtifact := result.Artifacts[0].Identifier
	assert.Contains(t, repoArtifact, "/", "Repository artifact should be in 'owner/repo' format")
	assert.Contains(t, repoArtifact, "test/", "Repository artifact should use target owner")
	assert.Contains(t, repoArtifact, "trajan-c2-", "Repository artifact should contain C2 repo name")
}

func TestExecute_DryRun_WithCustomRepoName(t *testing.T) {
	plugin := New()

	opts := attacks.AttackOptions{
		SessionID: "test-session",
		DryRun:    true,
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "test/repo"},
		ExtraOpts: map[string]string{
			"c2_repo_name": "my-custom-c2",
		},
	}

	result, err := plugin.Execute(context.Background(), opts)

	assert.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "my-custom-c2")
	assert.Contains(t, result.Artifacts[0].Identifier, "my-custom-c2")

	// Verify custom repo name is also in "owner/repo" format
	assert.Contains(t, result.Artifacts[0].Identifier, "test/my-custom-c2")
}

func TestExecute_InvalidPlatform(t *testing.T) {
	plugin := New()

	opts := attacks.AttackOptions{
		SessionID: "test-session",
		DryRun:    false,
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "test/repo"},
		Platform:  nil, // Invalid platform
		ExtraOpts: map[string]string{},
	}

	result, err := plugin.Execute(context.Background(), opts)

	assert.Error(t, err)
	assert.False(t, result.Success)
	assert.Equal(t, "platform is not GitHub", result.Message)
}

func newC2AppPlatform(t *testing.T, url string) *github.Platform {
	t.Helper()
	p := github.NewPlatform()
	if err := p.Init(context.Background(), platforms.Config{BaseURL: url, Token: "ghs_test"}); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	return p
}

func TestC2Setup_AppToken_RequiresC2Org(t *testing.T) {
	p := newC2AppPlatform(t, "https://api.github.com")
	res, err := New().Execute(context.Background(), attacks.AttackOptions{
		Platform:  p,
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "acme/x"},
		ExtraOpts: map[string]string{}, // no c2_org
	})
	if err == nil {
		t.Fatal("expected error when --c2-org missing for app token")
	}
	if res.Success {
		t.Error("Success should be false")
	}
	if !strings.Contains(res.Message, "c2-org") {
		t.Errorf("message %q should mention --c2-org", res.Message)
	}
}
