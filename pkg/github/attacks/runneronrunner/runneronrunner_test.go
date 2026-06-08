package runneronrunner

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

func TestRunnerOnRunner_CanAttack(t *testing.T) {
	plugin := New()

	testCases := []struct {
		name     string
		findings []detections.Finding
		expected bool
	}{
		{
			name:     "with pwn request vulnerability",
			findings: []detections.Finding{{Type: detections.VulnPwnRequest}},
			expected: true,
		},
		{
			name:     "with self-hosted runner vulnerability",
			findings: []detections.Finding{{Type: detections.VulnSelfHostedRunner}},
			expected: true,
		},
		{
			name: "with both vulnerabilities",
			findings: []detections.Finding{
				{Type: detections.VulnPwnRequest},
				{Type: detections.VulnSelfHostedRunner},
			},
			expected: true,
		},
		{
			name:     "with unrelated vulnerability",
			findings: []detections.Finding{{Type: detections.VulnActionsInjection}},
			expected: false,
		},
		{
			name:     "with no vulnerabilities",
			findings: []detections.Finding{},
			expected: false,
		},
		{
			name:     "nil findings",
			findings: nil,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := plugin.CanAttack(tc.findings)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestRunnerOnRunner_Metadata(t *testing.T) {
	plugin := New()

	assert.Equal(t, "runner-on-runner", plugin.Name())
	assert.NotEmpty(t, plugin.Description())
	assert.Equal(t, attacks.CategoryRunners, plugin.Category())
}

func TestRunnerOnRunner_New(t *testing.T) {
	plugin := New()

	assert.NotNil(t, plugin)
	assert.Equal(t, "runner-on-runner", plugin.Name())
	assert.Equal(t, "github", plugin.Platform())
}

func TestRoR_AppToken_RequiresC2Repo(t *testing.T) {
	p := github.NewPlatform()
	if err := p.Init(context.Background(), platforms.Config{BaseURL: "https://api.github.com", Token: "ghs_test"}); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	res, err := New().Execute(context.Background(), attacks.AttackOptions{
		Platform:  p,
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "acme/x"},
		ExtraOpts: map[string]string{}, // no c2_repo
	})
	if err == nil {
		t.Fatal("expected error when --c2-repo missing for app token")
	}
	if res.Success || !strings.Contains(res.Message, "c2-repo") {
		t.Errorf("message %q should require --c2-repo; success=%v", res.Message, res.Success)
	}
}
