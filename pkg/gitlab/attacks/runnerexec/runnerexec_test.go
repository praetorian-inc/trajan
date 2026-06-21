// pkg/gitlab/attacks/runnerexec/runnerexec_test.go
package runnerexec

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestPlugin_CanAttack_AlwaysReturnsFalse(t *testing.T) {
	plugin := New()

	tests := []struct {
		name     string
		findings []detections.Finding
	}{
		{
			name:     "nil findings",
			findings: nil,
		},
		{
			name:     "empty findings",
			findings: []detections.Finding{},
		},
		{
			name: "self-hosted runner finding",
			findings: []detections.Finding{
				{Type: detections.VulnSelfHostedRunner},
			},
		},
		{
			name: "multiple findings",
			findings: []detections.Finding{
				{Type: detections.VulnSelfHostedRunner},
				{Type: detections.VulnPwnRequest},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.CanAttack(tt.findings)
			assert.False(t, result, "CanAttack should always return false (force-only plugin)")
		})
	}
}

func TestPlugin_Metadata(t *testing.T) {
	plugin := New()

	assert.Equal(t, "runner-exec", plugin.Name())
	assert.Equal(t, "Execute commands on self-hosted GitLab runners", plugin.Description())
	assert.Equal(t, "gitlab", plugin.Platform())
}
