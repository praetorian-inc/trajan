package tokenprobe

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProbeResult_HasCapability(t *testing.T) {
	result := &ProbeResult{
		Capabilities: []Capability{CapabilityProjectsRead, CapabilityRepositoriesRead},
	}

	assert.True(t, result.HasCapability(CapabilityProjectsRead))
	assert.True(t, result.HasCapability(CapabilityRepositoriesRead))
	assert.False(t, result.HasCapability(CapabilityPipelinesRead))
}

func TestProbeResult_HasHighValueAccess(t *testing.T) {
	tests := []struct {
		name          string
		capabilities  []Capability
		hasSecrets    bool
		hasSelfHosted bool
		expected      bool
	}{
		{
			name:         "no access",
			capabilities: []Capability{CapabilityProjectsRead},
			expected:     false,
		},
		{
			name:         "pipelines access",
			capabilities: []Capability{CapabilityPipelinesRead},
			expected:     true,
		},
		{
			name:         "variable groups access",
			capabilities: []Capability{CapabilityVariableGroupsRead},
			expected:     true,
		},
		{
			name:         "service connections access",
			capabilities: []Capability{CapabilityServiceConnectionsRead},
			expected:     true,
		},
		{
			name:         "agent pools access",
			capabilities: []Capability{CapabilityAgentPoolsRead},
			expected:     true,
		},
		{
			name:         "has secret variables",
			capabilities: []Capability{CapabilityProjectsRead},
			hasSecrets:   true,
			expected:     true,
		},
		{
			name:          "has self-hosted agents",
			capabilities:  []Capability{CapabilityProjectsRead},
			hasSelfHosted: true,
			expected:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ProbeResult{
				Capabilities:        tt.capabilities,
				HasSecretVariables:  tt.hasSecrets,
				HasSelfHostedAgents: tt.hasSelfHosted,
			}
			assert.Equal(t, tt.expected, result.HasHighValueAccess())
		})
	}
}
