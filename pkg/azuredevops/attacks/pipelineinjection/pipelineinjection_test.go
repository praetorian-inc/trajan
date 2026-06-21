package pipelineinjection

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestNew(t *testing.T) {
	plugin := New()
	assert.NotNil(t, plugin)
	assert.Equal(t, "ado-pipeline-injection", plugin.Name())
	assert.Equal(t, "azuredevops", plugin.Platform())
	assert.Equal(t, attacks.CategoryCICD, plugin.Category())
	assert.Contains(t, plugin.Description(), "Poisoned Pipeline Execution")
}

func TestCanAttack(t *testing.T) {
	plugin := New()

	tests := []struct {
		name     string
		findings []detections.Finding
		want     bool
	}{
		{
			name: "script injection - can attack",
			findings: []detections.Finding{
				{Type: detections.VulnScriptInjection},
			},
			want: true,
		},
		{
			name: "dynamic template injection - can attack",
			findings: []detections.Finding{
				{Type: detections.VulnDynamicTemplateInjection},
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
				{Type: detections.VulnPwnRequest},
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

func TestGeneratePipelineYAML(t *testing.T) {
	plugin := New()

	t.Run("basic YAML without variable groups", func(t *testing.T) {
		yaml := plugin.generatePipelineYAML(nil, nil)

		assert.Contains(t, yaml, "trigger: none")
		assert.Contains(t, yaml, "vmImage: 'ubuntu-latest'")
		assert.Contains(t, yaml, "Pipeline Injection - Trajan")
		assert.Contains(t, yaml, "env | sort")
		assert.Contains(t, yaml, "base64 | base64")
		assert.NotContains(t, yaml, "variables:")
		assert.NotContains(t, yaml, "group:")
		assert.NotContains(t, yaml, "env:")
	})

	t.Run("YAML with single variable group from extraOpts", func(t *testing.T) {
		extraOpts := map[string]string{
			"groups": "my-secrets",
		}
		yaml := plugin.generatePipelineYAML(extraOpts, nil)

		assert.Contains(t, yaml, "variables:")
		assert.Contains(t, yaml, "group: my-secrets")
	})

	t.Run("YAML with multiple variable groups from extraOpts", func(t *testing.T) {
		extraOpts := map[string]string{
			"groups": "secrets-prod, secrets-staging, api-keys",
		}
		yaml := plugin.generatePipelineYAML(extraOpts, nil)

		assert.Contains(t, yaml, "variables:")
		assert.Contains(t, yaml, "group: secrets-prod")
		assert.Contains(t, yaml, "group: secrets-staging")
		assert.Contains(t, yaml, "group: api-keys")
	})

	t.Run("YAML with empty groups string", func(t *testing.T) {
		extraOpts := map[string]string{
			"groups": "",
		}
		yaml := plugin.generatePipelineYAML(extraOpts, nil)

		assert.NotContains(t, yaml, "variables:")
		assert.NotContains(t, yaml, "group:")
	})

	t.Run("YAML with discovered variable groups", func(t *testing.T) {
		discoveredGroups := []azuredevops.VariableGroup{
			{
				ID:   1,
				Name: "isengard-secrets",
				Variables: map[string]azuredevops.VariableValue{
					"API_KEY":     {Value: "", IsSecret: true},
					"APP_ENV":     {Value: "production", IsSecret: false},
					"DB_PASSWORD": {Value: "", IsSecret: true},
				},
			},
			{
				ID:   2,
				Name: "mordor-config",
				Variables: map[string]azuredevops.VariableValue{
					"RING_POWER": {Value: "", IsSecret: true},
					"LOCATION":   {Value: "mount-doom", IsSecret: false},
				},
			},
		}

		yaml := plugin.generatePipelineYAML(nil, discoveredGroups)

		// Check variables section
		assert.Contains(t, yaml, "variables:")
		assert.Contains(t, yaml, "group: isengard-secrets")
		assert.Contains(t, yaml, "group: mordor-config")

		// Check env section for secret variables
		assert.Contains(t, yaml, "env:")
		assert.Contains(t, yaml, "API_KEY: $(API_KEY)")
		assert.Contains(t, yaml, "DB_PASSWORD: $(DB_PASSWORD)")
		assert.Contains(t, yaml, "RING_POWER: $(RING_POWER)")

		// Non-secret variables should NOT be in env block
		assert.NotContains(t, yaml, "APP_ENV: $(APP_ENV)")
		assert.NotContains(t, yaml, "LOCATION: $(LOCATION)")
	})

	t.Run("extraOpts takes precedence over discovered groups", func(t *testing.T) {
		extraOpts := map[string]string{
			"groups": "manual-override",
		}
		discoveredGroups := []azuredevops.VariableGroup{
			{ID: 1, Name: "auto-discovered", Variables: map[string]azuredevops.VariableValue{}},
		}

		yaml := plugin.generatePipelineYAML(extraOpts, discoveredGroups)

		// Should use extraOpts, not discovered
		assert.Contains(t, yaml, "group: manual-override")
		assert.NotContains(t, yaml, "group: auto-discovered")
	})

	t.Run("env block only added if secret variables exist", func(t *testing.T) {
		discoveredGroups := []azuredevops.VariableGroup{
			{
				ID:   1,
				Name: "non-secret-only",
				Variables: map[string]azuredevops.VariableValue{
					"PUBLIC_VAR": {Value: "value", IsSecret: false},
				},
			},
		}

		yaml := plugin.generatePipelineYAML(nil, discoveredGroups)

		assert.Contains(t, yaml, "variables:")
		assert.Contains(t, yaml, "group: non-secret-only")
		assert.NotContains(t, yaml, "env:")
	})
}
