package common

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/azuredevops"
)

func TestGenerateVariableGroupsYAML(t *testing.T) {
	t.Run("empty groups list", func(t *testing.T) {
		yaml := GenerateVariableGroupsYAML(nil)
		assert.Equal(t, "", yaml)

		yaml = GenerateVariableGroupsYAML([]azuredevops.VariableGroup{})
		assert.Equal(t, "", yaml)
	})

	t.Run("single variable group", func(t *testing.T) {
		groups := []azuredevops.VariableGroup{
			{ID: 1, Name: "test-secrets"},
		}

		yaml := GenerateVariableGroupsYAML(groups)

		assert.Contains(t, yaml, "variables:")
		assert.Contains(t, yaml, "  - group: test-secrets")
	})

	t.Run("multiple variable groups", func(t *testing.T) {
		groups := []azuredevops.VariableGroup{
			{ID: 1, Name: "secrets-prod"},
			{ID: 2, Name: "secrets-staging"},
			{ID: 3, Name: "api-keys"},
		}

		yaml := GenerateVariableGroupsYAML(groups)

		assert.Contains(t, yaml, "variables:")
		assert.Contains(t, yaml, "  - group: secrets-prod")
		assert.Contains(t, yaml, "  - group: secrets-staging")
		assert.Contains(t, yaml, "  - group: api-keys")
	})
}

func TestGenerateSecretEnvYAML(t *testing.T) {
	t.Run("no secret variables", func(t *testing.T) {
		groups := []azuredevops.VariableGroup{
			{
				ID:   1,
				Name: "public-vars",
				Variables: map[string]azuredevops.VariableValue{
					"PUBLIC_KEY": {Value: "value", IsSecret: false},
				},
			},
		}

		envYaml := GenerateSecretEnvYAML(groups)
		assert.Equal(t, "", envYaml)
	})

	t.Run("single secret variable", func(t *testing.T) {
		groups := []azuredevops.VariableGroup{
			{
				ID:   1,
				Name: "secrets",
				Variables: map[string]azuredevops.VariableValue{
					"API_KEY": {Value: "", IsSecret: true},
				},
			},
		}

		envYaml := GenerateSecretEnvYAML(groups)

		assert.Contains(t, envYaml, "    env:")
		assert.Contains(t, envYaml, "      API_KEY: $(API_KEY)")
	})

	t.Run("multiple secret variables", func(t *testing.T) {
		groups := []azuredevops.VariableGroup{
			{
				ID:   1,
				Name: "secrets",
				Variables: map[string]azuredevops.VariableValue{
					"DB_PASSWORD": {Value: "", IsSecret: true},
					"API_KEY":     {Value: "", IsSecret: true},
					"PUBLIC_VAR":  {Value: "public", IsSecret: false},
				},
			},
		}

		envYaml := GenerateSecretEnvYAML(groups)

		assert.Contains(t, envYaml, "    env:")
		assert.Contains(t, envYaml, "      API_KEY: $(API_KEY)")
		assert.Contains(t, envYaml, "      DB_PASSWORD: $(DB_PASSWORD)")
		assert.NotContains(t, envYaml, "PUBLIC_VAR")
	})

	t.Run("secrets sorted alphabetically", func(t *testing.T) {
		groups := []azuredevops.VariableGroup{
			{
				ID:   1,
				Name: "secrets",
				Variables: map[string]azuredevops.VariableValue{
					"ZEBRA_SECRET": {Value: "", IsSecret: true},
					"APPLE_SECRET": {Value: "", IsSecret: true},
					"MANGO_SECRET": {Value: "", IsSecret: true},
				},
			},
		}

		envYaml := GenerateSecretEnvYAML(groups)

		lines := strings.Split(envYaml, "\n")
		var secretLines []string
		for _, line := range lines {
			if strings.Contains(line, "SECRET") {
				secretLines = append(secretLines, line)
			}
		}

		// Should be sorted: APPLE, MANGO, ZEBRA
		assert.Len(t, secretLines, 3)
		assert.Contains(t, secretLines[0], "APPLE_SECRET")
		assert.Contains(t, secretLines[1], "MANGO_SECRET")
		assert.Contains(t, secretLines[2], "ZEBRA_SECRET")
	})

	t.Run("multiple groups with overlapping secret names", func(t *testing.T) {
		groups := []azuredevops.VariableGroup{
			{
				ID:   1,
				Name: "group1",
				Variables: map[string]azuredevops.VariableValue{
					"API_KEY": {Value: "", IsSecret: true},
				},
			},
			{
				ID:   2,
				Name: "group2",
				Variables: map[string]azuredevops.VariableValue{
					"API_KEY":     {Value: "", IsSecret: true}, // Same name in different group
					"DB_PASSWORD": {Value: "", IsSecret: true},
				},
			},
		}

		envYaml := GenerateSecretEnvYAML(groups)

		// Should deduplicate - only one API_KEY mapping
		apiKeyCount := strings.Count(envYaml, "API_KEY: $(API_KEY)")
		assert.Equal(t, 1, apiKeyCount, "API_KEY should appear only once")

		assert.Contains(t, envYaml, "      API_KEY: $(API_KEY)")
		assert.Contains(t, envYaml, "      DB_PASSWORD: $(DB_PASSWORD)")
	})
}
