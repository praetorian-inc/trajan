package common

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/azuredevops"
)

func TestGenerateEncryptedPipelineYAML_WithDiscoveredGroups(t *testing.T) {
	groups := []azuredevops.VariableGroup{
		{
			ID:   1,
			Name: "my-secrets",
			Variables: map[string]azuredevops.VariableValue{
				"SECRET_KEY": {Value: "", IsSecret: true},
				"PUBLIC_VAR": {Value: "hello", IsSecret: false},
				"API_TOKEN":  {Value: "", IsSecret: true},
			},
		},
	}

	pubKey := "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...\n-----END PUBLIC KEY-----"
	yaml := GenerateEncryptedPipelineYAML(pubKey, groups, true)

	// Basic structure
	assert.Contains(t, yaml, "trigger: none")
	assert.Contains(t, yaml, "vmImage: 'ubuntu-latest'")

	// Variable group reference
	assert.Contains(t, yaml, "group: my-secrets")

	// Python3 collection step
	assert.Contains(t, yaml, "python3 -c")
	assert.Contains(t, yaml, "import os, json")
	assert.Contains(t, yaml, "output.json")

	// Structured collection — var_to_group mapping
	assert.Contains(t, yaml, "var_to_group")
	assert.Contains(t, yaml, "'API_TOKEN': 'my-secrets'")
	assert.Contains(t, yaml, "'PUBLIC_VAR': 'my-secrets'")
	assert.Contains(t, yaml, "'SECRET_KEY': 'my-secrets'")

	// Environment variables collection (includeEnvVars=true)
	assert.Contains(t, yaml, "__environment_variables__")
	assert.Contains(t, yaml, "env_vars")

	// Env block should map secret vars only
	assert.Contains(t, yaml, "API_TOKEN: $(API_TOKEN)")
	assert.Contains(t, yaml, "SECRET_KEY: $(SECRET_KEY)")
	// Non-secret vars should NOT appear in env block
	assert.NotContains(t, yaml, "PUBLIC_VAR: $(PUBLIC_VAR)")

	// OpenSSL encryption commands
	assert.Contains(t, yaml, "openssl rand -hex 32")
	assert.Contains(t, yaml, "openssl enc -aes-256-cbc -pbkdf2")
	assert.Contains(t, yaml, "openssl pkeyutl -encrypt")

	// Public key embedding
	assert.Contains(t, yaml, "PUBKEY: |")
	assert.Contains(t, yaml, "MIIBIjANBg...")

	// PublishPipelineArtifact task
	assert.Contains(t, yaml, "PublishPipelineArtifact@1")
	assert.Contains(t, yaml, "artifact: 'encrypted-secrets'")
}

func TestGenerateEncryptedPipelineYAML_SingleGroup_NoEnvVars(t *testing.T) {
	groups := []azuredevops.VariableGroup{
		{
			ID:   1,
			Name: "target-group",
			Variables: map[string]azuredevops.VariableValue{
				"SECRET_A": {Value: "", IsSecret: true},
				"PUBLIC_B": {Value: "val", IsSecret: false},
			},
		},
	}

	pubKey := "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----"
	yaml := GenerateEncryptedPipelineYAML(pubKey, groups, false)

	// Should have group reference
	assert.Contains(t, yaml, "group: target-group")

	// Should have structured collection
	assert.Contains(t, yaml, "var_to_group")
	assert.Contains(t, yaml, "'target-group'")

	// Should NOT collect environment variables
	assert.NotContains(t, yaml, "__environment_variables__")
	assert.NotContains(t, yaml, "env_vars")

	// Secret env mapping should still work
	assert.Contains(t, yaml, "SECRET_A: $(SECRET_A)")
	assert.NotContains(t, yaml, "PUBLIC_B: $(PUBLIC_B)")
}

func TestGenerateEncryptedPipelineYAML_NoGroups_WithEnvVars(t *testing.T) {
	pubKey := "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----"
	yaml := GenerateEncryptedPipelineYAML(pubKey, nil, true)

	// Should NOT have variables section
	assert.NotContains(t, yaml, "variables:")
	// Should still have collection and encryption steps
	assert.Contains(t, yaml, "python3 -c")
	assert.Contains(t, yaml, "openssl enc -aes-256-cbc")
	// Should collect env vars even without groups
	assert.Contains(t, yaml, "__environment_variables__")
	assert.Contains(t, yaml, "env_vars")
}

func TestGenerateEncryptedPipelineYAML_NoGroups_NoEnvVars(t *testing.T) {
	pubKey := "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----"
	yaml := GenerateEncryptedPipelineYAML(pubKey, nil, false)

	// Should NOT have variables section
	assert.NotContains(t, yaml, "variables:")
	// Should NOT collect env vars
	assert.NotContains(t, yaml, "__environment_variables__")
	// Should still have encryption steps
	assert.Contains(t, yaml, "openssl enc -aes-256-cbc")
}

func TestGenerateEncryptedPipelineYAML_MultipleGroups(t *testing.T) {
	groups := []azuredevops.VariableGroup{
		{
			ID:   1,
			Name: "group-1",
			Variables: map[string]azuredevops.VariableValue{
				"VAR_A": {Value: "", IsSecret: true},
			},
		},
		{
			ID:   2,
			Name: "group-2",
			Variables: map[string]azuredevops.VariableValue{
				"VAR_B": {Value: "", IsSecret: true},
			},
		},
	}

	pubKey := "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----"
	yaml := GenerateEncryptedPipelineYAML(pubKey, groups, true)

	assert.Contains(t, yaml, "group: group-1")
	assert.Contains(t, yaml, "group: group-2")
	assert.Contains(t, yaml, "VAR_A: $(VAR_A)")
	assert.Contains(t, yaml, "VAR_B: $(VAR_B)")

	// Both groups should appear in var_to_group
	assert.Contains(t, yaml, "'VAR_A': 'group-1'")
	assert.Contains(t, yaml, "'VAR_B': 'group-2'")
}

func TestCollectSecretVarNames(t *testing.T) {
	groups := []azuredevops.VariableGroup{
		{
			Variables: map[string]azuredevops.VariableValue{
				"SECRET":  {IsSecret: true},
				"PUBLIC":  {IsSecret: false},
				"SECRET2": {IsSecret: true},
			},
		},
	}

	names := collectSecretVarNames(groups)
	assert.Equal(t, []string{"SECRET", "SECRET2"}, names)
}

func TestCollectSecretVarNames_Empty(t *testing.T) {
	names := collectSecretVarNames(nil)
	assert.Empty(t, names)
}

func TestPythonStringList(t *testing.T) {
	result := pythonStringList([]string{"A", "B", "C"})
	assert.Equal(t, "['A', 'B', 'C']", result)
}

func TestPythonStringList_Single(t *testing.T) {
	result := pythonStringList([]string{"ONLY"})
	assert.Equal(t, "['ONLY']", result)
}

func TestPythonDictLiteral(t *testing.T) {
	m := map[string]string{"VAR_B": "group-2", "VAR_A": "group-1"}
	result := pythonDictLiteral(m)
	assert.Equal(t, "{'VAR_A': 'group-1', 'VAR_B': 'group-2'}", result)
}

func TestPythonDictLiteral_Empty(t *testing.T) {
	result := pythonDictLiteral(map[string]string{})
	assert.Equal(t, "{}", result)
}

func TestBuildVarToGroupMap(t *testing.T) {
	groups := []azuredevops.VariableGroup{
		{
			Name: "group-1",
			Variables: map[string]azuredevops.VariableValue{
				"VAR_A": {IsSecret: true},
				"VAR_B": {IsSecret: false},
			},
		},
		{
			Name: "group-2",
			Variables: map[string]azuredevops.VariableValue{
				"VAR_C": {IsSecret: true},
			},
		},
	}

	result := buildVarToGroupMap(groups)
	assert.Equal(t, "group-1", result["VAR_A"])
	assert.Equal(t, "group-1", result["VAR_B"])
	assert.Equal(t, "group-2", result["VAR_C"])
}

func TestCollectAllVarNames(t *testing.T) {
	groups := []azuredevops.VariableGroup{
		{
			Variables: map[string]azuredevops.VariableValue{
				"SECRET":  {IsSecret: true},
				"PUBLIC":  {IsSecret: false},
				"SECRET2": {IsSecret: true},
			},
		},
	}

	names := collectAllVarNames(groups)
	assert.Equal(t, []string{"PUBLIC", "SECRET", "SECRET2"}, names)
}

func TestCollectAllVarNames_Empty(t *testing.T) {
	names := collectAllVarNames(nil)
	assert.Empty(t, names)
}
