package common

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatDecryptedSecrets(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"valid json", []byte(`{"key": "value"}`), `{"key": "value"}`},
		{"empty", []byte(""), "(no secrets found)"},
		{"empty json", []byte("{}"), "(no secrets found)"},
		{"null", []byte("null"), "(no secrets found)"},
		{"whitespace", []byte("  \n  "), "(no secrets found)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatDecryptedSecrets(tt.input)
			if tt.want == "(no secrets found)" {
				assert.Equal(t, tt.want, got)
			} else {
				assert.Contains(t, got, tt.want)
			}
		})
	}
}

func TestFormatStructuredSecrets_MultiGroupWithEnvVars(t *testing.T) {
	input := `{
		"__environment_variables__": {"CUSTOM_VAR": "val1", "APP_KEY": "val2"},
		"MyGroup": {"SECRET_A": "sec_a", "SECRET_B": "sec_b"},
		"AnotherGroup": {"SECRET_C": "sec_c"}
	}`

	result, err := FormatStructuredSecrets([]byte(input))
	require.NoError(t, err)

	// Environment variables section should come first
	assert.Contains(t, result, "=== Environment Variables ===")
	assert.Contains(t, result, "APP_KEY=val2")
	assert.Contains(t, result, "CUSTOM_VAR=val1")

	// Variable group sections
	assert.Contains(t, result, "=== Variable Group: AnotherGroup ===")
	assert.Contains(t, result, "SECRET_C=sec_c")
	assert.Contains(t, result, "=== Variable Group: MyGroup ===")
	assert.Contains(t, result, "SECRET_A=sec_a")
	assert.Contains(t, result, "SECRET_B=sec_b")

	// Env vars section should appear before groups (AnotherGroup comes after alphabetically)
	envIdx := indexOf(result, "=== Environment Variables ===")
	groupIdx := indexOf(result, "=== Variable Group: AnotherGroup ===")
	assert.Greater(t, groupIdx, envIdx, "Environment Variables should appear before variable groups")
}

func TestFormatStructuredSecrets_SingleGroup_NoEnvVars(t *testing.T) {
	input := `{
		"MyGroup": {"SECRET_A": "sec_a", "SECRET_B": "sec_b"}
	}`

	result, err := FormatStructuredSecrets([]byte(input))
	require.NoError(t, err)

	assert.Contains(t, result, "=== Variable Group: MyGroup ===")
	assert.Contains(t, result, "SECRET_A=sec_a")
	assert.Contains(t, result, "SECRET_B=sec_b")
	assert.NotContains(t, result, "Environment Variables")
}

func TestFormatStructuredSecrets_Empty(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"empty object", "{}"},
		{"null", "null"},
		{"whitespace", "  \n  "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FormatStructuredSecrets([]byte(tt.input))
			require.NoError(t, err)
			assert.Equal(t, "(no secrets found)", result)
		})
	}
}

func TestFormatStructuredSecrets_EmptyGroups(t *testing.T) {
	input := `{
		"EmptyGroup": {},
		"__environment_variables__": {}
	}`

	result, err := FormatStructuredSecrets([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "(no secrets found)", result)
}

func TestFormatStructuredSecrets_MalformedJSON(t *testing.T) {
	// Non-structured JSON should be returned as-is
	input := `{"flat_key": "flat_value"}`
	result, err := FormatStructuredSecrets([]byte(input))
	require.NoError(t, err)
	// Should fall back gracefully — the JSON doesn't match map[string]map[string]string
	// so it returns the raw string
	assert.Contains(t, result, "flat_key")
}

func TestFormatStructuredSecrets_NonJSON(t *testing.T) {
	input := `this is not json at all`
	result, err := FormatStructuredSecrets([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "this is not json at all", result)
}

func TestSecretsSummary(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "env vars and groups",
			input: `{"__environment_variables__": {"A": "1", "B": "2"}, "Group1": {"S1": "v1"}, "Group2": {"S2": "v2", "S3": "v3"}}`,
			want:  "2 environment variables, 2 variable groups (3 secrets)",
		},
		{
			name:  "groups only",
			input: `{"Group1": {"S1": "v1"}}`,
			want:  "1 variable groups (1 secrets)",
		},
		{
			name:  "env vars only",
			input: `{"__environment_variables__": {"A": "1"}}`,
			want:  "1 environment variables",
		},
		{
			name:  "empty",
			input: `{}`,
			want:  "no secrets found",
		},
		{
			name:  "invalid json",
			input: `not json`,
			want:  "secrets retrieved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SecretsSummary([]byte(tt.input))
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestWriteSecretsToFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")

	content := "=== Environment Variables ===\nFOO=bar\n"
	err := WriteSecretsToFile(content, path)
	require.NoError(t, err)

	// Verify file exists and has correct content
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, content+"\n", string(data))

	// Verify permissions are 0600
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestWriteSecretsToFile_InvalidPath(t *testing.T) {
	err := WriteSecretsToFile("content", "/nonexistent/dir/file.txt")
	assert.Error(t, err)
}

// indexOf returns the position of substr in s, or -1 if not found.
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
