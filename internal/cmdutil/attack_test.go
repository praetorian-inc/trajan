package cmdutil

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/attacks"
)

// captureStdout calls fn while capturing everything written to os.Stdout,
// then returns the captured output as a string.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	fn()

	w.Close()
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	os.Stdout = old

	return buf.String()
}

// makeResult is a small helper that builds an AttackResult with the given data.
func makeResult(data interface{}) *attacks.AttackResult {
	return &attacks.AttackResult{
		Plugin:    "test-plugin",
		SessionID: "sess-001",
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Success:   true,
		Message:   "attack completed",
		Data:      data,
	}
}

func TestOutputAttackResults_TextWithSecrets(t *testing.T) {
	results := []*attacks.AttackResult{
		makeResult(map[string]interface{}{
			"secrets": []string{"SECRET1=val1", "SECRET2=val2"},
		}),
	}

	output := captureStdout(t, func() {
		err := OutputAttackResults("text", results, "sess-001", "trajan cleanup")
		require.NoError(t, err)
	})

	assert.Contains(t, output, "Extracted Credentials:")
	assert.Contains(t, output, "SECRET1=val1")
	assert.Contains(t, output, "SECRET2=val2")
	assert.Contains(t, output, "[1] SECRET1=val1")
	assert.Contains(t, output, "[2] SECRET2=val2")
}

func TestOutputAttackResults_TextWithOutput(t *testing.T) {
	results := []*attacks.AttackResult{
		{
			Plugin:  "ado-agent-exec",
			Success: true,
			Message: "Command executed",
			Data: map[string]interface{}{
				"output": []interface{}{
					"uid=1000(runner) gid=1000(runner)",
					"Linux buildhost 5.15.0",
				},
			},
		},
	}

	output := captureStdout(t, func() {
		err := OutputAttackResults("text", results, "def456", "trajan ado attack cleanup")
		if err != nil {
			t.Fatalf("OutputAttackResults returned error: %v", err)
		}
	})

	if !strings.Contains(output, "Command Output:") {
		t.Errorf("expected 'Command Output:' header in output, got:\n%s", output)
	}
	if !strings.Contains(output, "uid=1000(runner) gid=1000(runner)") {
		t.Errorf("expected command output line in output, got:\n%s", output)
	}
	if !strings.Contains(output, "Linux buildhost 5.15.0") {
		t.Errorf("expected command output line in output, got:\n%s", output)
	}
}

func TestOutputAttackResults_TextWithOutputDir(t *testing.T) {
	results := []*attacks.AttackResult{
		{
			Plugin:  "ado-extract-securefiles",
			Success: true,
			Message: "Downloaded 2 files",
			Data: map[string]interface{}{
				"output_dir": "/tmp/securefiles-abc123",
				"file_names": []interface{}{
					"cert.pfx",
					"deploy-key.pem",
				},
			},
		},
	}

	output := captureStdout(t, func() {
		err := OutputAttackResults("text", results, "ghi789", "trajan ado attack cleanup")
		if err != nil {
			t.Fatalf("OutputAttackResults returned error: %v", err)
		}
	})

	if !strings.Contains(output, "Extracted Files: /tmp/securefiles-abc123") {
		t.Errorf("expected 'Extracted Files:' with path in output, got:\n%s", output)
	}
	if !strings.Contains(output, "- cert.pfx") {
		t.Errorf("expected filename 'cert.pfx' in output, got:\n%s", output)
	}
	if !strings.Contains(output, "- deploy-key.pem") {
		t.Errorf("expected filename 'deploy-key.pem' in output, got:\n%s", output)
	}
}

func TestOutputAttackResults_TextNoData(t *testing.T) {
	results := []*attacks.AttackResult{
		{
			Plugin:  "ado-persistence",
			Success: false,
			Message: "Attack failed",
			Data:    nil,
		},
	}

	output := captureStdout(t, func() {
		err := OutputAttackResults("text", results, "jkl012", "trajan ado attack cleanup")
		if err != nil {
			t.Fatalf("OutputAttackResults returned error: %v", err)
		}
	})

	if !strings.Contains(output, "[FAILED] ado-persistence") {
		t.Errorf("expected '[FAILED] ado-persistence' in output, got:\n%s", output)
	}
	// Should not contain any data sections
	if strings.Contains(output, "Extracted Credentials:") {
		t.Errorf("unexpected 'Extracted Credentials:' in output for nil Data, got:\n%s", output)
	}
	if strings.Contains(output, "Command Output:") {
		t.Errorf("unexpected 'Command Output:' in output for nil Data, got:\n%s", output)
	}
	if strings.Contains(output, "Extracted Files:") {
		t.Errorf("unexpected 'Extracted Files:' in output for nil Data, got:\n%s", output)
	}
}

func TestOutputAttackResults_TextNoData_Success(t *testing.T) {
	results := []*attacks.AttackResult{
		makeResult(nil),
	}

	output := captureStdout(t, func() {
		err := OutputAttackResults("text", results, "sess-001", "trajan cleanup")
		require.NoError(t, err)
	})

	assert.NotContains(t, output, "Extracted Credentials:")
	// Verify the basic structure is still printed
	assert.Contains(t, output, "[SUCCESS] test-plugin")
	assert.Contains(t, output, "attack completed")
}

func TestOutputAttackResults_TextDataNoSecrets(t *testing.T) {
	results := []*attacks.AttackResult{
		makeResult(map[string]interface{}{
			"other_key": "value",
		}),
	}

	output := captureStdout(t, func() {
		err := OutputAttackResults("text", results, "sess-001", "trajan cleanup")
		require.NoError(t, err)
	})

	assert.NotContains(t, output, "Extracted Credentials:")
	assert.Contains(t, output, "[SUCCESS] test-plugin")
}

func TestOutputAttackResults_TextEmptySecrets(t *testing.T) {
	results := []*attacks.AttackResult{
		makeResult(map[string]interface{}{
			"secrets": []string{},
		}),
	}

	output := captureStdout(t, func() {
		err := OutputAttackResults("text", results, "sess-001", "trajan cleanup")
		require.NoError(t, err)
	})

	assert.NotContains(t, output, "Extracted Credentials:")
}

func TestOutputAttackResults_JSONWithSecrets(t *testing.T) {
	results := []*attacks.AttackResult{
		makeResult(map[string]interface{}{
			"secrets": []string{"TOKEN=abc123"},
		}),
	}

	output := captureStdout(t, func() {
		err := OutputAttackResults("json", results, "sess-001", "trajan cleanup")
		require.NoError(t, err)
	})

	// Parse the JSON output
	var parsed map[string]interface{}
	err := json.Unmarshal([]byte(output), &parsed)
	require.NoError(t, err, "output should be valid JSON: %s", output)

	// Verify session_id
	assert.Equal(t, "sess-001", parsed["session_id"])

	// Verify results array
	resultsArr, ok := parsed["results"].([]interface{})
	require.True(t, ok, "results should be an array")
	require.Len(t, resultsArr, 1)

	// Verify the first result contains data with secrets
	firstResult, ok := resultsArr[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, firstResult["success"])
	assert.Equal(t, "test-plugin", firstResult["plugin"])

	data, ok := firstResult["data"].(map[string]interface{})
	require.True(t, ok, "data should be a map")

	secrets, ok := data["secrets"].([]interface{})
	require.True(t, ok, "secrets should be an array")
	require.Len(t, secrets, 1)
	assert.Equal(t, "TOKEN=abc123", secrets[0])
}

func TestWriteExtractedDataToFile(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "extracted.txt")

	results := []*attacks.AttackResult{
		{
			Plugin:  "ado-secrets-dump",
			Success: true,
			Message: "Extracted secrets",
			Data: map[string]interface{}{
				"secrets": []string{
					"SECRET_A=value1",
					"SECRET_B=value2",
				},
			},
		},
		{
			Plugin:  "ado-agent-exec",
			Success: true,
			Message: "Command executed",
			Data: map[string]interface{}{
				"output": []string{
					"whoami output",
				},
			},
		},
	}

	if err := WriteExtractedDataToFile(outPath, results); err != nil {
		t.Fatalf("WriteExtractedDataToFile returned error: %v", err)
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	fileContent := string(content)
	if !strings.Contains(fileContent, "SECRET_A=value1") {
		t.Errorf("expected 'SECRET_A=value1' in file, got:\n%s", fileContent)
	}
	if !strings.Contains(fileContent, "SECRET_B=value2") {
		t.Errorf("expected 'SECRET_B=value2' in file, got:\n%s", fileContent)
	}
	if !strings.Contains(fileContent, "whoami output") {
		t.Errorf("expected 'whoami output' in file, got:\n%s", fileContent)
	}

	// Verify each entry is on its own line
	lines := strings.Split(strings.TrimSpace(fileContent), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines in output file, got %d: %v", len(lines), lines)
	}
}

func TestPrintExtractedData(t *testing.T) {
	tests := []struct {
		name     string
		data     interface{}
		contains []string
		excludes []string
	}{
		{
			name:     "nil data",
			data:     nil,
			contains: nil,
			excludes: []string{"Extracted Credentials:", "Command Output:", "Extracted Files:"},
		},
		{
			name:     "non-map data",
			data:     "unexpected string",
			contains: nil,
			excludes: []string{"Extracted Credentials:", "Command Output:", "Extracted Files:"},
		},
		{
			name:     "empty map",
			data:     map[string]interface{}{},
			excludes: []string{"Extracted Credentials:", "Command Output:", "Extracted Files:"},
		},
		{
			name: "secrets only",
			data: map[string]interface{}{
				"secrets": []interface{}{"KEY=val"},
			},
			contains: []string{"Extracted Credentials:", "KEY=val"},
			excludes: []string{"Command Output:", "Extracted Files:"},
		},
		{
			name: "secrets as []string",
			data: map[string]interface{}{
				"secrets": []string{"KEY=val"},
			},
			contains: []string{"Extracted Credentials:", "KEY=val"},
			excludes: []string{"Command Output:", "Extracted Files:"},
		},
		{
			name: "output as []string",
			data: map[string]interface{}{
				"output": []string{"hello world"},
			},
			contains: []string{"Command Output:", "hello world"},
			excludes: []string{"Extracted Credentials:", "Extracted Files:"},
		},
		{
			name: "file_names as []string",
			data: map[string]interface{}{
				"output_dir": "/tmp/files",
				"file_names": []string{"a.txt", "b.txt"},
			},
			contains: []string{"Extracted Files: /tmp/files", "- a.txt", "- b.txt"},
			excludes: []string{"Extracted Credentials:", "Command Output:"},
		},
		{
			name: "output only",
			data: map[string]interface{}{
				"output": []interface{}{"hello world"},
			},
			contains: []string{"Command Output:", "hello world"},
			excludes: []string{"Extracted Credentials:", "Extracted Files:"},
		},
		{
			name: "output_dir with file_names",
			data: map[string]interface{}{
				"output_dir": "/tmp/files",
				"file_names": []interface{}{"a.txt", "b.txt"},
			},
			contains: []string{"Extracted Files: /tmp/files", "- a.txt", "- b.txt"},
			excludes: []string{"Extracted Credentials:", "Command Output:"},
		},
		{
			name: "output_dir without file_names",
			data: map[string]interface{}{
				"output_dir": "/tmp/nofiles",
			},
			contains: []string{"Extracted Files: /tmp/nofiles"},
			excludes: []string{"Extracted Credentials:", "Command Output:"},
		},
		{
			name: "empty secrets slice",
			data: map[string]interface{}{
				"secrets": []interface{}{},
			},
			excludes: []string{"Extracted Credentials:"},
		},
		{
			name: "all data types together",
			data: map[string]interface{}{
				"secrets":    []interface{}{"A=1"},
				"output":     []interface{}{"line1"},
				"output_dir": "/out",
				"file_names": []interface{}{"f.txt"},
			},
			contains: []string{"Extracted Credentials:", "A=1", "Command Output:", "line1", "Extracted Files: /out", "- f.txt"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output := captureStdout(t, func() {
				printExtractedData(tc.data)
			})

			for _, want := range tc.contains {
				if !strings.Contains(output, want) {
					t.Errorf("expected %q in output, got:\n%s", want, output)
				}
			}
			for _, unwanted := range tc.excludes {
				if strings.Contains(output, unwanted) {
					t.Errorf("unexpected %q in output, got:\n%s", unwanted, output)
				}
			}
		})
	}
}
