package cmdutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Side-effect imports populate the detection and platform registries.
	_ "github.com/praetorian-inc/trajan/pkg/detections/all"
	_ "github.com/praetorian-inc/trajan/pkg/platforms/all"
)

// vulnWorkflow is a known-vulnerable GitHub Actions workflow that interpolates
// a user-controlled value into a run: step, triggering script-injection detections.
const vulnWorkflow = `name: vuln
on:
  issues:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
`

// writeVulnGitHubWorkflow creates a temp directory containing a vulnerable
// GitHub Actions workflow at the canonical .github/workflows/ci.yml path and
// returns the root directory path.
func writeVulnGitHubWorkflow(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, ".github", "workflows", "ci.yml")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(vulnWorkflow), 0o644))
	return root
}

// TestRunLocalScan_HappyPath_VulnWorkflow verifies that scanning a directory
// containing a vulnerable GitHub Actions workflow produces at least one finding.
func TestRunLocalScan_HappyPath_VulnWorkflow(t *testing.T) {
	root := writeVulnGitHubWorkflow(t)

	silenceStderr(t)

	// Capture stdout (console output) to keep test output clean.
	out := captureStdout(t, func() {
		err := RunLocalScan(LocalScanConfig{
			Platform:      "github",
			Path:          root,
			Concurrency:   4,
			WorkflowLabel: "GitHub workflow",
		})
		require.NoError(t, err)
	})

	// The vulnerable workflow must produce at least one finding visible in output.
	assert.NotEmpty(t, out, "expected console output with findings")
}

// TestRunLocalScan_SeverityFilter verifies that the --severity flag narrows
// findings: passing an unlikely severity level produces no findings line.
func TestRunLocalScan_SeverityFilter(t *testing.T) {
	root := writeVulnGitHubWorkflow(t)

	silenceStderr(t)

	// "info" is typically the lowest severity; passing only "info" on a workflow
	// that fires critical/high detections should result in zero reported findings.
	out := captureStdout(t, func() {
		err := RunLocalScan(LocalScanConfig{
			Platform:      "github",
			Path:          root,
			Concurrency:   4,
			Severity:      "info",
			Output:        "json",
			WorkflowLabel: "GitHub workflow",
		})
		require.NoError(t, err)
	})

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &parsed))
	summary, ok := parsed["summary"].(map[string]any)
	require.True(t, ok, "json must have summary object")
	assert.Equal(t, float64(0), summary["findings"], "filter should narrow findings to zero")
}

// TestRunLocalScan_CapabilitiesFilter verifies that an unknown capabilities
// spec produces an empty findings set without error.
func TestRunLocalScan_CapabilitiesFilter(t *testing.T) {
	root := writeVulnGitHubWorkflow(t)

	silenceStderr(t)

	out := captureStdout(t, func() {
		err := RunLocalScan(LocalScanConfig{
			Platform:         "github",
			Path:             root,
			Concurrency:      4,
			Capabilities:     "nonexistent_capability_xyz",
			CapabilityFilter: FilterFindingsByCapabilities,
			Output:           "json",
			WorkflowLabel:    "GitHub workflow",
		})
		require.NoError(t, err)
	})

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &parsed))
	summary, ok := parsed["summary"].(map[string]any)
	require.True(t, ok, "json must have summary object")
	assert.Equal(t, float64(0), summary["findings"], "filter should narrow findings to zero")
}

// TestRunLocalScan_OutputJSON verifies that --output json produces parseable
// JSON on stdout containing a "findings" key.
func TestRunLocalScan_OutputJSON(t *testing.T) {
	root := writeVulnGitHubWorkflow(t)

	silenceStderr(t)

	out := captureStdout(t, func() {
		err := RunLocalScan(LocalScanConfig{
			Platform:      "github",
			Path:          root,
			Concurrency:   4,
			Output:        "json",
			WorkflowLabel: "GitHub workflow",
		})
		require.NoError(t, err)
	})

	require.NotEmpty(t, out, "expected JSON output on stdout")

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(out), &parsed), "stdout should be valid JSON: %s", out)

	// The JSON output from OutputFindingsJSON must contain a "findings" key.
	assert.Contains(t, parsed, "findings", "JSON output should contain a 'findings' key")
}

// TestRunLocalScan_UnsupportedPlatform verifies that passing an unsupported
// platform name returns a wrapped error.
func TestRunLocalScan_UnsupportedPlatform(t *testing.T) {
	root := t.TempDir()

	silenceStderr(t)

	err := RunLocalScan(LocalScanConfig{
		Platform:      "bitbucket",
		Path:          root,
		Concurrency:   4,
		WorkflowLabel: "workflow",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "bitbucket")
}

// silenceStderr redirects os.Stderr to /dev/null for the duration of the test
// so that RunLocalScan progress lines don't pollute test output.
func silenceStderr(t *testing.T) {
	t.Helper()
	old := os.Stderr
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		// If we can't open /dev/null, just leave stderr alone.
		return
	}
	os.Stderr = devNull
	t.Cleanup(func() {
		devNull.Close()
		os.Stderr = old
	})
}
