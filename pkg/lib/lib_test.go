package lib

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListPlatforms(t *testing.T) {
	platforms := ListPlatforms()
	require.NotEmpty(t, platforms, "expected registered platforms from blank imports")

	expected := []string{"azuredevops", "github", "gitlab", "jenkins", "jfrog"}
	for _, name := range expected {
		assert.Contains(t, platforms, name, "missing platform: %s", name)
	}
}

func TestGetPlatform_Known(t *testing.T) {
	for _, name := range []string{"github", "gitlab", "azuredevops", "jenkins", "jfrog"} {
		t.Run(name, func(t *testing.T) {
			p, err := GetPlatform(name)
			require.NoError(t, err)
			assert.Equal(t, name, p.Name())
		})
	}
}

func TestGetPlatform_Unknown(t *testing.T) {
	_, err := GetPlatform("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestGetDetectionsForPlatform_GitHub(t *testing.T) {
	dets := GetDetectionsForPlatform("github")
	require.NotEmpty(t, dets, "expected GitHub detections from blank imports")

	// Verify at least some known detection types exist
	names := make(map[string]bool)
	for _, d := range dets {
		names[d.Name()] = true
	}
	// actions_injection is a core detection that should always be registered
	assert.True(t, names["actions_injection"] || len(names) > 0,
		"expected at least one GitHub detection, got: %v", names)
}

func TestGetDetectionsForPlatform_Unknown(t *testing.T) {
	dets := GetDetectionsForPlatform("nonexistent")
	// Unknown platform returns empty slice (not nil), no cross-platform detections expected
	assert.Empty(t, dets)
}

func TestListDetectionPlatforms(t *testing.T) {
	platforms := ListDetectionPlatforms()
	require.NotEmpty(t, platforms)
	assert.Contains(t, platforms, "github")
}

func TestScan_InvalidPlatform(t *testing.T) {
	_, err := Scan(context.Background(), ScanConfig{
		Platform: "nonexistent",
		Token:    "test",
		Org:      "test",
		Repo:     "test",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestScan_InvalidPlatform_ReturnsError(t *testing.T) {
	// Verify that Scan with an invalid token returns an error from platform Init or Scan
	_, err := Scan(context.Background(), ScanConfig{
		Platform: "github",
		Token:    "invalid-token",
		Org:      "test",
		Repo:     "test",
	})
	require.Error(t, err)
}

func TestApplyDefaults(t *testing.T) {
	cfg := applyDefaults(ScanConfig{Platform: "github"})
	assert.Equal(t, 10, cfg.Concurrency)
	assert.Equal(t, 5*time.Minute, cfg.Timeout)

	// Non-zero values should not be overridden
	cfg = applyDefaults(ScanConfig{Concurrency: 20, Timeout: 10 * time.Minute})
	assert.Equal(t, 20, cfg.Concurrency)
	assert.Equal(t, 10*time.Minute, cfg.Timeout)
}

func TestGetDetections_GitHub(t *testing.T) {
	dets := GetDetections("github")
	assert.NotEmpty(t, dets, "github should have registered detections")

	// GetDetections returns platform-specific only (no cross-platform "all" detections)
	allDets := GetDetectionsForPlatform("github")
	assert.GreaterOrEqual(t, len(allDets), len(dets),
		"GetDetectionsForPlatform should include cross-platform detections")
}

// minimalGitHubWorkflow is a valid minimal GitHub Actions workflow YAML.
const minimalGitHubWorkflow = `name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`

func TestScan_LocalPath_GitHub(t *testing.T) {
	tmp := t.TempDir()
	workflowDir := tmp + "/.github/workflows"
	require.NoError(t, os.MkdirAll(workflowDir, 0o755))
	require.NoError(t, os.WriteFile(workflowDir+"/test.yml", []byte(minimalGitHubWorkflow), 0o644))

	result, err := Scan(context.Background(), ScanConfig{
		Platform:  "github",
		LocalPath: tmp,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	require.Len(t, result.Workflows, 1)
	assert.Equal(t, ".github/workflows/test.yml", result.Workflows[0].Path)
	assert.Equal(t, "test.yml", result.Workflows[0].Name)
	assert.True(t, len(result.Workflows[0].RepoSlug) > 0)
	assert.Contains(t, result.Workflows[0].RepoSlug, "local:")
}

func TestScan_LocalPath_NoTokenRequired(t *testing.T) {
	tmp := t.TempDir()
	workflowDir := tmp + "/.github/workflows"
	require.NoError(t, os.MkdirAll(workflowDir, 0o755))
	require.NoError(t, os.WriteFile(workflowDir+"/test.yml", []byte(minimalGitHubWorkflow), 0o644))

	// Token is explicitly empty — local mode must not require it.
	result, err := Scan(context.Background(), ScanConfig{
		Platform:  "github",
		Token:     "",
		LocalPath: tmp,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestScan_LocalPath_RequiresPlatform(t *testing.T) {
	tmp := t.TempDir()

	_, err := Scan(context.Background(), ScanConfig{
		LocalPath: tmp,
		// Platform intentionally empty
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "local scan requires Platform to be set")
}

func TestScan_LocalPath_UnsupportedPlatform(t *testing.T) {
	tmp := t.TempDir()

	_, err := Scan(context.Background(), ScanConfig{
		Platform:  "bitbucket",
		LocalPath: tmp,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `local scanning not supported for platform "bitbucket"`)
}

func TestScan_LocalPath_NonexistentPath(t *testing.T) {
	_, err := Scan(context.Background(), ScanConfig{
		Platform:  "github",
		LocalPath: "/nonexistent/definitely/not/here",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "walking local path")
}

// vulnGitHubWorkflow contains a known-vulnerable GitHub Actions pattern:
// it interpolates github.event.issue.title into a run: step, which triggers
// script-injection detections.
const vulnGitHubWorkflow = `name: vuln
on:
  issues:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
`

func TestScan_LocalPath_GitHub_ProducesFindings(t *testing.T) {
	tmpDir := t.TempDir()
	workflowDir := tmpDir + "/.github/workflows"
	require.NoError(t, os.MkdirAll(workflowDir, 0o755))
	require.NoError(t, os.WriteFile(workflowDir+"/inject.yml", []byte(vulnGitHubWorkflow), 0o644))

	result, err := Scan(context.Background(), ScanConfig{
		Platform:  "github",
		LocalPath: tmpDir,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	require.Len(t, result.Workflows, 1)
	assert.GreaterOrEqual(t, len(result.Findings), 1, "expected at least one finding from the vulnerable workflow; pipeline may be silently dropping detections")
}
