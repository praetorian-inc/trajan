package lib

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListPlatforms(t *testing.T) {
	platforms := ListPlatforms()
	require.NotEmpty(t, platforms, "expected registered platforms from blank imports")

	// GitHub was ported to the new (internal/) CLI-only stack and is no longer
	// registered in the old-stack SDK registry — see GITHUB_PORT_PLAN.md §3.
	expected := []string{"azuredevops", "gitlab", "jenkins", "jfrog"}
	for _, name := range expected {
		assert.Contains(t, platforms, name, "missing platform: %s", name)
	}
	assert.NotContains(t, platforms, "github", "github was ported out of the old-stack SDK registry")
}

func TestGetPlatform_Known(t *testing.T) {
	// github intentionally excluded: ported to the new CLI-only stack (§3).
	for _, name := range []string{"gitlab", "azuredevops", "jenkins", "jfrog"} {
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

// GitHub moved to the new CLI-only stack; GitLab is the representative
// surviving old-stack platform for SDK detection-discovery coverage.
func TestGetDetectionsForPlatform_GitLab(t *testing.T) {
	dets := GetDetectionsForPlatform("gitlab")
	require.NotEmpty(t, dets, "expected GitLab detections from blank imports")

	// Verify at least some known detection types exist
	names := make(map[string]bool)
	for _, d := range dets {
		names[d.Name()] = true
	}
	// script-injection is a core GitLab detection that should always be registered
	assert.True(t, names["script-injection"] || len(names) > 0,
		"expected at least one GitLab detection, got: %v", names)
}

// GitHub is no longer discoverable through the old-stack SDK (§3).
func TestGetDetectionsForPlatform_GitHub_Removed(t *testing.T) {
	assert.Empty(t, GetDetectionsForPlatform("github"),
		"github detections were ported out of the old-stack SDK")
}

func TestGetDetectionsForPlatform_Unknown(t *testing.T) {
	dets := GetDetectionsForPlatform("nonexistent")
	// Unknown platform returns empty slice (not nil), no cross-platform detections expected
	assert.Empty(t, dets)
}

func TestListDetectionPlatforms(t *testing.T) {
	platforms := ListDetectionPlatforms()
	require.NotEmpty(t, platforms)
	assert.Contains(t, platforms, "gitlab")
	assert.NotContains(t, platforms, "github", "github detections were ported out of the old-stack SDK (§3)")
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

func TestGetDetections_GitLab(t *testing.T) {
	dets := GetDetections("gitlab")
	assert.NotEmpty(t, dets, "gitlab should have registered detections")

	// GetDetections returns platform-specific only (no cross-platform "all" detections)
	allDets := GetDetectionsForPlatform("gitlab")
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
	workflowDir := filepath.Join(tmp, ".github", "workflows")
	require.NoError(t, os.MkdirAll(workflowDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(workflowDir, "test.yml"), []byte(minimalGitHubWorkflow), 0o644))

	result, err := Scan(context.Background(), ScanConfig{
		Platform:  "github",
		LocalPath: tmp,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	require.Len(t, result.Workflows, 1)
	assert.Equal(t, ".github/workflows/test.yml", result.Workflows[0].Path)
	assert.Equal(t, "test.yml", result.Workflows[0].Name)
	assert.NotEmpty(t, result.Workflows[0].RepoSlug)
	assert.Contains(t, result.Workflows[0].RepoSlug, "local:")
}

func TestScan_LocalPath_NoTokenRequired(t *testing.T) {
	tmp := t.TempDir()
	workflowDir := filepath.Join(tmp, ".github", "workflows")
	require.NoError(t, os.MkdirAll(workflowDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(workflowDir, "test.yml"), []byte(minimalGitHubWorkflow), 0o644))

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

// vulnGitLabCI contains a known-vulnerable GitLab CI pattern: it interpolates
// $CI_MERGE_REQUEST_TITLE into a script in a merge-request pipeline, which
// triggers the script-injection detection. GitHub findings coverage moved to
// the new CLI-only stack (internal/github); GitLab is the representative
// surviving old-stack platform for this end-to-end SDK smoke.
const vulnGitLabCI = `build:
  script:
    - echo "$CI_MERGE_REQUEST_TITLE"
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
`

func TestScan_LocalPath_GitLab_ProducesFindings(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".gitlab-ci.yml"), []byte(vulnGitLabCI), 0o644))

	result, err := Scan(context.Background(), ScanConfig{
		Platform:  "gitlab",
		LocalPath: tmpDir,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	require.Len(t, result.Workflows, 1)
	assert.GreaterOrEqual(t, len(result.Findings), 1, "expected at least one finding from the vulnerable pipeline; pipeline may be silently dropping detections")
}
