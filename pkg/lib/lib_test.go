package lib

import (
	"context"
	"os"
	"path/filepath"
	"testing"

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

// GitHub is no longer discoverable through the old-stack SDK (§3).
func TestGetDetectionsForPlatform_GitHub_Removed(t *testing.T) {
	assert.Empty(t, GetDetectionsForPlatform("github"),
		"github detections were ported out of the old-stack SDK")
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
