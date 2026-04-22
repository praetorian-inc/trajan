package local_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/local"
	"github.com/praetorian-inc/trajan/pkg/platforms"

	// Belt-and-suspenders: ensure all parser init() functions have run.
	_ "github.com/praetorian-inc/trajan/pkg/analysis/parser"
)

// YAML fixtures — must match the CanParse expectations of each parser.
const githubYAML = `name: ci
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`

const gitlabYAML = `test:
  script:
    - echo hi
`

const jenkinsfile = `pipeline { agent any; stages { stage('test') { steps { sh 'echo hi' } } } }
`

const azureYAML = `trigger: [main]
jobs:
  - job: test
    steps:
      - script: echo hi
`

// writeFile creates all required parent directories and writes content to path.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// newInitialized creates a Platform, calls Init, and returns it ready to use.
func newInitialized(t *testing.T) *local.Platform {
	t.Helper()
	p := local.NewPlatform()
	require.NoError(t, p.Init(context.Background(), platforms.Config{}))
	return p
}

// TestPlatform_Name asserts that Name() returns "local".
func TestPlatform_Name(t *testing.T) {
	p := local.NewPlatform()
	assert.Equal(t, "local", p.Name())
}

// TestPlatform_Scan_GitHubWorkflow verifies a GitHub Actions workflow is detected.
func TestPlatform_Scan_GitHubWorkflow(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, ".github", "workflows", "ci.yml"), githubYAML)

	p := newInitialized(t)
	result, err := p.Scan(context.Background(), platforms.Target{
		Type:  platforms.TargetLocal,
		Value: tmp,
	})

	require.NoError(t, err)
	assert.Len(t, result.Workflows, 1, "expected exactly one platform bucket")

	wfs, ok := result.Workflows["local:github"]
	require.True(t, ok, "bucket 'local:github' not found")
	require.Len(t, wfs, 1)

	wf := wfs[0]
	assert.Equal(t, "ci.yml", wf.Name)
	assert.Equal(t, ".github/workflows/ci.yml", wf.Path)
	assert.NotEmpty(t, wf.Content)
	assert.Equal(t, "local:github", wf.RepoSlug)
	assert.Equal(t, "github", wf.Metadata["platform"])
}

// TestPlatform_Scan_GitLabCI verifies a GitLab CI workflow is detected.
func TestPlatform_Scan_GitLabCI(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, ".gitlab-ci.yml"), gitlabYAML)

	p := newInitialized(t)
	result, err := p.Scan(context.Background(), platforms.Target{
		Type:  platforms.TargetLocal,
		Value: tmp,
	})

	require.NoError(t, err)
	wfs, ok := result.Workflows["local:gitlab"]
	require.True(t, ok, "bucket 'local:gitlab' not found")
	require.Len(t, wfs, 1)
	assert.Equal(t, "gitlab", wfs[0].Metadata["platform"])
}

// TestPlatform_Scan_Jenkinsfile verifies a Jenkinsfile is detected.
func TestPlatform_Scan_Jenkinsfile(t *testing.T) {
	tmp := t.TempDir()
	// Jenkinsfile must be exactly "Jenkinsfile" at the root for CanParse("Jenkinsfile") to match.
	writeFile(t, filepath.Join(tmp, "Jenkinsfile"), jenkinsfile)

	p := newInitialized(t)
	result, err := p.Scan(context.Background(), platforms.Target{
		Type:  platforms.TargetLocal,
		Value: tmp,
	})

	require.NoError(t, err)
	wfs, ok := result.Workflows["local:jenkins"]
	require.True(t, ok, "bucket 'local:jenkins' not found")
	require.Len(t, wfs, 1)
	assert.Equal(t, "jenkins", wfs[0].Metadata["platform"])
}

// TestPlatform_Scan_AzurePipelines verifies an Azure Pipelines workflow is detected.
func TestPlatform_Scan_AzurePipelines(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "azure-pipelines.yml"), azureYAML)

	p := newInitialized(t)
	result, err := p.Scan(context.Background(), platforms.Target{
		Type:  platforms.TargetLocal,
		Value: tmp,
	})

	require.NoError(t, err)
	wfs, ok := result.Workflows["local:azure"]
	require.True(t, ok, "bucket 'local:azure' not found")
	require.Len(t, wfs, 1)
	assert.Equal(t, "azure", wfs[0].Metadata["platform"])
}

// TestPlatform_Scan_MixedPlatforms verifies that workflows from multiple platforms
// are grouped into separate buckets, and exactly one Repository is returned.
func TestPlatform_Scan_MixedPlatforms(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, ".github", "workflows", "a.yml"), githubYAML)
	writeFile(t, filepath.Join(tmp, ".gitlab-ci.yml"), gitlabYAML)
	writeFile(t, filepath.Join(tmp, "Jenkinsfile"), jenkinsfile)

	p := newInitialized(t)
	result, err := p.Scan(context.Background(), platforms.Target{
		Type:  platforms.TargetLocal,
		Value: tmp,
	})

	require.NoError(t, err)

	_, hasGitHub := result.Workflows["local:github"]
	_, hasGitLab := result.Workflows["local:gitlab"]
	_, hasJenkins := result.Workflows["local:jenkins"]
	assert.True(t, hasGitHub, "expected bucket 'local:github'")
	assert.True(t, hasGitLab, "expected bucket 'local:gitlab'")
	assert.True(t, hasJenkins, "expected bucket 'local:jenkins'")
	assert.Len(t, result.Workflows["local:github"], 1)
	assert.Len(t, result.Workflows["local:gitlab"], 1)
	assert.Len(t, result.Workflows["local:jenkins"], 1)

	assert.Len(t, result.Repositories, 1, "expected exactly one repository entry")
}

// TestPlatform_Scan_SkipsNonWorkflowFiles verifies that non-workflow files produce
// no workflows and no errors.
func TestPlatform_Scan_SkipsNonWorkflowFiles(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "README.md"), "# readme\n")
	writeFile(t, filepath.Join(tmp, "src", "app.go"), "package main\n")
	writeFile(t, filepath.Join(tmp, ".github", "CODEOWNERS"), "* @owner\n")

	p := newInitialized(t)
	result, err := p.Scan(context.Background(), platforms.Target{
		Type:  platforms.TargetLocal,
		Value: tmp,
	})

	require.NoError(t, err)
	assert.Empty(t, result.Workflows, "expected no workflows for non-workflow files")
	assert.Empty(t, result.Errors)
}

// TestPlatform_Scan_SkipsGitDir verifies that the walker skips the .git directory
// entirely and still finds real workflow files at other paths.
func TestPlatform_Scan_SkipsGitDir(t *testing.T) {
	tmp := t.TempDir()
	// Real workflow file.
	writeFile(t, filepath.Join(tmp, ".github", "workflows", "ci.yml"), githubYAML)
	// Files inside .git — these must be skipped entirely.
	writeFile(t, filepath.Join(tmp, ".git", "HEAD"), "ref: refs/heads/main\n")
	writeFile(t, filepath.Join(tmp, ".git", "objects", "pack.yml"), "not a real workflow\n")

	p := newInitialized(t)
	result, err := p.Scan(context.Background(), platforms.Target{
		Type:  platforms.TargetLocal,
		Value: tmp,
	})

	require.NoError(t, err)
	total := 0
	for _, wfs := range result.Workflows {
		total += len(wfs)
	}
	assert.Equal(t, 1, total, "expected exactly 1 workflow (the .github/workflows/ci.yml)")

	wfs, ok := result.Workflows["local:github"]
	require.True(t, ok)
	assert.Equal(t, ".github/workflows/ci.yml", wfs[0].Path)
}

// TestPlatform_Scan_SkipsNodeModulesAndVendor verifies that node_modules and vendor
// directories are skipped, while a top-level workflow file is still detected.
func TestPlatform_Scan_SkipsNodeModulesAndVendor(t *testing.T) {
	tmp := t.TempDir()
	// Files that MUST be skipped.
	writeFile(t, filepath.Join(tmp, "node_modules", "pkg", ".github", "workflows", "x.yml"), githubYAML)
	writeFile(t, filepath.Join(tmp, "vendor", "somepkg", ".gitlab-ci.yml"), gitlabYAML)
	// The one file that should be found.
	writeFile(t, filepath.Join(tmp, ".gitlab-ci.yml"), gitlabYAML)

	p := newInitialized(t)
	result, err := p.Scan(context.Background(), platforms.Target{
		Type:  platforms.TargetLocal,
		Value: tmp,
	})

	require.NoError(t, err)
	total := 0
	for _, wfs := range result.Workflows {
		total += len(wfs)
	}
	assert.Equal(t, 1, total, "expected only the top-level .gitlab-ci.yml to be found")
}

// TestPlatform_Scan_SingleFile verifies scanning a single workflow file directly
// (not a directory).
func TestPlatform_Scan_SingleFile(t *testing.T) {
	tmp := t.TempDir()
	filePath := filepath.Join(tmp, ".gitlab-ci.yml")
	writeFile(t, filePath, gitlabYAML)

	p := newInitialized(t)
	result, err := p.Scan(context.Background(), platforms.Target{
		Type:  platforms.TargetLocal,
		Value: filePath,
	})

	require.NoError(t, err)
	wfs, ok := result.Workflows["local:gitlab"]
	require.True(t, ok, "bucket 'local:gitlab' not found")
	require.Len(t, wfs, 1)
	// For a single-file target, Path is filepath.Base (just the filename).
	assert.Equal(t, ".gitlab-ci.yml", wfs[0].Path)
}

// TestPlatform_Scan_NonexistentPath verifies that scanning a path that does not
// exist returns an error.
func TestPlatform_Scan_NonexistentPath(t *testing.T) {
	p := newInitialized(t)
	_, err := p.Scan(context.Background(), platforms.Target{
		Type:  platforms.TargetLocal,
		Value: "/nonexistent/does/not/exist",
	})
	require.Error(t, err)
}

// TestPlatform_Scan_InvalidTargetType verifies that a non-TargetLocal target type
// returns an error containing the expected message.
func TestPlatform_Scan_InvalidTargetType(t *testing.T) {
	tmp := t.TempDir()
	p := newInitialized(t)
	_, err := p.Scan(context.Background(), platforms.Target{
		Type:  platforms.TargetRepo,
		Value: tmp,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported target type for local")
}

// TestPlatform_Scan_RelativePath verifies that a relative path is resolved correctly
// by filepath.Abs inside Scan.
func TestPlatform_Scan_RelativePath(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, ".gitlab-ci.yml"), gitlabYAML)

	// t.Chdir changes cwd and restores it via t.Cleanup (Go 1.24+).
	t.Chdir(tmp)

	p := newInitialized(t)
	result, err := p.Scan(context.Background(), platforms.Target{
		Type:  platforms.TargetLocal,
		Value: "./",
	})

	require.NoError(t, err)
	wfs, ok := result.Workflows["local:gitlab"]
	require.True(t, ok, "bucket 'local:gitlab' not found")
	assert.Len(t, wfs, 1)
}
