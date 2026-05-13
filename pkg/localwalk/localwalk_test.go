package localwalk

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// createFile creates a file at the given path, creating all parent directories.
func createFile(t *testing.T, path string, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func TestSupportedPlatforms_ReturnsSorted(t *testing.T) {
	got := SupportedPlatforms()
	want := []string{
		platforms.PlatformAzureDevOps,
		platforms.PlatformGitHub,
		platforms.PlatformGitLab,
		platforms.PlatformJenkins,
	}
	assert.Equal(t, want, got)
}

func TestIsSupported(t *testing.T) {
	tests := []struct {
		platform string
		want     bool
	}{
		{platforms.PlatformGitHub, true},
		{platforms.PlatformGitLab, true},
		{platforms.PlatformAzureDevOps, true},
		{platforms.PlatformJenkins, true},
		{"bitbucket", false},
		{"jfrog", false},
		{"", false},
		{"unknown", false},
	}
	for _, tc := range tests {
		t.Run(tc.platform, func(t *testing.T) {
			assert.Equal(t, tc.want, IsSupported(tc.platform))
		})
	}
}

func TestWalk_UnsupportedPlatform(t *testing.T) {
	tmp := t.TempDir()
	_, err := Walk("bitbucket", tmp, "slug")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `local scanning not supported for platform "bitbucket"`)
}

func TestWalk_NonexistentPath(t *testing.T) {
	_, err := Walk(platforms.PlatformGitHub, "/nonexistent/path/definitely/not/here", "slug")
	require.Error(t, err)
}

func TestWalk_SingleFile_TrustsCallerPlatform(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "random-name.txt")
	content := "name: ci\non: [push]\n"
	createFile(t, file, content)

	workflows, err := Walk(platforms.PlatformGitHub, file, "slug")
	require.NoError(t, err)
	require.Len(t, workflows, 1)

	wf := workflows[0]
	assert.Equal(t, "random-name.txt", wf.Name)
	assert.Equal(t, "random-name.txt", wf.Path)
	assert.Equal(t, "slug", wf.RepoSlug)
}

func TestWalk_Directory_GitHub_MatchesAndSkipsDirs(t *testing.T) {
	root := t.TempDir()

	// Should be included
	createFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"), "")
	createFile(t, filepath.Join(root, ".github", "workflows", "sub", "x.yaml"), "")

	// Should be excluded (not under workflows/)
	createFile(t, filepath.Join(root, ".github", "other.yml"), "")

	// Should be excluded (wrong extension)
	createFile(t, filepath.Join(root, "README.md"), "")

	// Should be skipped (skip dir .git)
	createFile(t, filepath.Join(root, ".git", "HEAD"), "ref: refs/heads/main")

	// Should be skipped (skip dir node_modules)
	createFile(t, filepath.Join(root, "node_modules", ".github", "workflows", "sneaky.yml"), "")

	// Should be skipped (skip dir vendor)
	createFile(t, filepath.Join(root, "vendor", "x", ".github", "workflows", "v.yml"), "")

	workflows, err := Walk(platforms.PlatformGitHub, root, "my-slug")
	require.NoError(t, err)
	require.Len(t, workflows, 2)

	assert.Equal(t, ".github/workflows/ci.yml", workflows[0].Path)
	assert.Equal(t, ".github/workflows/sub/x.yaml", workflows[1].Path)
	assert.Equal(t, "my-slug", workflows[0].RepoSlug)
	assert.Equal(t, "my-slug", workflows[1].RepoSlug)
}

func TestWalk_Directory_GitLab(t *testing.T) {
	root := t.TempDir()

	// Should be included
	createFile(t, filepath.Join(root, ".gitlab-ci.yml"), "")
	createFile(t, filepath.Join(root, "sub", ".gitlab-ci.yaml"), "")

	// Should be excluded
	createFile(t, filepath.Join(root, "pipeline.yml"), "")
	createFile(t, filepath.Join(root, "sub", "other-ci.yml"), "")

	workflows, err := Walk(platforms.PlatformGitLab, root, "gl-slug")
	require.NoError(t, err)
	require.Len(t, workflows, 2)

	paths := []string{workflows[0].Path, workflows[1].Path}
	assert.Contains(t, paths, ".gitlab-ci.yml")
	assert.Contains(t, paths, "sub/.gitlab-ci.yaml")
}

func TestWalk_Directory_AzureDevOps(t *testing.T) {
	root := t.TempDir()

	// Should be included
	createFile(t, filepath.Join(root, "azure-pipelines.yml"), "")
	createFile(t, filepath.Join(root, "services", "api.azure-pipelines.yaml"), "")
	createFile(t, filepath.Join(root, ".azure-pipelines", "build.yml"), "")
	createFile(t, filepath.Join(root, ".azure-pipelines", "sub", "deploy.yaml"), "")

	// Should be excluded
	createFile(t, filepath.Join(root, "azure-other.yml"), "")

	workflows, err := Walk(platforms.PlatformAzureDevOps, root, "az-slug")
	require.NoError(t, err)
	require.Len(t, workflows, 4)

	paths := make([]string, len(workflows))
	for i, wf := range workflows {
		paths[i] = wf.Path
	}
	assert.Contains(t, paths, "azure-pipelines.yml")
	assert.Contains(t, paths, "services/api.azure-pipelines.yaml")
	assert.Contains(t, paths, ".azure-pipelines/build.yml")
	assert.Contains(t, paths, ".azure-pipelines/sub/deploy.yaml")
	assert.NotContains(t, paths, "azure-other.yml")
}

func TestWalk_Directory_Jenkins(t *testing.T) {
	root := t.TempDir()

	// Should be included
	createFile(t, filepath.Join(root, "Jenkinsfile"), "")
	createFile(t, filepath.Join(root, "services", "Jenkinsfile.prod"), "")
	// Use separate directories to avoid case-insensitive filesystem collision
	// on macOS (build.jenkinsfile vs BUILD.JENKINSFILE would resolve to same inode).
	createFile(t, filepath.Join(root, "legacy", "build.jenkinsfile"), "")
	createFile(t, filepath.Join(root, "LEGACY_UPPER", "BUILD.JENKINSFILE"), "")
	createFile(t, filepath.Join(root, "Jenkinsfile.bak"), "")
	// Bare lowercase jenkinsfile in a separate directory to avoid macOS collision.
	createFile(t, filepath.Join(root, "lowercase_bare", "jenkinsfile"), "")

	// Should be excluded (underscore separator, not dot-prefix)
	createFile(t, filepath.Join(root, "Jenkinsfile_old"), "")

	workflows, err := Walk(platforms.PlatformJenkins, root, "jen-slug")
	require.NoError(t, err)
	require.Len(t, workflows, 6)

	paths := make([]string, len(workflows))
	for i, wf := range workflows {
		paths[i] = wf.Path
	}
	assert.Contains(t, paths, "Jenkinsfile")
	assert.Contains(t, paths, "services/Jenkinsfile.prod")
	assert.Contains(t, paths, "legacy/build.jenkinsfile")
	assert.Contains(t, paths, "LEGACY_UPPER/BUILD.JENKINSFILE")
	assert.Contains(t, paths, "Jenkinsfile.bak")
	assert.Contains(t, paths, "lowercase_bare/jenkinsfile")
	assert.NotContains(t, paths, "Jenkinsfile_old")
}

func TestWalk_Directory_StableSortByPath(t *testing.T) {
	root := t.TempDir()

	createFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"), "")
	createFile(t, filepath.Join(root, ".github", "workflows", "sub", "x.yaml"), "")

	first, err := Walk(platforms.PlatformGitHub, root, "slug")
	require.NoError(t, err)

	second, err := Walk(platforms.PlatformGitHub, root, "slug")
	require.NoError(t, err)

	require.Equal(t, len(first), len(second))
	for i := range first {
		assert.Equal(t, first[i].Path, second[i].Path)
		assert.Equal(t, first[i].Name, second[i].Name)
	}
}

func TestWalk_ContentReadCorrectly(t *testing.T) {
	root := t.TempDir()
	content := "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
	createFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"), content)

	workflows, err := Walk(platforms.PlatformGitHub, root, "slug")
	require.NoError(t, err)
	require.Len(t, workflows, 1)

	assert.Equal(t, []byte(content), workflows[0].Content)
}

func TestWalk_Directory_EmptyDir_ReturnsNoWorkflows(t *testing.T) {
	workflows, err := Walk(platforms.PlatformGitHub, t.TempDir(), "slug")
	require.NoError(t, err)
	assert.Empty(t, workflows)
}

func TestWalk_Directory_OnlyNonMatchingFiles_ReturnsNoWorkflows(t *testing.T) {
	root := t.TempDir()
	createFile(t, filepath.Join(root, "README.md"), "# not a workflow")
	createFile(t, filepath.Join(root, "Makefile"), "all:\n\techo hi")
	workflows, err := Walk(platforms.PlatformGitHub, root, "slug")
	require.NoError(t, err)
	assert.Empty(t, workflows)
}

func TestWalk_SingleFile_UnreadableFile_ReturnsError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 0o000 not meaningful on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses permission bits")
	}
	tmp := t.TempDir()
	file := filepath.Join(tmp, "ci.yml")
	require.NoError(t, os.WriteFile(file, []byte("name: ci\n"), 0o644))
	require.NoError(t, os.Chmod(file, 0o000))
	t.Cleanup(func() { _ = os.Chmod(file, 0o644) }) // restore so t.TempDir cleanup works

	workflows, err := Walk(platforms.PlatformGitHub, file, "slug")
	require.Error(t, err)
	assert.Nil(t, workflows)
	assert.Contains(t, err.Error(), "reading")
}

func TestWalk_Directory_SkipsOversizedFiles(t *testing.T) {
	root := t.TempDir()

	// Normal workflow file — should be included.
	createFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"), "name: ci\n")

	// Oversized file — should be skipped.
	oversized := filepath.Join(root, ".github", "workflows", "big.yml")
	require.NoError(t, os.MkdirAll(filepath.Dir(oversized), 0o755))
	f, err := os.Create(oversized)
	require.NoError(t, err)
	// Write 11 MB to exceed MaxFileSize (10 MB).
	chunk := make([]byte, 1024*1024)
	for i := 0; i < 11; i++ {
		_, err = f.Write(chunk)
		require.NoError(t, err)
	}
	require.NoError(t, f.Close())

	workflows, err := Walk(platforms.PlatformGitHub, root, "slug")
	require.NoError(t, err)
	require.Len(t, workflows, 1)
	assert.Equal(t, ".github/workflows/ci.yml", workflows[0].Path)
}

func TestWalk_SingleFile_RejectsOversized(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "ci.yml")
	f, err := os.Create(file)
	require.NoError(t, err)
	// Write 11 MB to exceed MaxFileSize (10 MB).
	chunk := make([]byte, 1024*1024)
	for i := 0; i < 11; i++ {
		_, err = f.Write(chunk)
		require.NoError(t, err)
	}
	require.NoError(t, f.Close())

	_, err = Walk(platforms.PlatformGitHub, file, "slug")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "limit")
}

func TestWalk_PathSemantics(t *testing.T) {
	root := t.TempDir()
	createFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"), "name: ci\n")
	file := filepath.Join(root, ".github", "workflows", "ci.yml")

	// Directory mode: Path is relative from root.
	dirWorkflows, err := Walk(platforms.PlatformGitHub, root, "slug")
	require.NoError(t, err)
	require.Len(t, dirWorkflows, 1)
	assert.Equal(t, ".github/workflows/ci.yml", dirWorkflows[0].Path)
	assert.Equal(t, "ci.yml", dirWorkflows[0].Name)

	// Single-file mode: Path is the basename only.
	fileWorkflows, err := Walk(platforms.PlatformGitHub, file, "slug")
	require.NoError(t, err)
	require.Len(t, fileWorkflows, 1)
	assert.Equal(t, "ci.yml", fileWorkflows[0].Path)
	assert.Equal(t, "ci.yml", fileWorkflows[0].Name)
}
