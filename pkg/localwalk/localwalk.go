// Package localwalk walks a local filesystem path and returns workflow files
// matching a given platform's patterns. It is used by the --local flag on scan
// commands to enable scanning locally-cloned repositories without contacting
// any platform API.
package localwalk

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// matcher is a function that reports whether a forward-slash relative path
// (or just a basename for single-file mode) belongs to the platform.
type matcher func(relPath string) bool

// platformMatchers maps each supported platform constant to its file matcher.
var platformMatchers = map[string]matcher{
	platforms.PlatformGitHub: func(relPath string) bool {
		// Must be inside .github/workflows/ and end with .yml or .yaml
		return strings.Contains(relPath, ".github/workflows/") &&
			(strings.HasSuffix(relPath, ".yml") || strings.HasSuffix(relPath, ".yaml"))
	},

	platforms.PlatformGitLab: func(relPath string) bool {
		base := filepath.Base(relPath)
		return base == ".gitlab-ci.yml" || base == ".gitlab-ci.yaml"
	},

	platforms.PlatformAzureDevOps: func(relPath string) bool {
		base := filepath.Base(relPath)
		// Canonical filenames
		if base == "azure-pipelines.yml" || base == "azure-pipelines.yaml" {
			return true
		}
		// Suffix pattern: *.azure-pipelines.yml / *.azure-pipelines.yaml
		if strings.HasSuffix(base, ".azure-pipelines.yml") || strings.HasSuffix(base, ".azure-pipelines.yaml") {
			return true
		}
		// Files inside an .azure-pipelines/ directory
		if strings.Contains(relPath, ".azure-pipelines/") &&
			(strings.HasSuffix(relPath, ".yml") || strings.HasSuffix(relPath, ".yaml")) {
			return true
		}
		return false
	},

	platforms.PlatformJenkins: func(relPath string) bool {
		base := filepath.Base(relPath)
		lower := strings.ToLower(base)
		// Bare Jenkinsfile (exact, case-sensitive)
		if base == "Jenkinsfile" {
			return true
		}
		// Jenkinsfile.* (e.g. Jenkinsfile.prod)
		if strings.HasPrefix(base, "Jenkinsfile.") {
			return true
		}
		// *.jenkinsfile (case-insensitive suffix)
		if strings.HasSuffix(lower, ".jenkinsfile") {
			return true
		}
		return false
	},
}

// SupportedPlatforms returns the sorted list of platforms that support local scanning.
func SupportedPlatforms() []string {
	names := make([]string, 0, len(platformMatchers))
	for k := range platformMatchers {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// IsSupported reports whether the given platform supports local scanning.
func IsSupported(platform string) bool {
	_, ok := platformMatchers[platform]
	return ok
}

// skipDirs contains directory names that Walk always ignores.
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
}

// Walk walks a local filesystem path (file or directory) and returns
// platforms.Workflow entries matching the given platform's file patterns.
//
// For a single file the platform filter is not applied — the caller asserts the
// platform choice and the file is loaded unconditionally.  For directories, only
// files that pass the platform matcher are included.
//
// Unreadable files/directories are skipped silently.  A non-nil error is only
// returned for os.Stat failures on the root path or for a WalkDir failure.
//
// Workflow.Path is the forward-slash relative path from the walk root (or the
// basename in single-file mode).  Workflow.RepoSlug is set to the caller-supplied
// slug.  Workflow.Name is the basename.  Results are stable-sorted by Path.
func Walk(platform, path, repoSlug string) ([]platforms.Workflow, error) {
	if !IsSupported(platform) {
		supported := strings.Join(SupportedPlatforms(), ", ")
		return nil, fmt.Errorf("local scanning not supported for platform %q (supported: %s)", platform, supported)
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		// Single-file mode: trust the caller's platform choice, skip matcher.
		return loadSingleFile(path, repoSlug)
	}

	return walkDir(platform, path, repoSlug)
}

// loadSingleFile reads one file and returns it as a single-element slice.
func loadSingleFile(path, repoSlug string) ([]platforms.Workflow, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		// Treat unreadable single file as empty rather than erroring; the caller
		// already chose this exact path, so a missing-permissions case is not a
		// programming bug worth surfacing.
		return nil, nil //nolint:nilerr
	}
	return []platforms.Workflow{{
		Name:     filepath.Base(path),
		Path:     filepath.Base(path),
		Content:  content,
		RepoSlug: repoSlug,
	}}, nil
}

// walkDir walks a directory and returns all files matching the platform matcher.
func walkDir(platform, root, repoSlug string) ([]platforms.Workflow, error) {
	m := platformMatchers[platform]
	var workflows []platforms.Workflow

	walkErr := filepath.WalkDir(root, func(absPath string, d fs.DirEntry, err error) error {
		if err != nil {
			// Skip unreadable entries silently
			return nil
		}

		name := d.Name()

		if d.IsDir() {
			if skipDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}

		// Compute forward-slash relative path for matching and storage.
		rel, err := filepath.Rel(root, absPath)
		if err != nil {
			return nil // skip on error
		}
		relSlash := filepath.ToSlash(rel)

		if !m(relSlash) {
			return nil
		}

		content, err := os.ReadFile(absPath)
		if err != nil {
			return nil // skip unreadable files silently
		}

		workflows = append(workflows, platforms.Workflow{
			Name:     name,
			Path:     relSlash,
			Content:  content,
			RepoSlug: repoSlug,
		})
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walking %s: %w", root, walkErr)
	}

	// Stable sort by Path for deterministic output.
	sort.Slice(workflows, func(i, j int) bool {
		return workflows[i].Path < workflows[j].Path
	})

	return workflows, nil
}
