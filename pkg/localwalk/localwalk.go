// Package localwalk walks a local filesystem path for the workflow files of a
// given platform, so a cloned repository can be scanned without API access.
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

// matcher reports whether a forward-slash relative path belongs to the platform.
type matcher func(relPath string) bool

var platformMatchers = map[string]matcher{
	platforms.PlatformGitHub: func(relPath string) bool {
		const prefix = ".github/workflows/"
		if !strings.HasPrefix(relPath, prefix) {
			return false
		}
		rest := relPath[len(prefix):]
		if strings.Contains(rest, "/") {
			return false
		}
		return strings.HasSuffix(rest, ".yml") || strings.HasSuffix(rest, ".yaml")
	},

	platforms.PlatformGitLab: func(relPath string) bool {
		base := filepath.Base(relPath)
		return base == ".gitlab-ci.yml" || base == ".gitlab-ci.yaml"
	},

	platforms.PlatformAzureDevOps: func(relPath string) bool {
		base := filepath.Base(relPath)
		if base == "azure-pipelines.yml" || base == "azure-pipelines.yaml" {
			return true
		}
		if strings.HasSuffix(base, ".azure-pipelines.yml") || strings.HasSuffix(base, ".azure-pipelines.yaml") {
			return true
		}
		if strings.Contains(relPath, ".azure-pipelines/") &&
			(strings.HasSuffix(relPath, ".yml") || strings.HasSuffix(relPath, ".yaml")) {
			return true
		}
		return false
	},

	platforms.PlatformJenkins: func(relPath string) bool {
		lower := strings.ToLower(filepath.Base(relPath))
		if lower == "jenkinsfile" {
			return true
		}
		if strings.HasPrefix(lower, "jenkinsfile.") {
			return true
		}
		if strings.HasSuffix(lower, ".jenkinsfile") {
			return true
		}
		return false
	},
}

func SupportedPlatforms() []string {
	names := make([]string, 0, len(platformMatchers))
	for k := range platformMatchers {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func IsSupported(platform string) bool {
	_, ok := platformMatchers[platform]
	return ok
}

var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
}

// MaxFileSize caps a single workflow read. Workflow YAML and Jenkinsfiles sit
// well under 100 KB, so 10 MB is ample headroom.
const MaxFileSize = 10 << 20 // 10 MB

// Walk takes a file or a directory. Directory mode filters by the platform
// matcher, sets Path relative to root, and silently skips unreadable or
// oversized files; single-file mode trusts the caller's platform, sets Path to
// the basename, and errors on an unreadable or oversized file.
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
		return loadSingleFile(path, repoSlug)
	}

	return walkDir(platform, path, repoSlug)
}

func loadSingleFile(path, repoSlug string) ([]platforms.Workflow, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxFileSize {
		return nil, fmt.Errorf("file %s exceeds %d-byte limit", path, MaxFileSize)
	}
	fileContent, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return []platforms.Workflow{{
		Name:     filepath.Base(path),
		Path:     filepath.Base(path),
		Content:  fileContent,
		RepoSlug: repoSlug,
	}}, nil
}

func walkDir(platform, root, repoSlug string) ([]platforms.Workflow, error) {
	m := platformMatchers[platform]
	var workflows []platforms.Workflow

	walkErr := filepath.WalkDir(root, func(absPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		name := d.Name()

		if d.IsDir() {
			if skipDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}

		rel, err := filepath.Rel(root, absPath)
		if err != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)

		if !m(relSlash) {
			return nil
		}

		if info, err := d.Info(); err == nil && info.Size() > MaxFileSize {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: file exceeds %d-byte limit\n", relSlash, MaxFileSize)
			return nil
		}

		fileContent, err := os.ReadFile(absPath)
		if err != nil {
			return nil
		}

		workflows = append(workflows, platforms.Workflow{
			Name:     name,
			Path:     relSlash,
			Content:  fileContent,
			RepoSlug: repoSlug,
		})
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walking %s: %w", root, walkErr)
	}

	// Sorted for deterministic output.
	sort.Slice(workflows, func(i, j int) bool {
		return workflows[i].Path < workflows[j].Path
	})

	return workflows, nil
}
