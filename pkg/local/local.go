// Package local implements a platforms.Platform that scans local filesystem paths.
package local

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/praetorian-inc/trajan/pkg/analysis/parser"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// Platform implements platforms.Platform for local filesystem scanning.
type Platform struct {
	config platforms.Config
}

// NewPlatform creates a new local filesystem platform.
func NewPlatform() *Platform {
	return &Platform{}
}

// Name returns the platform identifier.
func (p *Platform) Name() string {
	return "local"
}

// Init stores config; no remote client is needed for local scanning.
func (p *Platform) Init(_ context.Context, config platforms.Config) error {
	p.config = config
	return nil
}

// Scan walks the local filesystem path and discovers CI/CD workflow files.
// It only handles targets of type TargetLocal.
func (p *Platform) Scan(_ context.Context, target platforms.Target) (*platforms.ScanResult, error) {
	if target.Type != platforms.TargetLocal {
		return nil, fmt.Errorf("unsupported target type for local: %s", target.Type)
	}

	absRoot, err := filepath.Abs(target.Value)
	if err != nil {
		return nil, fmt.Errorf("resolving path %s: %w", target.Value, err)
	}

	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, fmt.Errorf("accessing path %s: %w", absRoot, err)
	}

	fmt.Fprintf(os.Stderr, "Scanning local path %s...\n", absRoot)

	result := &platforms.ScanResult{
		Workflows: make(map[string][]platforms.Workflow),
	}

	repoName := filepath.Base(absRoot)

	var candidates []string
	if !info.IsDir() {
		// Single file: treat it as a candidate directly.
		candidates = []string{absRoot}
	} else {
		candidates, err = walkCandidates(absRoot)
		if err != nil {
			return nil, fmt.Errorf("walking %s: %w", absRoot, err)
		}
	}

	for _, absPath := range candidates {
		var relPath string
		if !info.IsDir() {
			relPath = filepath.Base(absPath)
		} else {
			rel, relErr := filepath.Rel(absRoot, absPath)
			if relErr != nil {
				result.Errors = append(result.Errors, relErr)
				continue
			}
			relPath = filepath.ToSlash(rel)
		}

		wfParser := parser.DetectParser(relPath)
		if wfParser == nil {
			continue
		}

		content, readErr := os.ReadFile(absPath)
		if readErr != nil {
			result.Errors = append(result.Errors, fmt.Errorf("reading %s: %w", absPath, readErr))
			continue
		}

		platform := wfParser.Platform()
		key := "local:" + platform
		wf := platforms.Workflow{
			Name:     filepath.Base(absPath),
			Path:     relPath,
			Content:  content,
			RepoSlug: key,
			Metadata: map[string]interface{}{"platform": platform},
		}
		result.Workflows[key] = append(result.Workflows[key], wf)
	}

	platformCount := len(result.Workflows)
	totalWorkflows := 0
	for _, wfs := range result.Workflows {
		totalWorkflows += len(wfs)
	}
	fmt.Fprintf(os.Stderr, "Found %d workflows across %d platforms\n", totalWorkflows, platformCount)

	result.Repositories = []platforms.Repository{
		{Name: repoName, URL: absRoot},
	}

	return result, nil
}

// walkCandidates returns all non-skipped file paths under root.
func walkCandidates(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && skipDir(d.Name()) {
			return filepath.SkipDir
		}
		if !d.IsDir() {
			paths = append(paths, path)
		}
		return nil
	})
	return paths, err
}

// skipDir returns true for directories that should be skipped entirely.
func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor":
		return true
	}
	return false
}

var _ platforms.Platform = (*Platform)(nil)
