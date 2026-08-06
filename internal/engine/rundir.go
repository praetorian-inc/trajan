package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The minute-precision UTC timestamp leads the name so lexical order is
// chronological and ResolveRunDir can pick the latest run for a platform.
func MintRunDir(cfg *Config, platform, scopeSlug string) (string, error) {
	ts := time.Now().UTC().Format("2006-01-02-1504")
	name := fmt.Sprintf("%s-%s-%s", ts, platform, scopeSlug)
	dir := filepath.Join(cfg.OutputDir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func ResolveRunDir(cfg *Config, platform, explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	entries, err := os.ReadDir(cfg.OutputDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrNoRunDir
		}
		return "", err
	}
	tag := "-" + platform + "-"
	best := ""
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.Contains(name, tag) {
			continue
		}
		if name > best {
			best = name
		}
	}
	if best == "" {
		return "", ErrNoRunDir
	}
	return filepath.Join(cfg.OutputDir, best), nil
}
