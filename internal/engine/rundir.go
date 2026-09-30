package engine

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxRunDirSuffix = 99

// The minute-precision UTC timestamp leads the name so lexical order is
// chronological and ResolveRunDir can pick the latest run for a platform.
func MintRunDir(cfg *Config, platform, scopeSlug string) (string, error) {
	ts := time.Now().UTC().Format("2006-01-02-1504")
	base := filepath.Join(cfg.OutputDir, fmt.Sprintf("%s-%s-%s", ts, platform, scopeSlug))
	if err := os.MkdirAll(cfg.OutputDir, 0o755); err != nil {
		return "", err
	}
	// Zero-padded so the suffixed siblings keep ResolveRunDir's lexical ordering.
	for n := 1; n <= maxRunDirSuffix; n++ {
		dir := base
		if n > 1 {
			dir = fmt.Sprintf("%s-%02d", base, n)
		}
		err := os.Mkdir(dir, 0o755)
		if err == nil {
			return dir, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	return "", fmt.Errorf("mint run directory: %s and %d suffixes already exist", base, maxRunDirSuffix-1)
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
