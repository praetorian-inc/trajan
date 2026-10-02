package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMintRunDirNeverReusesADirectoryAndResolvePicksTheNewest(t *testing.T) {
	cfg := &Config{OutputDir: t.TempDir()}
	seen := map[string]bool{}
	last := ""
	for i := range 11 {
		dir, err := MintRunDir(cfg, "github", "org")
		if err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}
		if seen[dir] {
			t.Fatalf("mint %d returned %s again", i, dir)
		}
		seen[dir] = true
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}
		if len(entries) != 0 {
			t.Fatalf("mint %d returned %s, which already holds %d entries", i, dir, len(entries))
		}
		if err := os.WriteFile(filepath.Join(dir, "_meta.json"), []byte(`{"run_id":"x"}`), 0o644); err != nil {
			t.Fatal(err)
		}
		last = dir
	}

	got, err := ResolveRunDir(cfg, "github", "")
	if err != nil {
		t.Fatalf("ResolveRunDir: %v", err)
	}
	if got != last {
		t.Errorf("ResolveRunDir = %s, want the most recently minted %s", got, last)
	}
}

func TestResolveRunDirMatchesThePlatformSegmentOnly(t *testing.T) {
	cfg := &Config{OutputDir: t.TempDir()}
	for _, name := range []string{"2026-09-30-1200-ado-myorg-my-gh-project", "2026-09-29-1200-gh-myorg"} {
		if err := os.MkdirAll(filepath.Join(cfg.OutputDir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	got, err := ResolveRunDir(cfg, "gh", "")
	if err != nil {
		t.Fatalf("ResolveRunDir: %v", err)
	}
	if filepath.Base(got) != "2026-09-29-1200-gh-myorg" {
		t.Errorf("ResolveRunDir(gh) = %s; a scope slug containing -gh- resolved as a GitHub run", got)
	}
}
