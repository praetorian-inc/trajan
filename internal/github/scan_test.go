package github

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// A scan that aborts on bad input must leave the previous run's findings and
// graph alone; a scan that completes must drop the graph its old findings backed.
func TestScanClearsOutputOnlyAfterInputsValidate(t *testing.T) {
	runDir := t.TempDir()
	state := &engine.State{RunID: "t", Org: "acme", LastPhase: 1, Phases: []engine.PhaseRecord{}}
	if err := state.Save(runDir); err != nil {
		t.Fatal(err)
	}
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(runDir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	exists := func(rel string) bool {
		_, err := os.Stat(filepath.Join(runDir, rel))
		return err == nil
	}

	write("20-scan/findings/cat-01/prior.json", `{}`)
	write("30-graph/nodes.json", `[]`)
	write("10-normalize/jobs/broken.json", `{`)

	if err := Scan(t.Context(), runDir, ScanOptions{}); err == nil {
		t.Fatal("a malformed job record should abort the scan")
	}
	if !exists("20-scan/findings/cat-01/prior.json") || !exists("30-graph/nodes.json") {
		t.Error("an aborted scan destroyed the previous run's output")
	}

	if err := os.Remove(filepath.Join(runDir, "10-normalize/jobs/broken.json")); err != nil {
		t.Fatal(err)
	}
	if err := Scan(t.Context(), runDir, ScanOptions{}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if exists("20-scan/findings/cat-01/prior.json") {
		t.Error("a completed scan kept a finding from the previous run")
	}
	if exists("30-graph") {
		t.Error("a completed scan left a graph built from the previous findings")
	}
}
