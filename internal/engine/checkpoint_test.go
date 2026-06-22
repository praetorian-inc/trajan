package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteJSONNoTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "out.json")

	if err := WriteJSON(p, map[string]any{"a": 1, "b": "two"}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("empty output")
	}
	if b[len(b)-1] == '\n' {
		t.Fatalf("output has trailing newline; last byte = %q", b[len(b)-1])
	}
	if !containsByte(b, '\n') {
		t.Fatalf("expected indented multi-line JSON, got %q", b)
	}
}

func TestWriteReadJSONRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.json")
	in := map[string]string{"k": "v"}
	if err := WriteJSON(p, in); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var out map[string]string
	if err := ReadJSON(p, &out); err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if out["k"] != "v" {
		t.Fatalf("round trip mismatch: %v", out)
	}
}

func TestWriteRaw(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nested", "raw.txt")
	want := []byte("hello\nworld")
	if err := WriteRaw(p, want); err != nil {
		t.Fatalf("WriteRaw: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestIterJSON(t *testing.T) {
	dir := t.TempDir()
	run := filepath.Join(dir, "run1")
	phaseDir := "10-normalize"
	root := filepath.Join(run, phaseDir)

	// Layout:
	//   jobs/a.json          -> included
	//   jobs/b.json          -> included
	//   jobs/nested/c.json   -> included (recursive)
	//   jobs/_skip.json      -> skipped (leading underscore)
	//   _summary.json        -> skipped (leading underscore, at phase root)
	//   jobs/note.txt        -> skipped (not .json)
	mustWrite(t, filepath.Join(root, "jobs", "b.json"), `{"id":"b"}`)
	mustWrite(t, filepath.Join(root, "jobs", "a.json"), `{"id":"a"}`)
	mustWrite(t, filepath.Join(root, "jobs", "nested", "c.json"), `{"id":"c"}`)
	mustWrite(t, filepath.Join(root, "jobs", "_skip.json"), `{"id":"skip"}`)
	mustWrite(t, filepath.Join(root, "_summary.json"), `{"summary":true}`)
	mustWrite(t, filepath.Join(root, "jobs", "note.txt"), `not json`)

	pp := PriorPhase{RunDir: run}
	files, err := pp.IterJSON(phaseDir)
	if err != nil {
		t.Fatalf("IterJSON: %v", err)
	}

	wantRels := []string{
		filepath.Join("jobs", "a.json"),
		filepath.Join("jobs", "b.json"),
		filepath.Join("jobs", "nested", "c.json"),
	}
	if len(files) != len(wantRels) {
		t.Fatalf("got %d files, want %d: %+v", len(files), len(wantRels), files)
	}
	for i, f := range files {
		if f.Rel != wantRels[i] {
			t.Errorf("files[%d].Rel = %q, want %q", i, f.Rel, wantRels[i])
		}
		if len(f.Data) == 0 {
			t.Errorf("files[%d].Data empty", i)
		}
	}
}

func TestIterJSONMissingDir(t *testing.T) {
	dir := t.TempDir()
	pp := PriorPhase{RunDir: dir}
	files, err := pp.IterJSON("does-not-exist")
	if err != nil {
		t.Fatalf("IterJSON on missing dir: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("got %d files, want 0", len(files))
	}
}

func TestCurrentPhaseWrite(t *testing.T) {
	dir := t.TempDir()
	cp := CurrentPhase{RunDir: dir}
	if err := cp.Write(filepath.Join("20-scan", "findings", "f.json"), map[string]int{"n": 1}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "20-scan", "findings", "f.json")); err != nil {
		t.Fatalf("expected written file: %v", err)
	}
	if err := cp.WriteRaw("raw.bin", []byte{0x01, 0x02}); err != nil {
		t.Fatalf("WriteRaw: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "raw.bin"))
	if err != nil || len(b) != 2 {
		t.Fatalf("WriteRaw round trip: %v %v", b, err)
	}
}

func containsByte(b []byte, c byte) bool {
	for _, x := range b {
		if x == c {
			return true
		}
	}
	return false
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
