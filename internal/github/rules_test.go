package github

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine/detect"
)

func TestBlockMarshalJSON(t *testing.T) {
	scalar, err := json.Marshal(detect.Block{Predicate: "a == b"})
	if err != nil {
		t.Fatal(err)
	}
	if string(scalar) != `"a == b"` {
		t.Errorf("scalar block: want %q, got %s", "a == b", scalar)
	}

	combo, err := json.Marshal(detect.Block{IsCombo: true, AllOf: []detect.Block{{Predicate: "x"}, {Predicate: "y"}}})
	if err != nil {
		t.Fatal(err)
	}
	if string(combo) != `{"all_of":["x","y"]}` {
		t.Errorf("combo block: got %s", combo)
	}
}

func TestBuildFindingOrgBackfillAndProvenance(t *testing.T) {
	rule := &detect.Rule{
		ID: "cat-x/y", Title: "T", Severity: "high", Confidence: "high",
		Subject:  "job",
		Where:    &detect.Block{Predicate: "foo != null"},
		Evidence: []string{"value is {{ foo }}"},
	}
	subj := map[string]any{
		"_id":         "s1",
		"foo":         "bar",
		"_provenance": map[string]any{"workflow_file": "wf.yml"},
	}

	f := detect.BuildFinding(provider, rule, subj, "job", "myorg", "")

	if f.Org != "myorg" {
		t.Errorf("org should backfill from the run scope when the subject lacks one, got %q", f.Org)
	}
	if f.Provenance["foo"] != "bar" {
		t.Errorf("provenance should carry the evidence-referenced value, got %v", f.Provenance)
	}
	if f.Provenance["collect.workflow_file"] != "wf.yml" {
		t.Errorf("provenance should carry the collect-input pointer, got %v", f.Provenance)
	}
	if f.Fingerprint == "" {
		t.Error("BuildFinding must compute a fingerprint")
	}
	if f.Evidence[0] != "value is bar" {
		t.Errorf("evidence should be the rendered string, got %q", f.Evidence[0])
	}
}

func TestBuildFindingSubjectOwnerWins(t *testing.T) {
	rule := &detect.Rule{ID: "cat-x/y", Subject: "org"}
	subj := map[string]any{"_id": "acme", "owner": "acme"}
	f := detect.BuildFinding(provider, rule, subj, "org", "passed-org", "")
	if f.Org != "passed-org" {
		t.Errorf("a non-empty run scope should win; got %q", f.Org)
	}

	f2 := detect.BuildFinding(provider, rule, subj, "org", "", "")
	if f2.Org != "acme" {
		t.Errorf("with no run scope, org should come from the subject owner; got %q", f2.Org)
	}
}

func TestReadSnippet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wf.yml")
	if err := os.WriteFile(path, []byte("l1\nl2\nl3\nl4\nl5"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := readSnippet(path, 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got != "l2\nl3\nl4" {
		t.Errorf("want lines 2-4 inclusive, got %q", got)
	}

	// end past EOF clamps rather than erroring
	if got, err := readSnippet(path, 4, 99); err != nil || got != "l4\nl5" {
		t.Errorf("clamp to EOF: got %q err %v", got, err)
	}
}

func TestBuildCodeEmbedsWindow(t *testing.T) {
	dir := t.TempDir()
	rel := "00-collect/workflows/r/main.yml"
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("a\nb\nc\nd"), 0o644); err != nil {
		t.Fatal(err)
	}

	subj := map[string]any{
		"_provenance": map[string]any{
			"workflow_file":   rel,
			"yaml_line_range": []any{float64(2), float64(3)}, // JSON-decoded floats
		},
	}
	code := buildCode(dir, subj)
	if code == nil {
		t.Fatal("expected a code block")
	}
	if code.Snippet != "b\nc" || len(code.LineRange) != 2 || code.LineRange[0] != 2 || code.LineRange[1] != 3 {
		t.Errorf("unexpected code block: %+v", code)
	}

	// no run dir, or a subject without a code location → nil (no scan failure)
	if buildCode("", subj) != nil {
		t.Error("empty runDir should skip the snippet")
	}
	if buildCode(dir, map[string]any{"_id": "x"}) != nil {
		t.Error("subject without _provenance should have no code block")
	}
}
