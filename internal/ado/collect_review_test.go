package ado

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// A soft-failed list surface must write an {_unobserved} marker, not an empty [],
// so downstream can tell "no access" from "genuinely empty".
func TestWriteListOrMark(t *testing.T) {
	dir := t.TempDir()
	cp := engine.CurrentPhase{RunDir: dir}

	// soft fail -> marker
	if err := writeListOrMark(cp, engine.CollectADOServiceConnections("P"), "service-connections", "/p", nil, 403); err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := engine.ReadJSON(filepath.Join(dir, engine.CollectADOServiceConnections("P")), &env); err != nil {
		t.Fatal(err)
	}
	data, _ := env["data"].(map[string]any)
	if data == nil || data["_unobserved"] == nil {
		t.Errorf("soft-fail list did not write _unobserved marker: %v", env["data"])
	}

	// success -> the list (never nil)
	if err := writeListOrMark(cp, engine.CollectADOVariableGroups("P"), "variable-groups", "/p", nil, 0); err != nil {
		t.Fatal(err)
	}
	var env2 map[string]any
	if err := engine.ReadJSON(filepath.Join(dir, engine.CollectADOVariableGroups("P")), &env2); err != nil {
		t.Fatal(err)
	}
	if _, ok := env2["data"].([]any); !ok {
		t.Errorf("success list should serialize as [], got %T", env2["data"])
	}
}

// A malicious template path must not escape the collection directory: the path is
// flattened by adoKey when the on-disk name is built.
func TestPipelineYAMLPathNoTraversal(t *testing.T) {
	name := "repoid@main__../../../../state.json"
	rel := engine.CollectADOPipelineYAML("Proj", 7, name)
	if strings.Contains(rel, "..") && strings.Contains(rel, "/..") {
		t.Errorf("traversal not flattened: %q", rel)
	}
	// the whole reconstructed name collapses to a single path segment (no separators)
	if c := strings.Count(strings.TrimPrefix(rel, "00-collect/pipeline-yaml/"), "/"); c != 1 {
		t.Errorf("template name introduced extra path segments: %q", rel)
	}
}

func TestRefVersion(t *testing.T) {
	cases := []struct{ ref, ver, typ string }{
		{"refs/tags/v1.0", "v1.0", "tag"},
		{"refs/heads/main", "main", "branch"},
		{"release", "release", "branch"},
	}
	for _, c := range cases {
		v, tp := refVersion(c.ref)
		if v != c.ver || tp != c.typ {
			t.Errorf("refVersion(%q) = %q/%q, want %q/%q", c.ref, v, tp, c.ver, c.typ)
		}
	}
}

// A cross-project repo that merely shares a name with a local repo must be treated
// as external, not matched to the local one.
func TestResolveRepoName(t *testing.T) {
	if n, ext := resolveRepoName("MyRepo", "Proj"); n != "MyRepo" || ext {
		t.Errorf("bare name: got %q ext=%v", n, ext)
	}
	if n, ext := resolveRepoName("Proj/MyRepo", "Proj"); n != "MyRepo" || ext {
		t.Errorf("same-project qualified: got %q ext=%v", n, ext)
	}
	if _, ext := resolveRepoName("OtherProject/MyRepo", "Proj"); !ext {
		t.Error("cross-project repo should be external")
	}
}

// A same-repo relative template resolves against the including file's directory;
// a leading "/" is repo-root absolute.
func TestResolveTemplatePath(t *testing.T) {
	if got := resolveTemplatePath("/ci/pipeline.yml", "templates/build.yml"); got != "/ci/templates/build.yml" {
		t.Errorf("relative = %q, want /ci/templates/build.yml", got)
	}
	if got := resolveTemplatePath("/ci/pipeline.yml", "/shared/base.yml"); got != "/shared/base.yml" {
		t.Errorf("absolute = %q, want /shared/base.yml", got)
	}
	if got := resolveTemplatePath("/ci/pipeline.yml", "../common/x.yml"); got != "/common/x.yml" {
		t.Errorf("dotdot = %q, want /common/x.yml", got)
	}
}
