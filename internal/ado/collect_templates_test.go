package ado

import "testing"

func TestSplitTemplateRef(t *testing.T) {
	tests := []struct {
		in    string
		path  string
		alias string
	}{
		{"base.yml@templates", "base.yml", "templates"},
		{"local.yml", "local.yml", ""},
		{"dir/base.yml@repo", "dir/base.yml", "repo"},
		{"a@b@c", "a@b", "c"}, // split on the LAST @
	}
	for _, tt := range tests {
		got := splitTemplateRef(tt.in)
		if got.path != tt.path || got.alias != tt.alias {
			t.Errorf("splitTemplateRef(%q) = {%q,%q}, want {%q,%q}", tt.in, got.path, got.alias, tt.path, tt.alias)
		}
	}
}

func TestStripRefAndNormalize(t *testing.T) {
	if got := stripRef("refs/heads/main"); got != "main" {
		t.Errorf("stripRef heads = %q", got)
	}
	if got := stripRef("refs/tags/v1.2"); got != "v1.2" {
		t.Errorf("stripRef tags = %q", got)
	}
	if got := stripRef("release/1.0"); got != "release/1.0" {
		t.Errorf("stripRef bare = %q", got)
	}
	if got := normalizePath("templates/x.yml"); got != "/templates/x.yml" {
		t.Errorf("normalizePath rel = %q", got)
	}
	if got := normalizePath("/a.yml"); got != "/a.yml" {
		t.Errorf("normalizePath abs = %q", got)
	}
}

// Oracle: the real Imladris s08-01 consumer shape — extends a cross-repo template
// declared via resources.repositories.
func TestParseTemplateRefs(t *testing.T) {
	yaml := `
resources:
  repositories:
  - repository: templates
    type: git
    name: Imladris/BuildTemplates
    ref: refs/heads/release
variables:
- group: prod-secrets
extends:
  template: base.yml@templates
`
	refs, aliases := parseTemplateRefs(yaml)
	if len(refs) != 1 {
		t.Fatalf("want 1 template ref, got %d: %+v", len(refs), refs)
	}
	if refs[0].path != "base.yml" || refs[0].alias != "templates" {
		t.Errorf("ref = %+v", refs[0])
	}
	res, ok := aliases["templates"]
	if !ok {
		t.Fatalf("alias 'templates' not resolved; got %+v", aliases)
	}
	if res.name != "Imladris/BuildTemplates" || res.ref != "refs/heads/release" {
		t.Errorf("repoResource = %+v", res)
	}
}

// A template that includes another template inline (nested steps) must surface
// both references.
func TestParseTemplateRefs_Nested(t *testing.T) {
	yaml := `
steps:
- template: steps/build.yml
- script: echo hi
- template: steps/deploy.yml@shared
`
	refs, _ := parseTemplateRefs(yaml)
	if len(refs) != 2 {
		t.Fatalf("want 2 refs, got %d: %+v", len(refs), refs)
	}
	paths := map[string]string{refs[0].path: refs[0].alias, refs[1].path: refs[1].alias}
	if paths["steps/build.yml"] != "" || paths["steps/deploy.yml"] != "shared" {
		t.Errorf("unexpected refs: %+v", refs)
	}
}
