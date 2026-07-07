package github

import (
	"reflect"
	"slices"
	"sort"
	"testing"
)

// Independent copy of the canonical scope set: the test must not import the impl's allScopes.
var expectedScopes = []string{
	"actions", "attestations", "checks", "contents", "deployments",
	"discussions", "id-token", "issues", "models", "packages", "pages",
	"pull-requests", "repository-projects", "security-events", "statuses",
}

func scopeKeys(out map[string]any) []string {
	var ks []string
	for k := range out {
		if k == "_source" || k == "_chain" {
			continue
		}
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func scope(t *testing.T, out map[string]any, key string) string {
	t.Helper()
	v, ok := out[key]
	if !ok {
		t.Fatalf("scope %q absent from resolved block", key)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("scope %q = %T, want string", key, v)
	}
	return s
}

func chainOf(t *testing.T, out map[string]any) []map[string]any {
	t.Helper()
	raw, ok := out["_chain"].([]any)
	if !ok {
		t.Fatalf("_chain = %T, want []any", out["_chain"])
	}
	var ch []map[string]any
	for i, e := range raw {
		m, ok := e.(map[string]any)
		if !ok {
			t.Fatalf("_chain[%d] = %T, want map", i, e)
		}
		ch = append(ch, m)
	}
	return ch
}

func TestResolveImplicitNoLayers(t *testing.T) {
	out := resolvePermissions(permInputs{})
	if out["_source"] != "implicit" {
		t.Errorf("_source = %v, want implicit", out["_source"])
	}
	if ch := chainOf(t, out); len(ch) != 0 {
		t.Errorf("_chain = %v, want empty", ch)
	}
	if ks := scopeKeys(out); len(ks) != 0 {
		t.Errorf("implicit resolution must emit no scope keys, got %v", ks)
	}
}

func TestResolveOrgDefaultReadOptInExempt(t *testing.T) {
	out := resolvePermissions(permInputs{OrgDefault: "read"})
	if out["_source"] != "org_default" {
		t.Errorf("_source = %v, want org_default", out["_source"])
	}
	if ks := scopeKeys(out); !reflect.DeepEqual(ks, sortedCopy(expectedScopes)) {
		t.Errorf("scope keys = %v, want full 15-scope set", ks)
	}
	if got := scope(t, out, "contents"); got != "read" {
		t.Errorf("contents = %q, want read", got)
	}
	if got := scope(t, out, "id-token"); got != "none" {
		t.Errorf("id-token = %q, want none (opt-in exempt)", got)
	}
	if got := scope(t, out, "attestations"); got != "none" {
		t.Errorf("attestations = %q, want none (opt-in exempt)", got)
	}
	ch := chainOf(t, out)
	if len(ch) != 1 || ch[0]["source"] != "org_default" || ch[0]["value"] != "read" {
		t.Errorf("_chain = %v, want single org_default/read", ch)
	}
	if _, has := ch[0]["_provenance"]; has {
		t.Error("org_default chain entry must not have _provenance")
	}
}

// repo_default REPLACES the org_default layer entirely (reassignment, not merge).
func TestResolveRepoDefaultReplacesOrgDefault(t *testing.T) {
	out := resolvePermissions(permInputs{OrgDefault: "write", RepoDefault: "read"})
	if out["_source"] != "repo_default" {
		t.Errorf("_source = %v, want repo_default", out["_source"])
	}
	if got := scope(t, out, "contents"); got != "read" {
		t.Errorf("contents = %q, want read (repo_default replaced org write)", got)
	}
	if got := scope(t, out, "actions"); got != "read" {
		t.Errorf("actions = %q, want read", got)
	}
	ch := chainOf(t, out)
	if len(ch) != 2 {
		t.Fatalf("_chain len = %d, want 2", len(ch))
	}
	if ch[0]["source"] != "org_default" || ch[1]["source"] != "repo_default" {
		t.Errorf("_chain sources = [%v %v], want [org_default repo_default]", ch[0]["source"], ch[1]["source"])
	}
}

func TestResolveWorkflowShorthandReadAll(t *testing.T) {
	prov := &SourceProvenance{File: "ci.yml"}
	out := resolvePermissions(permInputs{
		WorkflowPerms:      "read-all",
		WorkflowProvenance: prov,
	})
	if out["_source"] != "workflow" {
		t.Errorf("_source = %v, want workflow", out["_source"])
	}
	if got := scope(t, out, "contents"); got != "read" {
		t.Errorf("contents = %q, want read", got)
	}
	if got := scope(t, out, "id-token"); got != "none" {
		t.Errorf("id-token = %q, want none (opt-in exempt under shorthand)", got)
	}
	ch := chainOf(t, out)
	if len(ch) != 1 || ch[0]["source"] != "workflow" || ch[0]["value"] != "read-all" {
		t.Fatalf("_chain = %v, want workflow/read-all", ch)
	}
	if ch[0]["_provenance"] != prov {
		t.Errorf("workflow chain _provenance = %v, want the passed provenance", ch[0]["_provenance"])
	}
}

func TestResolveShorthandRestrictedAndEmptyBraces(t *testing.T) {
	for _, v := range []string{"restricted", "{}"} {
		out := resolvePermissions(permInputs{WorkflowPerms: v})
		if ks := scopeKeys(out); !reflect.DeepEqual(ks, sortedCopy(expectedScopes)) {
			t.Errorf("%q: scope keys = %v, want all 15", v, ks)
		}
		for _, s := range expectedScopes {
			if got := scope(t, out, s); got != "none" {
				t.Errorf("%q: scope %s = %q, want none", v, s, got)
			}
		}
	}
}

// A dict is the FULL set; an explicit id-token entry passes through verbatim (not opt-in-filtered).
func TestResolveWorkflowDictResetsUnmentionedToNoneAndExplicitOptInWins(t *testing.T) {
	out := resolvePermissions(permInputs{
		WorkflowPerms: map[string]any{
			"contents": "read",
			"id-token": "write",
		},
	})
	if out["_source"] != "workflow" {
		t.Errorf("_source = %v, want workflow", out["_source"])
	}
	if got := scope(t, out, "contents"); got != "read" {
		t.Errorf("contents = %q, want read", got)
	}
	if got := scope(t, out, "id-token"); got != "write" {
		t.Errorf("id-token = %q, want write (explicit dict entry bypasses opt-in filter)", got)
	}
	if got := scope(t, out, "pull-requests"); got != "none" {
		t.Errorf("pull-requests = %q, want none (dict resets unmentioned)", got)
	}
	if ks := scopeKeys(out); !reflect.DeepEqual(ks, sortedCopy(expectedScopes)) {
		t.Errorf("dict layer must emit all 15 scopes, got %v", ks)
	}
}

// A dict resets everything to none first, so it must NOT inherit an underlying default's grant.
func TestResolveWorkflowDictDoesNotInheritDefault(t *testing.T) {
	out := resolvePermissions(permInputs{
		OrgDefault:    "write",
		WorkflowPerms: map[string]any{"contents": "write"},
	})
	if got := scope(t, out, "contents"); got != "write" {
		t.Errorf("contents = %q, want write", got)
	}
	if got := scope(t, out, "packages"); got != "none" {
		t.Errorf("packages = %q, want none — dict must not inherit org write", got)
	}
}

func TestResolveFullPrecedenceJobWins(t *testing.T) {
	wProv := &SourceProvenance{File: "ci.yml"}
	jProv := &SourceProvenance{File: "ci.yml"}
	out := resolvePermissions(permInputs{
		OrgDefault:         "write",
		RepoDefault:        "read",
		WorkflowPerms:      map[string]any{"contents": "read", "packages": "write"},
		JobPerms:           map[string]any{"contents": "write"},
		WorkflowProvenance: wProv,
		JobProvenance:      jProv,
	})
	if out["_source"] != "job" {
		t.Errorf("_source = %v, want job", out["_source"])
	}
	if got := scope(t, out, "contents"); got != "write" {
		t.Errorf("contents = %q, want write (job)", got)
	}
	if got := scope(t, out, "packages"); got != "none" {
		t.Errorf("packages = %q, want none (job dict resets; workflow's write discarded)", got)
	}
	ch := chainOf(t, out)
	wantSources := []string{"org_default", "repo_default", "workflow", "job"}
	if len(ch) != 4 {
		t.Fatalf("_chain len = %d, want 4", len(ch))
	}
	for i, want := range wantSources {
		if ch[i]["source"] != want {
			t.Errorf("_chain[%d].source = %v, want %v", i, ch[i]["source"], want)
		}
	}
	if _, has := ch[2]["_provenance"]; !has {
		t.Error("workflow chain entry must carry _provenance")
	}
	if _, has := ch[3]["_provenance"]; !has {
		t.Error("job chain entry must carry _provenance")
	}
	if _, has := ch[0]["_provenance"]; has {
		t.Error("org_default chain entry must not carry _provenance")
	}
	if _, has := ch[1]["_provenance"]; has {
		t.Error("repo_default chain entry must not carry _provenance")
	}
}

func TestResolveJobShorthandOverridesWorkflowDict(t *testing.T) {
	out := resolvePermissions(permInputs{
		WorkflowPerms: map[string]any{"contents": "write", "id-token": "write"},
		JobPerms:      "read-all",
	})
	if out["_source"] != "job" {
		t.Errorf("_source = %v, want job", out["_source"])
	}
	if got := scope(t, out, "contents"); got != "read" {
		t.Errorf("contents = %q, want read (job read-all)", got)
	}
	if got := scope(t, out, "id-token"); got != "none" {
		t.Errorf("id-token = %q, want none (job read-all opt-in exempt, workflow grant discarded)", got)
	}
}

func TestResolveChainValueShapes(t *testing.T) {
	dictLayer := map[string]any{"contents": "read"}
	out := resolvePermissions(permInputs{
		WorkflowPerms: "write-all",
		JobPerms:      dictLayer,
	})
	ch := chainOf(t, out)
	if len(ch) != 2 {
		t.Fatalf("_chain len = %d, want 2", len(ch))
	}
	if ch[0]["value"] != "write-all" {
		t.Errorf("workflow chain value = %v, want write-all", ch[0]["value"])
	}
	jv, ok := ch[1]["value"].(map[string]string)
	if !ok {
		t.Fatalf("job chain value = %T, want map[string]string copy", ch[1]["value"])
	}
	if jv["contents"] != "read" {
		t.Errorf("job chain value[contents] = %q, want read", jv["contents"])
	}
	dictLayer["contents"] = "write"
	if jv["contents"] != "read" {
		t.Error("chain value must be a defensive copy, not an alias")
	}
}

// Dict values are stringified Python-style: booleans become "True"/"False".
func TestResolveDictValuesStringified(t *testing.T) {
	out := resolvePermissions(permInputs{
		JobPerms: map[string]any{"contents": true, "issues": 0},
	})
	if got := scope(t, out, "contents"); got != "True" {
		t.Errorf("contents = %q, want stringified True", got)
	}
	if got := scope(t, out, "issues"); got != "0" {
		t.Errorf("issues = %q, want stringified 0", got)
	}
}

func TestResolveRepoDefaultAloneSource(t *testing.T) {
	out := resolvePermissions(permInputs{RepoDefault: "write"})
	if out["_source"] != "repo_default" {
		t.Errorf("_source = %v, want repo_default", out["_source"])
	}
	if got := scope(t, out, "contents"); got != "write" {
		t.Errorf("contents = %q, want write", got)
	}
	if got := scope(t, out, "id-token"); got != "none" {
		t.Errorf("id-token = %q, want none under repo_default write", got)
	}
	ch := chainOf(t, out)
	if len(ch) != 1 || ch[0]["source"] != "repo_default" {
		t.Errorf("_chain = %v, want single repo_default", ch)
	}
}

// An admin grant is preserved verbatim: no special handling, no opt-in filter.
func TestResolveAdminPassesThroughDict(t *testing.T) {
	out := resolvePermissions(permInputs{
		JobPerms: map[string]any{"security-events": "admin"},
	})
	if got := scope(t, out, "security-events"); got != "admin" {
		t.Errorf("security-events = %q, want admin", got)
	}
}

// An unknown org/repo default value (neither read nor write) adds no layer and is skipped by _source.
func TestResolveUnknownDefaultIsNoOp(t *testing.T) {
	out := resolvePermissions(permInputs{
		OrgDefault:    "",
		WorkflowPerms: "read-all",
	})
	if out["_source"] != "workflow" {
		t.Errorf("_source = %v, want workflow", out["_source"])
	}
	ch := chainOf(t, out)
	if len(ch) != 1 || ch[0]["source"] != "workflow" {
		t.Errorf("_chain = %v, want only workflow (empty org default is no-op)", ch)
	}
}

func sortedCopy(in []string) []string {
	out := slices.Clone(in)
	sort.Strings(out)
	return out
}
