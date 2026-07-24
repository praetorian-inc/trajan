package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// collectCIConfig fetches the raw .gitlab-ci.yml at the project's default branch;
// the ref must be taken from the project detail and URL-escaped. The raw bytes are
// written verbatim (not enveloped) so the include-resolver can parse the YAML.
func TestCollectCIConfigUsesDefaultBranch(t *testing.T) {
	var gotRef, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRef = r.URL.Query().Get("ref")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("stages:\n  - build\n"))
	}))
	defer srv.Close()
	cl := NewClient(srv.URL, "t", false, 1)
	cp := engine.CurrentPhase{RunDir: t.TempDir()}

	projRaw := json.RawMessage(`{"id":7,"default_branch":"develop"}`)
	if err := collectCIConfig(context.Background(), cl, cp, "g/p", "/projects/7", projRaw); err != nil {
		t.Fatalf("collectCIConfig: %v", err)
	}
	if gotRef != "develop" {
		t.Errorf("ref = %q, want develop (the project default_branch)", gotRef)
	}
	if !strings.Contains(gotPath, url.PathEscape(".gitlab-ci.yml")) {
		t.Errorf("path = %q, want the escaped .gitlab-ci.yml", gotPath)
	}
	b, err := readRaw(cp.RunDir, engine.CollectGLCIConfig("g/p", ".gitlab-ci.yml"))
	if err != nil {
		t.Fatalf("ci-config not written: %v", err)
	}
	if string(b) != "stages:\n  - build\n" {
		t.Errorf("ci-config bytes = %q, want the raw yaml verbatim", b)
	}
}

// With no default_branch on the project detail, the collector falls back to "main".
func TestCollectCIConfigDefaultBranchFallback(t *testing.T) {
	var gotRef string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRef = r.URL.Query().Get("ref")
		w.Write([]byte("x"))
	}))
	defer srv.Close()
	cl := NewClient(srv.URL, "t", false, 1)
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	if err := collectCIConfig(context.Background(), cl, cp, "g/p", "/projects/7", json.RawMessage(`{"id":7}`)); err != nil {
		t.Fatalf("collectCIConfig: %v", err)
	}
	if gotRef != "main" {
		t.Errorf("ref = %q, want main fallback when default_branch absent", gotRef)
	}
}

// A missing .gitlab-ci.yml (404 -> GetRaw allow404 -> nil body) is not an error and
// writes no file: absence of a config is a legitimate, non-fatal state.
func TestCollectCIConfigAbsentWritesNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	cl := NewClient(srv.URL, "t", false, 1)
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	if err := collectCIConfig(context.Background(), cl, cp, "g/p", "/projects/7", json.RawMessage(`{"default_branch":"main"}`)); err != nil {
		t.Fatalf("absent ci-config must be non-fatal: %v", err)
	}
	if _, err := readRaw(cp.RunDir, engine.CollectGLCIConfig("g/p", ".gitlab-ci.yml")); err == nil {
		t.Error("a file was written for an absent .gitlab-ci.yml, want none")
	}
}

// collectProjectCISettings folds the GraphQL ciCdSettings and the REST
// job_token_scope + inbound allowlist entries into a single file. When one half
// soft-fails, only that half is marked _unobserved; the other keeps its data.
func TestCollectProjectCISettingsBundle(t *testing.T) {
	cl := newFake()
	base := "/projects/7"
	cl.graphql[projectCICdQuery] = json.RawMessage(`{"data":{"project":{"ciCdSettings":{"jobTokenScopeEnabled":true}}}}`)
	cl.softPath[base+"/job_token_scope"] = http.StatusForbidden
	cl.list[base+"/job_token_scope/allowlist"] = []json.RawMessage{json.RawMessage(`{"target_project_id":9}`)}
	cp := engine.CurrentPhase{RunDir: t.TempDir()}

	if err := collectProjectCISettings(context.Background(), cl, cp, "g/p", base); err != nil {
		t.Fatalf("collectProjectCISettings: %v", err)
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(readEnvelope(t, cp.RunDir, engine.CollectGLCISettings("g/p"))["data"], &data); err != nil {
		t.Fatalf("data: %v", err)
	}
	if got := compact(t, data["ci_cd_settings"]); got != `{"project":{"ciCdSettings":{"jobTokenScopeEnabled":true}}}` {
		t.Errorf("ci_cd_settings = %s, want the graphql data half", got)
	}
	if got := compact(t, data["job_token_scope"]); got != `{"_unobserved":403}` {
		t.Errorf("job_token_scope = %s, want _unobserved:403 (the forbidden REST half)", got)
	}
	if got := compact(t, data["job_token_allowlist"]); got != `[{"target_project_id":9}]` {
		t.Errorf("job_token_allowlist = %s, want the inbound project allowlist entries", got)
	}
	// The absent groups_allowlist must serialize as [] (rules gate on != []), never null.
	if got := compact(t, data["job_token_groups_allowlist"]); got != `[]` {
		t.Errorf("job_token_groups_allowlist = %s, want [] for an empty allowlist", got)
	}
}

// The security-policies surface is GraphQL: a null-data-with-errors response marks
// _unobserved and must be tagged with the graphql source api.
func TestCollectSecurityPoliciesSoftFail(t *testing.T) {
	cl := newFake()
	cl.graphql[securityPolicyQuery] = json.RawMessage(`{"errors":[{"message":"FORBIDDEN"}]}`)
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	if err := collectSecurityPolicies(context.Background(), cl, cp, "g/p"); err != nil {
		t.Fatalf("collectSecurityPolicies soft-fail must not error: %v", err)
	}
	env := readEnvelope(t, cp.RunDir, engine.CollectGLSecurityPolicies("g/p"))
	if got := compact(t, env["data"]); got != `{"_unobserved":403}` {
		t.Errorf("security-policies data = %s, want _unobserved:403", got)
	}
	var meta collectMeta
	json.Unmarshal(env["_meta"], &meta)
	if meta.Source.API != sourceGQL {
		t.Errorf("security-policies source api = %q, want %q", meta.Source.API, sourceGQL)
	}
}
