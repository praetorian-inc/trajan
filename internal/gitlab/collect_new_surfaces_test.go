package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// enrichRunners must fetch GET /runners/:id and fold the detail (run_untagged,
// access_level, locked, tag_list — the runner-subject rule fields) onto the bare
// list record. The list endpoint alone omits them, so without this merge the rules
// key on absent fields.
func TestEnrichRunnersMergesDetail(t *testing.T) {
	cl := newFake()
	base := "/projects/7"
	cl.list[base+"/runners"] = []json.RawMessage{json.RawMessage(`{"id":11,"description":"r11"}`)}
	cl.get["/runners/11"] = json.RawMessage(`{"id":11,"run_untagged":false,"access_level":"ref_protected","locked":true,"tag_list":["deploy"]}`)
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	timer := engine.StartPhaseTimer(engine.PhaseCollect, "collect")

	if err := collectProjectRunners(context.Background(), cl, cp, "g/p", base, timer); err != nil {
		t.Fatalf("collectProjectRunners: %v", err)
	}
	var runners []map[string]json.RawMessage
	if err := json.Unmarshal(readEnvelope(t, cp.RunDir, engine.CollectGLProjectRunners("g/p"))["data"], &runners); err != nil {
		t.Fatalf("data: %v", err)
	}
	if len(runners) != 1 {
		t.Fatalf("got %d runners, want 1", len(runners))
	}
	r := runners[0]
	for k, want := range map[string]string{
		"run_untagged": "false",
		"access_level": `"ref_protected"`,
		"locked":       "true",
		"tag_list":     `["deploy"]`,
		"description":  `"r11"`, // list-only field preserved through the merge
	} {
		if got := compact(t, r[k]); got != want {
			t.Errorf("runner.%s = %s, want %s", k, got, want)
		}
	}
}

// A soft 403 on the per-runner detail fetch must not drop the runner: the bare list
// record survives (the enrich is best-effort), and no fatal error propagates.
func TestEnrichRunnersDetailSoftFailKeepsBare(t *testing.T) {
	cl := newFake()
	base := "/projects/7"
	cl.list[base+"/runners"] = []json.RawMessage{json.RawMessage(`{"id":11,"description":"r11"}`)}
	cl.softPath["/runners/11"] = http.StatusForbidden
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	timer := engine.StartPhaseTimer(engine.PhaseCollect, "collect")

	if err := collectProjectRunners(context.Background(), cl, cp, "g/p", base, timer); err != nil {
		t.Fatalf("collectProjectRunners: %v", err)
	}
	if got := compact(t, readEnvelope(t, cp.RunDir, engine.CollectGLProjectRunners("g/p"))["data"]); got != `[{"id":11,"description":"r11"}]` {
		t.Errorf("runner list = %s, want the bare record preserved", got)
	}
}

// mergeRaw overlays detail keys onto base (detail wins on collision) and returns nil
// when either side is a non-object so the caller falls back to the original.
func TestMergeRaw(t *testing.T) {
	got := mergeRaw(json.RawMessage(`{"a":1,"b":2}`), json.RawMessage(`{"b":3,"c":4}`))
	var m map[string]int
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("merged not an object: %v", err)
	}
	if m["a"] != 1 || m["b"] != 3 || m["c"] != 4 {
		t.Errorf("merged = %v, want {a:1,b:3,c:4} (detail wins on b)", m)
	}
	if mergeRaw(json.RawMessage(`[1,2]`), json.RawMessage(`{"x":1}`)) != nil {
		t.Error("mergeRaw with a non-object base should return nil")
	}
}

// collectClusterAgents writes the grant graph, then for each named agent fetches
// .gitlab/agents/<name>/config.yaml (the source for config_path, ci_access
// environments filter, protected_branches_only, access_as, default_permissions).
func TestCollectClusterAgentsFetchesConfig(t *testing.T) {
	cl := newFake()
	base := "/projects/7"
	cl.graphql[clusterAgentsQuery] = json.RawMessage(`{"data":{"project":{"clusterAgents":{"nodes":[{"id":"gid://1","name":"prod"}]}}}}`)
	cfgAPI := base + "/repository/files/" + url.PathEscape(".gitlab/agents/prod/config.yaml") + "/raw"
	cl.get[cfgAPI] = json.RawMessage("ci_access:\n  groups:\n    - id: g\n")
	cp := engine.CurrentPhase{RunDir: t.TempDir()}

	projRaw := json.RawMessage(`{"default_branch":"main"}`)
	if err := collectClusterAgents(context.Background(), cl, cp, "g/p", base, projRaw); err != nil {
		t.Fatalf("collectClusterAgents: %v", err)
	}
	b, err := readRaw(cp.RunDir, engine.CollectGLAgentConfig("g/p", "prod"))
	if err != nil {
		t.Fatalf("agent config not written: %v", err)
	}
	if !strings.Contains(string(b), "ci_access") {
		t.Errorf("agent config = %q, want the raw config.yaml", b)
	}
}

// Group SAML backs group.saml_provisioning_active (cat-12). It is admin/UI-gated
// and 401/404s on tenant tokens; the collector must still land a marked file so
// normalize can tell "no access" from "not collected".
func TestCollectGroupSAMLSoftFailMarked(t *testing.T) {
	cl := newFake()
	base := "/groups/42"
	cl.softPath[base+"/saml"] = http.StatusNotFound
	cl.get[base] = json.RawMessage(`{"id":42}`)
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	timer := engine.StartPhaseTimer(engine.PhaseCollect, "collect")

	collectGroupSurfaces(context.Background(), cl, cp, "g", 42, json.RawMessage(`{"id":42,"full_path":"g"}`), timer)

	env, err := readEnvelopeErr(cp.RunDir, engine.CollectGLGroupSAML("g"))
	if err != nil {
		t.Fatalf("group saml surface not written on 404: %v", err)
	}
	if got := compact(t, env["data"]); got != `{"_unobserved":404}` {
		t.Errorf("group saml data = %s, want _unobserved:404", got)
	}
}

// The service-accounts surface (credential.service_account) is admin-only; it must
// land a marked file when forbidden, and its data when present.
func TestCollectServiceAccountsMarkedAndPresent(t *testing.T) {
	cl := newFake()
	cl.softPath["/service_accounts"] = http.StatusForbidden
	cl.get["/user"] = json.RawMessage(`{"id":5}`)
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	timer := engine.StartPhaseTimer(engine.PhaseCollect, "collect")

	collectInstanceSurfaces(context.Background(), cl, cp, timer)

	if got := compact(t, readEnvelope(t, cp.RunDir, engine.CollectGLServiceAccounts())["data"]); got != `{"_unobserved":403}` {
		t.Errorf("service-accounts data = %s, want _unobserved:403", got)
	}
}

// backing_identity_breadth (cat-11): /users/:id/memberships is fetched for the
// token's own identity (id from /user). On a non-admin token it 403s and is marked.
func TestCollectSelfMemberships(t *testing.T) {
	cl := newFake()
	cl.get["/user"] = json.RawMessage(`{"id":5}`)
	cl.list["/users/5/memberships"] = []json.RawMessage{json.RawMessage(`{"source_id":1,"access_level":30}`)}
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	timer := engine.StartPhaseTimer(engine.PhaseCollect, "collect")

	collectInstanceSurfaces(context.Background(), cl, cp, timer)

	if got := compact(t, readEnvelope(t, cp.RunDir, engine.CollectGLUserMemberships(5))["data"]); got != `[{"source_id":1,"access_level":30}]` {
		t.Errorf("self memberships = %s, want the membership list", got)
	}
}

// When /user itself is unavailable, the memberships surface is skipped silently (no
// id to key on) — non-fatal, no file, no error.
func TestCollectSelfMembershipsNoUserSkips(t *testing.T) {
	cl := newFake()
	cl.softPath["/user"] = http.StatusUnauthorized
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	timer := engine.StartPhaseTimer(engine.PhaseCollect, "collect")

	collectInstanceSurfaces(context.Background(), cl, cp, timer)

	if len(timer.Errors) != 0 {
		t.Errorf("self-memberships skip must be silent, got errors: %v", timer.Errors)
	}
}

// A missing agent config.yaml (soft 404) is non-fatal and writes no config file, but
// the cluster-agents grant graph is still persisted.
func TestCollectClusterAgentsConfigAbsent(t *testing.T) {
	cl := newFake()
	base := "/projects/7"
	cl.graphql[clusterAgentsQuery] = json.RawMessage(`{"data":{"project":{"clusterAgents":{"nodes":[{"id":"gid://1","name":"prod"}]}}}}`)
	cp := engine.CurrentPhase{RunDir: t.TempDir()}

	if err := collectClusterAgents(context.Background(), cl, cp, "g/p", base, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("absent agent config must be non-fatal: %v", err)
	}
	if _, err := readRaw(cp.RunDir, engine.CollectGLAgentConfig("g/p", "prod")); err == nil {
		t.Error("a config file was written for an absent config.yaml, want none")
	}
	if _, err := readEnvelopeErr(cp.RunDir, engine.CollectGLClusterAgents("g/p")); err != nil {
		t.Errorf("cluster-agents grant graph not written: %v", err)
	}
}
