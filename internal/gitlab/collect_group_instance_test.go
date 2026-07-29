package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// collectGroupSurfaces writes the group detail from the already-fetched raw (no
// extra GET), lists each sub-surface, and derives ci-settings from a GET on the
// group root. A mix of present and forbidden surfaces must all leave a file: the
// present ones with data, the forbidden ones marked _unobserved.
func TestCollectGroupSurfacesFanOut(t *testing.T) {
	cl := newFake()
	gid := int64(42)
	base := "/groups/42"
	cl.list[base+"/subgroups"] = []json.RawMessage{json.RawMessage(`{"id":7}`)}
	cl.softPath[base+"/members/all"] = http.StatusForbidden
	cl.get[base] = json.RawMessage(`{"id":42,"project_creation_role":"maintainer"}`)
	cl.get["/namespaces/42"] = json.RawMessage(`{"id":42,"plan":"ultimate"}`)

	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	timer := engine.StartPhaseTimer(engine.PhaseCollect, "collect")
	groupRaw := json.RawMessage(`{"id":42,"full_path":"g"}`)

	collectGroupSurfaces(context.Background(), cl, cp, "g", gid, groupRaw, timer)

	// detail comes straight from groupRaw, not a re-fetch.
	if got := compact(t, readEnvelope(t, cp.RunDir, engine.CollectGLGroup("g"))["data"]); got != `{"id":42,"full_path":"g"}` {
		t.Errorf("group detail = %s, want the passed-in groupRaw", got)
	}
	// a present list surface holds its items
	if got := compact(t, readEnvelope(t, cp.RunDir, engine.CollectGLSubgroups("g"))["data"]); got != `[{"id":7}]` {
		t.Errorf("subgroups = %s, want [{\"id\":7}]", got)
	}
	// a forbidden list surface is marked, not omitted
	if got := compact(t, readEnvelope(t, cp.RunDir, engine.CollectGLGroupMembers("g"))["data"]); got != `{"_unobserved":403}` {
		t.Errorf("members = %s, want _unobserved:403", got)
	}
	// ci-settings comes off a GET of the group root
	if got := compact(t, readEnvelope(t, cp.RunDir, engine.CollectGLGroupCISettings("g"))["data"]); got != `{"id":42,"project_creation_role":"maintainer"}` {
		t.Errorf("ci-settings = %s, want the group-root body", got)
	}
	// namespace plan (agent.namespace_plan) comes off GET /namespaces/:id
	if got := compact(t, readEnvelope(t, cp.RunDir, engine.CollectGLNamespace("g"))["data"]); got != `{"id":42,"plan":"ultimate"}` {
		t.Errorf("namespace = %s, want the namespace plan body", got)
	}
}

// The group duo surface is GraphQL-sourced: a FORBIDDEN response marks _unobserved
// with the graphql api tag, and the meta source api must be gitlab_graphql (not the
// REST default) so downstream can tell where it came from.
func TestCollectGroupDuoSoftFailTagsGraphQL(t *testing.T) {
	cl := newFake()
	cl.graphql[groupDuoQuery] = json.RawMessage(`{"errors":[{"message":"FORBIDDEN"}]}`)
	cp := engine.CurrentPhase{RunDir: t.TempDir()}

	if err := collectGroupDuo(context.Background(), cl, cp, "g"); err != nil {
		t.Fatalf("collectGroupDuo soft-fail must not error: %v", err)
	}
	env := readEnvelope(t, cp.RunDir, engine.CollectGLGroupDuo("g"))
	if got := compact(t, env["data"]); got != `{"_unobserved":403}` {
		t.Errorf("duo data = %s, want _unobserved:403", got)
	}
	var meta collectMeta
	json.Unmarshal(env["_meta"], &meta)
	if meta.Source.API != sourceGQL {
		t.Errorf("duo source api = %q, want %q", meta.Source.API, sourceGQL)
	}
}

// Instance surfaces 403 on gitlab.com / non-admin tokens. Every one must still land
// a marked file rather than nothing — the whole point of soft-fail marking.
func TestCollectInstanceSurfacesAllForbiddenAreMarked(t *testing.T) {
	cl := newFake()
	cl.softPath["/admin/ci/variables"] = http.StatusForbidden
	cl.softPath["/runners/all"] = http.StatusForbidden
	cl.softPath["/application/settings"] = http.StatusForbidden
	cl.graphql[instanceDuoQuery] = json.RawMessage(`{"errors":[{"message":"FORBIDDEN"}]}`)
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	timer := engine.StartPhaseTimer(engine.PhaseCollect, "collect")

	collectInstanceSurfaces(context.Background(), cl, cp, timer)

	for _, rel := range []string{
		engine.CollectGLInstanceVariables(),
		engine.CollectGLInstanceRunners(),
		engine.CollectGLInstanceSettings(),
		engine.CollectGLInstanceDuo(),
	} {
		env, err := readEnvelopeErr(cp.RunDir, rel)
		if err != nil {
			t.Errorf("instance surface %s was not written on 403: %v", rel, err)
			continue
		}
		if got := compact(t, env["data"]); got != `{"_unobserved":403}` {
			t.Errorf("%s data = %s, want _unobserved:403", rel, got)
		}
	}
}
