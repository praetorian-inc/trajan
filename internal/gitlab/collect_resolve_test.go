package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// runCollect first probes the full locator path as a GROUP. When that resolves,
// the scope stays a group and projects are enumerated under it. The group id (not
// the escaped path) must be used for the subgroup-project listing once known.
func TestRunCollectGroupScope(t *testing.T) {
	cl := newFake()
	cl.get["/groups/g%2Fsub"] = json.RawMessage(`{"id":42,"full_path":"g/sub"}`)
	cl.list["/groups/42/projects"] = []json.RawMessage{
		json.RawMessage(`{"id":100,"path_with_namespace":"g/sub/p"}`),
	}
	cl.get["/projects/100"] = json.RawMessage(`{"id":100,"default_branch":"main"}`)

	scope := Scope{Kind: ScopeGroup, Group: "g/sub", path: "g/sub"}
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	timer := engine.StartPhaseTimer(engine.PhaseCollect, "collect")

	if err := runCollect(context.Background(), &engine.Config{Concurrency: 2}, cl, cp, &scope, &engine.State{}, timer); err != nil {
		t.Fatalf("runCollect(group): %v", err)
	}
	if scope.Kind != ScopeGroup {
		t.Errorf("scope.Kind = %d, want ScopeGroup (group probe hit)", scope.Kind)
	}
	if scope.Project != "" {
		t.Errorf("scope.Project = %q, want empty for a group scope", scope.Project)
	}
	// The one enumerated project must have been collected (detail written).
	data := readEnvelope(t, cp.RunDir, engine.CollectGLProject("g/sub/p"))["data"]
	if compact(t, data) != `{"id":100,"default_branch":"main"}` {
		t.Errorf("project detail = %s, want the collected project body", data)
	}
}

// When the full path 404s as a group, runCollect re-probes it as a PROJECT and,
// on success, promotes the scope: Kind flips to project, Project is the full path,
// and Group is taken from the project's namespace.full_path — not the raw locator.
func TestRunCollectProjectScopePromotion(t *testing.T) {
	cl := newFake()
	cl.softPath["/groups/g%2Fsub%2Fp"] = http.StatusNotFound
	cl.get["/projects/g%2Fsub%2Fp"] = json.RawMessage(`{"id":100,"path_with_namespace":"g/sub/p","namespace":{"full_path":"g/sub"}}`)
	cl.get["/groups/g%2Fsub"] = json.RawMessage(`{"id":42,"full_path":"g/sub"}`)
	cl.list["/groups/42/projects"] = []json.RawMessage{
		json.RawMessage(`{"id":100,"path_with_namespace":"g/sub/p"}`),
		json.RawMessage(`{"id":101,"path_with_namespace":"g/sub/other"}`),
	}
	cl.get["/projects/100"] = json.RawMessage(`{"id":100}`)

	scope := Scope{Kind: ScopeGroup, Group: "g/sub/p", path: "g/sub/p"}
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	timer := engine.StartPhaseTimer(engine.PhaseCollect, "collect")

	if err := runCollect(context.Background(), &engine.Config{Concurrency: 2}, cl, cp, &scope, &engine.State{}, timer); err != nil {
		t.Fatalf("runCollect(project): %v", err)
	}
	if scope.Kind != ScopeProject {
		t.Errorf("scope.Kind = %d, want ScopeProject after group-404 promotion", scope.Kind)
	}
	if scope.Project != "g/sub/p" {
		t.Errorf("scope.Project = %q, want g/sub/p", scope.Project)
	}
	if scope.Group != "g/sub" {
		t.Errorf("scope.Group = %q, want g/sub (from namespace.full_path)", scope.Group)
	}
	// Enumeration returned two projects but the project scope must collect only the
	// filtered one.
	if _, err := readEnvelopeErr(cp.RunDir, engine.CollectGLProject("g/sub/other")); err == nil {
		t.Error("g/sub/other was collected, but the project scope must filter it out")
	}
	if _, err := readEnvelopeErr(cp.RunDir, engine.CollectGLProject("g/sub/p")); err != nil {
		t.Errorf("scoped project g/sub/p was not collected: %v", err)
	}
}

// A path that resolves as NEITHER a group nor a project is a fatal scope error —
// the run cannot proceed with nothing to collect.
func TestRunCollectUnresolvableScopeIsFatal(t *testing.T) {
	cl := newFake()
	cl.softPath["/groups/nope"] = http.StatusNotFound
	cl.softPath["/projects/nope"] = http.StatusNotFound

	scope := Scope{Kind: ScopeGroup, Group: "nope", path: "nope"}
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	timer := engine.StartPhaseTimer(engine.PhaseCollect, "collect")

	err := runCollect(context.Background(), &engine.Config{Concurrency: 1}, cl, cp, &scope, &engine.State{}, timer)
	if err == nil {
		t.Fatal("runCollect(unresolvable) = nil error, want a fatal scope error")
	}
}

// A genuine (non-soft) transport error during the group probe aborts the phase —
// it is not swallowed as "group absent".
func TestRunCollectGroupProbeTransportErrorAborts(t *testing.T) {
	cl := newFake()
	cl.softPath["/groups/g"] = http.StatusInternalServerError

	scope := Scope{Kind: ScopeGroup, Group: "g", path: "g"}
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	timer := engine.StartPhaseTimer(engine.PhaseCollect, "collect")

	if err := runCollect(context.Background(), &engine.Config{Concurrency: 1}, cl, cp, &scope, &engine.State{}, timer); err == nil {
		t.Fatal("runCollect(group 500) = nil error, want the transport error propagated")
	}
}

func TestNamespaceFullPath(t *testing.T) {
	cases := map[string]string{
		`{"namespace":{"full_path":"g/sub"}}`: "g/sub",
		`{"namespace":{}}`:                    "",
		`{}`:                                  "",
	}
	for in, want := range cases {
		if got := namespaceFullPath(json.RawMessage(in)); got != want {
			t.Errorf("namespaceFullPath(%s) = %q, want %q", in, got, want)
		}
	}
}

// enumerateProjects drops entries missing an id or path_with_namespace (they can't
// be collected), and a soft 403 on the list yields (nil, nil) — an empty seed set,
// not a fatal error.
func TestEnumerateProjectsFiltersAndSoftFails(t *testing.T) {
	cl := newFake()
	cl.list["/groups/42/projects"] = []json.RawMessage{
		json.RawMessage(`{"id":1,"path_with_namespace":"g/a"}`),
		json.RawMessage(`{"id":0,"path_with_namespace":"g/b"}`), // no id
		json.RawMessage(`{"id":2}`),                             // no path
		json.RawMessage(`{"id":3,"path_with_namespace":"g/c"}`),
	}
	cp := engine.CurrentPhase{RunDir: t.TempDir()}

	out, err := enumerateProjects(context.Background(), cl, cp, "g", 42)
	if err != nil {
		t.Fatalf("enumerateProjects: %v", err)
	}
	if len(out) != 2 || out[0].FullPath != "g/a" || out[1].FullPath != "g/c" {
		t.Errorf("enumerated = %+v, want only the two well-formed refs g/a, g/c", out)
	}

	cl.softPath["/groups/g/projects"] = http.StatusForbidden
	out, err = enumerateProjects(context.Background(), cl, cp, "g", 0) // gid 0 -> escaped path
	if err != nil {
		t.Fatalf("enumerateProjects(soft 403) = fatal error: %v", err)
	}
	if out != nil {
		t.Errorf("enumerateProjects(soft 403) = %+v, want nil (empty, non-fatal)", out)
	}
}

func TestFilterProjects(t *testing.T) {
	projects := []projectRef{
		{ID: 1, FullPath: "g/One"},
		{ID: 2, FullPath: "g/two"},
	}
	// Match is case-insensitive.
	got := filterProjects(projects, "g/one")
	if len(got) != 1 || got[0].ID != 1 {
		t.Errorf("filterProjects(g/one) = %+v, want the g/One ref", got)
	}
	// No match yields an empty (nil) set, not the full list.
	if got := filterProjects(projects, "g/absent"); got != nil {
		t.Errorf("filterProjects(no match) = %+v, want nil", got)
	}
}

func TestGroupRefPrefersNumericID(t *testing.T) {
	if got := groupRef("g/sub", 42); got != "42" {
		t.Errorf("groupRef with id = %q, want 42", got)
	}
	// Unknown id (0) falls back to the URL-escaped path.
	if got := groupRef("g/sub", 0); got != "g%2Fsub" {
		t.Errorf("groupRef without id = %q, want g%%2Fsub", got)
	}
}
