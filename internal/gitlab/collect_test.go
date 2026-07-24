package gitlab

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// fakeGitLab implements the GitLab surface so collectors can be driven without a
// network. Responses are keyed by request path; a missing key returns a soft 404
// (matching allow404 behavior) so tests only wire the paths they care about.
type fakeGitLab struct {
	get      map[string]json.RawMessage
	list     map[string][]json.RawMessage
	graphql  map[string]json.RawMessage // keyed by exact query string
	softPath map[string]int             // path -> soft status to raise
	gqlErr   map[string]error           // query -> transport error
	paths    []string                   // observed GET/list paths, in call order
}

func newFake() *fakeGitLab {
	return &fakeGitLab{
		get:      map[string]json.RawMessage{},
		list:     map[string][]json.RawMessage{},
		graphql:  map[string]json.RawMessage{},
		softPath: map[string]int{},
		gqlErr:   map[string]error{},
	}
}

func (f *fakeGitLab) softErr(p string) error {
	if s, ok := f.softPath[p]; ok {
		return &GitLabError{Status: s, URL: p}
	}
	return nil
}

func (f *fakeGitLab) Get(_ context.Context, p string, _ url.Values, allow404 bool) (json.RawMessage, http.Header, error) {
	f.paths = append(f.paths, p)
	if err := f.softErr(p); err != nil {
		return nil, nil, err
	}
	if v, ok := f.get[p]; ok {
		return v, http.Header{}, nil
	}
	if allow404 {
		return nil, http.Header{}, nil
	}
	return nil, nil, &GitLabError{Status: 404, URL: p}
}

func (f *fakeGitLab) GetRaw(_ context.Context, p string, _ url.Values) ([]byte, http.Header, error) {
	f.paths = append(f.paths, p)
	if err := f.softErr(p); err != nil {
		return nil, nil, err
	}
	if v, ok := f.get[p]; ok {
		return v, http.Header{"Content-Type": {"text/plain"}}, nil
	}
	return nil, http.Header{}, nil
}

func (f *fakeGitLab) Paginate(_ context.Context, p string, _ url.Values) ([]json.RawMessage, error) {
	f.paths = append(f.paths, p)
	if err := f.softErr(p); err != nil {
		return nil, err
	}
	return f.list[p], nil
}

func (f *fakeGitLab) GraphQL(_ context.Context, query string, _ map[string]any) (json.RawMessage, error) {
	if err := f.gqlErr[query]; err != nil {
		return nil, err
	}
	if v, ok := f.graphql[query]; ok {
		return v, nil
	}
	return json.RawMessage(`{"data":null}`), nil
}

// compact strips WriteJSON's indentation so on-disk data can be compared to a
// canonical one-line form.
func compact(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		t.Fatalf("compact %s: %v", raw, err)
	}
	return buf.String()
}

func readEnvelope(t *testing.T, runDir, rel string) map[string]json.RawMessage {
	t.Helper()
	m, err := readEnvelopeErr(runDir, rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return m
}

// readEnvelopeErr reads an envelope but surfaces the error instead of failing, so
// tests can assert a surface was NOT written (file absent).
func readEnvelopeErr(runDir, rel string) (map[string]json.RawMessage, error) {
	b, err := os.ReadFile(filepath.Join(runDir, rel))
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func readRaw(runDir, rel string) ([]byte, error) {
	return os.ReadFile(filepath.Join(runDir, rel))
}

// The envelope must always carry _meta (with a versioned collector + source) and
// a data key — downstream normalization keys on this exact shape.
func TestEnvelopeShape(t *testing.T) {
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	rel := "00-collect/x.json"
	if err := envelope(cp, rel, "project", "/projects/1", json.RawMessage(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	env := readEnvelope(t, cp.RunDir, rel)

	var meta collectMeta
	if err := json.Unmarshal(env["_meta"], &meta); err != nil {
		t.Fatalf("_meta: %v", err)
	}
	if meta.Collector != "project"+collectorVer {
		t.Errorf("collector = %q, want project%s", meta.Collector, collectorVer)
	}
	if meta.Source.API != sourceAPI || meta.Source.Path != "/projects/1" {
		t.Errorf("source = %+v, want {%s /projects/1}", meta.Source, sourceAPI)
	}
	if meta.CollectedAt == "" {
		t.Error("collected_at empty")
	}
	if got := compact(t, env["data"]); got != `{"ok":true}` {
		t.Errorf("data = %s, want {\"ok\":true}", got)
	}
}

func TestEnvelopeSrcOverridesAPI(t *testing.T) {
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	rel := "00-collect/g.json"
	if err := envelopeSrc(cp, rel, "group-duo", sourceGQL, "graphql:x", json.RawMessage(`1`)); err != nil {
		t.Fatal(err)
	}
	var meta collectMeta
	json.Unmarshal(readEnvelope(t, cp.RunDir, rel)["_meta"], &meta)
	if meta.Source.API != sourceGQL {
		t.Errorf("api = %q, want %q", meta.Source.API, sourceGQL)
	}
}

// A soft-failed surface must persist a {"_unobserved":<status>} marker inside the
// data key, distinguishing "no access" from "collected, empty".
func TestWriteOrMarkUnobserved(t *testing.T) {
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	rel := "00-collect/pr.json"
	if err := writeOrMark(cp, rel, "push-rules", "/projects/1/push_rule", nil, http.StatusForbidden); err != nil {
		t.Fatal(err)
	}
	data := readEnvelope(t, cp.RunDir, rel)["data"]
	var d struct {
		Unobserved int `json:"_unobserved"`
	}
	json.Unmarshal(data, &d)
	if d.Unobserved != http.StatusForbidden {
		t.Errorf("data = %s, want _unobserved:403", data)
	}
}

func TestWriteOrMarkSuccessWritesRaw(t *testing.T) {
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	rel := "00-collect/pr.json"
	if err := writeOrMark(cp, rel, "push-rules", "/p", json.RawMessage(`{"a":1}`), 0); err != nil {
		t.Fatal(err)
	}
	if got := compact(t, readEnvelope(t, cp.RunDir, rel)["data"]); got != `{"a":1}` {
		t.Errorf("data = %s, want {\"a\":1}", got)
	}
}

// listOrMark: an empty successful list must serialize as [], not null (rules do
// membership/length checks on it); a soft-failed list must mark _unobserved.
func TestListOrMarkEmptyIsArray(t *testing.T) {
	b, _ := json.Marshal(listOrMark(nil, 0))
	if string(b) != `[]` {
		t.Errorf("empty successful list = %s, want []", b)
	}
	b, _ = json.Marshal(listOrMark([]json.RawMessage{json.RawMessage(`1`)}, 0))
	if string(b) != `[1]` {
		t.Errorf("list = %s, want [1]", b)
	}
	b, _ = json.Marshal(listOrMark(nil, http.StatusNotFound))
	if string(b) != `{"_unobserved":404}` {
		t.Errorf("soft-failed list = %s, want _unobserved:404", b)
	}
}

func TestWriteListOrMarkEmptyOnDisk(t *testing.T) {
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	rel := "00-collect/members/group/g.json"
	if err := writeListOrMark(cp, rel, "group-members", "/groups/1/members/all", nil, 0); err != nil {
		t.Fatal(err)
	}
	if got := string(readEnvelope(t, cp.RunDir, rel)["data"]); got != `[]` {
		t.Errorf("on-disk empty list data = %s, want []", got)
	}
}

func TestRawArrayNilBecomesEmpty(t *testing.T) {
	if got := rawArray(nil); got == nil || len(got) != 0 {
		t.Errorf("rawArray(nil) = %v, want non-nil empty slice", got)
	}
}

// softGet maps 401/403/404 to a status (non-fatal, raw nil), a nil body under
// allow404 to 404, and propagates any non-soft error.
func TestSoftGetClassification(t *testing.T) {
	cl := newFake()
	cl.softPath["/forbidden"] = http.StatusForbidden
	cl.softPath["/server"] = http.StatusInternalServerError
	cl.get["/ok"] = json.RawMessage(`{"x":1}`)

	if raw, status, err := softGet(context.Background(), cl, "/ok", nil); err != nil || status != 0 || string(raw) != `{"x":1}` {
		t.Errorf("softGet(/ok) = (%s,%d,%v), want ({\"x\":1},0,nil)", raw, status, err)
	}
	if _, status, err := softGet(context.Background(), cl, "/forbidden", nil); err != nil || status != http.StatusForbidden {
		t.Errorf("softGet(/forbidden) = (%d,%v), want (403,nil)", status, err)
	}
	// absent path under allow404 -> synthesized 404, non-fatal
	if _, status, err := softGet(context.Background(), cl, "/missing", nil); err != nil || status != 404 {
		t.Errorf("softGet(/missing) = (%d,%v), want (404,nil)", status, err)
	}
	// a 500 is NOT soft: it must propagate as a fatal error
	if _, _, err := softGet(context.Background(), cl, "/server", nil); err == nil {
		t.Error("softGet(/server 500) = nil error, want propagated error")
	}
}

func TestSoftListClassification(t *testing.T) {
	cl := newFake()
	cl.softPath["/deny"] = http.StatusUnauthorized
	cl.list["/items"] = []json.RawMessage{json.RawMessage(`1`)}

	if items, status, err := softList(context.Background(), cl, "/items", nil); err != nil || status != 0 || len(items) != 1 {
		t.Errorf("softList(/items) = (%d items,%d,%v)", len(items), status, err)
	}
	if _, status, err := softList(context.Background(), cl, "/deny", nil); err != nil || status != http.StatusUnauthorized {
		t.Errorf("softList(/deny) = (%d,%v), want (401,nil)", status, err)
	}
}

// graphQLSoft treats a FORBIDDEN-with-null-data response as a soft 403, a
// transport soft error as its status, and returns data when present.
func TestGraphQLSoft(t *testing.T) {
	cl := newFake()
	const qData = "query{ok}"
	const qForbidden = "query{denied}"
	const qTransport = "query{boom}"
	cl.graphql[qData] = json.RawMessage(`{"data":{"project":{"id":1}}}`)
	// A top-level auth failure carries errors and NO data key; graphQLSoft treats
	// that (errors present, data absent) as a soft 403.
	cl.graphql[qForbidden] = json.RawMessage(`{"errors":[{"message":"FORBIDDEN"}]}`)
	cl.gqlErr[qTransport] = &GitLabError{Status: http.StatusNotFound, URL: "gql"}

	if data, status, err := graphQLSoft(context.Background(), cl, qData, nil); err != nil || status != 0 || string(data) != `{"project":{"id":1}}` {
		t.Errorf("graphQLSoft(data) = (%s,%d,%v)", data, status, err)
	}
	if _, status, err := graphQLSoft(context.Background(), cl, qForbidden, nil); err != nil || status != http.StatusForbidden {
		t.Errorf("graphQLSoft(forbidden) = (%d,%v), want (403,nil)", status, err)
	}
	if _, status, err := graphQLSoft(context.Background(), cl, qTransport, nil); err != nil || status != http.StatusNotFound {
		t.Errorf("graphQLSoft(transport 404) = (%d,%v), want (404,nil)", status, err)
	}
}

// A response whose data key is present-but-null (field-level auth denial, where
// GitLab still returns 200 with data:{project:null}) is NOT a forbidden-mark case:
// the 403 mark only fires when the data key is absent. Pin this so the boundary
// isn't accidentally widened.
func TestGraphQLSoftNullDataIsSuccess(t *testing.T) {
	cl := newFake()
	const q = "query{fielddenied}"
	cl.graphql[q] = json.RawMessage(`{"data":{"project":null},"errors":[{"message":"denied"}]}`)
	data, status, err := graphQLSoft(context.Background(), cl, q, nil)
	if err != nil || status != 0 {
		t.Fatalf("graphQLSoft(null-data) = (%d,%v), want (0,nil)", status, err)
	}
	if string(data) != `{"project":null}` {
		t.Errorf("data = %s, want {\"project\":null}", data)
	}
}

// collectProjectVariables must strip the `value` field before writing (values are
// never collected) while keeping the rest of each variable, and still emit [] on a
// soft-failed list.
func TestCollectProjectVariablesStripsValue(t *testing.T) {
	cl := newFake()
	base := "/projects/7"
	cl.list[base+"/variables"] = []json.RawMessage{
		json.RawMessage(`{"key":"SECRET","value":"hunter2","protected":true}`),
		json.RawMessage(`{"key":"PUBLIC","value":"x"}`),
	}
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	if err := collectProjectVariables(context.Background(), cl, cp, "g/p", base); err != nil {
		t.Fatal(err)
	}
	data := readEnvelope(t, cp.RunDir, engine.CollectGLProjectVariables("g/p"))["data"]
	var vars []map[string]json.RawMessage
	if err := json.Unmarshal(data, &vars); err != nil {
		t.Fatalf("data: %v", err)
	}
	if len(vars) != 2 {
		t.Fatalf("got %d variables, want 2", len(vars))
	}
	for _, v := range vars {
		if _, leaked := v["value"]; leaked {
			t.Errorf("variable %s still carries value: %v", v["key"], v)
		}
		if _, ok := v["key"]; !ok {
			t.Errorf("variable lost its key: %v", v)
		}
	}
	if string(vars[0]["protected"]) != "true" {
		t.Errorf("non-value fields dropped: %v", vars[0])
	}
}

func TestCollectProjectVariablesSoftFailMarks(t *testing.T) {
	cl := newFake()
	base := "/projects/7"
	cl.softPath[base+"/variables"] = http.StatusForbidden
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	if err := collectProjectVariables(context.Background(), cl, cp, "g/p", base); err != nil {
		t.Fatalf("soft-fail must not error: %v", err)
	}
	data := readEnvelope(t, cp.RunDir, engine.CollectGLProjectVariables("g/p"))["data"]
	if got := compact(t, data); got != `{"_unobserved":403}` {
		t.Errorf("data = %s, want _unobserved:403", got)
	}
}

// collectOneProject wires ~25 surfaces. Even when every optional surface 403/404s,
// it must not return an error (soft-fail is non-fatal) and every soft surface must
// leave a marked file behind rather than nothing.
func TestCollectOneProjectSoftFailsAreNonFatal(t *testing.T) {
	cl := newFake() // no paths registered -> detail 404s (allow404), lists empty, graphql null
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	timer := engine.StartPhaseTimer(engine.PhaseCollect, "collect")

	err := collectOneProject(context.Background(), cl, cp, projectRef{ID: 7, FullPath: "g/p"}, timer)
	if err != nil {
		t.Fatalf("collectOneProject returned fatal error on all-soft-fail: %v", err)
	}
	// detail was fetched with allow404 -> synthesized 404 -> _unobserved marker written
	data := readEnvelope(t, cp.RunDir, engine.CollectGLProject("g/p"))["data"]
	if got := compact(t, data); got != `{"_unobserved":404}` {
		t.Errorf("project detail data = %s, want _unobserved:404", got)
	}
	// a list surface with no data writes [] (collected, empty)
	pb := readEnvelope(t, cp.RunDir, engine.CollectGLProtectedBranches("g/p"))["data"]
	if got := compact(t, pb); got != `[]` {
		t.Errorf("protected-branches data = %s, want []", got)
	}
}

// collectProjectRunners enriches each listed runner with its co-residency project
// set. A per-runner soft 403 marks that runner's file _unobserved (via softList)
// rather than aborting the surface.
func TestCollectProjectRunnersEnrichment(t *testing.T) {
	cl := newFake()
	base := "/projects/7"
	cl.list[base+"/runners"] = []json.RawMessage{
		json.RawMessage(`{"id":11}`),
		json.RawMessage(`{"id":12}`),
	}
	cl.list["/runners/11/projects"] = []json.RawMessage{json.RawMessage(`{"id":100}`)}
	cl.softPath["/runners/12/projects"] = http.StatusForbidden
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	timer := engine.StartPhaseTimer(engine.PhaseCollect, "collect")

	if err := collectProjectRunners(context.Background(), cl, cp, "g/p", base, timer); err != nil {
		t.Fatalf("collectProjectRunners: %v", err)
	}
	r11 := readEnvelope(t, cp.RunDir, engine.CollectGLRunnerProjects(11))["data"]
	if got := compact(t, r11); got != `[{"id":100}]` {
		t.Errorf("runner 11 projects = %s, want [{\"id\":100}]", got)
	}
	// runner 12's co-residency 403'd via softList -> marked _unobserved, not fatal
	r12 := readEnvelope(t, cp.RunDir, engine.CollectGLRunnerProjects(12))["data"]
	if got := compact(t, r12); got != `{"_unobserved":403}` {
		t.Errorf("runner 12 projects = %s, want _unobserved:403", got)
	}
}

// A per-runner TRANSPORT failure (non-soft) is routed to appendErr and skipped —
// it must not abort enrichment of the remaining runners.
func TestCollectProjectRunnersTransportErrorSkips(t *testing.T) {
	cl := newFake()
	base := "/projects/7"
	cl.list[base+"/runners"] = []json.RawMessage{json.RawMessage(`{"id":11}`)}
	cl.softPath["/runners/11/projects"] = http.StatusInternalServerError // non-soft
	cp := engine.CurrentPhase{RunDir: t.TempDir()}
	timer := engine.StartPhaseTimer(engine.PhaseCollect, "collect")

	if err := collectProjectRunners(context.Background(), cl, cp, "g/p", base, timer); err != nil {
		t.Fatalf("a per-runner transport error must not be fatal: %v", err)
	}
	if len(timer.Errors) == 0 {
		t.Error("expected a recorded per-runner error for the 500 co-residency call")
	}
}
