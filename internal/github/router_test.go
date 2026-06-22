package github

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
)

// fakeTransport records the calls it serves and returns a scripted error
// sequence so tests can simulate throttle-then-success and exhaustion.
type fakeTransport struct {
	k     transportKind
	calls int
	// errs is consumed one per attempt; nil means success. Once exhausted the
	// last value repeats.
	errs []error
}

func (f *fakeTransport) next() error {
	var e error
	if len(f.errs) > 0 {
		e = f.errs[0]
		if len(f.errs) > 1 {
			f.errs = f.errs[1:]
		}
	}
	return e
}

func (f *fakeTransport) Get(_ context.Context, _ string, _ url.Values, _ bool) (json.RawMessage, http.Header, error) {
	f.calls++
	if err := f.next(); err != nil {
		return nil, nil, err
	}
	return json.RawMessage(`{"served_by":"` + string(f.k) + `"}`), http.Header{}, nil
}
func (f *fakeTransport) GetRaw(_ context.Context, _ string, _ url.Values, _ string) ([]byte, http.Header, error) {
	f.calls++
	if err := f.next(); err != nil {
		return nil, nil, err
	}
	return []byte(f.k), http.Header{}, nil
}
func (f *fakeTransport) GetContentWithSHA(_ context.Context, _, _ string, _ bool) ([]byte, string, bool, error) {
	f.calls++
	if err := f.next(); err != nil {
		return nil, "", false, err
	}
	return []byte(f.k), "sha", true, nil
}
func (f *fakeTransport) ResolveRefCommitSHA(_ context.Context, _, _, _ string) (string, error) {
	f.calls++
	if err := f.next(); err != nil {
		return "", err
	}
	return string(f.k), nil
}
func (f *fakeTransport) Paginate(_ context.Context, _ string, _ url.Values, _ int) ([]json.RawMessage, error) {
	f.calls++
	if err := f.next(); err != nil {
		return nil, err
	}
	return []json.RawMessage{json.RawMessage(`"` + f.k + `"`)}, nil
}
func (f *fakeTransport) kind() transportKind { return f.k }

func newFakeRouter(ts ...*fakeTransport) *router {
	m := make(map[transportKind]transport, len(ts))
	for _, t := range ts {
		m[t.k] = t
	}
	return &router{transports: m}
}

func servedBy(raw json.RawMessage) string {
	var v struct {
		By string `json:"served_by"`
	}
	_ = json.Unmarshal(raw, &v)
	return v.By
}

func noSleep(t *testing.T) {
	old := sleepFn
	sleepFn = func(context.Context, float64) {}
	t.Cleanup(func() { sleepFn = old })
}

func TestRouterPrefersHighestCapableTransport(t *testing.T) {
	git := &fakeTransport{k: transportGit}
	gql := &fakeTransport{k: transportGraphQL}
	rest := &fakeTransport{k: transportREST}
	r := newFakeRouter(git, gql, rest)

	// workflow files: git capable -> git serves
	raw, _, err := r.Get(context.Background(), "/repos/o/p/contents/.github/workflows/ci.yml", nil, false)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := servedBy(raw); got != string(transportGit) {
		t.Fatalf("workflow files served by %q, want git", got)
	}

	// org members: git NOT capable -> graphql serves (preference over rest)
	raw, _, err = r.Get(context.Background(), "/orgs/o/members", nil, false)
	if err != nil {
		t.Fatalf("Get members: %v", err)
	}
	if got := servedBy(raw); got != string(transportGraphQL) {
		t.Fatalf("members served by %q, want graphql", got)
	}
}

func TestRouterRESTFloorNeverOffloaded(t *testing.T) {
	git := &fakeTransport{k: transportGit}
	gql := &fakeTransport{k: transportGraphQL}
	rest := &fakeTransport{k: transportREST}
	r := newFakeRouter(git, gql, rest)

	// secrets are rest-only; even with git/graphql registered, rest must serve.
	raw, _, err := r.Get(context.Background(), "/orgs/o/actions/secrets", nil, false)
	if err != nil {
		t.Fatalf("Get secrets: %v", err)
	}
	if got := servedBy(raw); got != string(transportREST) {
		t.Fatalf("rest-floor served by %q, want rest", got)
	}
	if git.calls != 0 || gql.calls != 0 {
		t.Fatalf("rest-floor leaked to git=%d graphql=%d", git.calls, gql.calls)
	}
}

func TestRouterLocalRetryThenSuccess(t *testing.T) {
	noSleep(t)
	// graphql throttles twice then succeeds within its local budget; the router
	// must NOT fall through to rest.
	throttle := &GhError{Status: 429, Body: "rate limited"}
	gql := &fakeTransport{k: transportGraphQL, errs: []error{throttle, throttle, nil}}
	rest := &fakeTransport{k: transportREST}
	r := newFakeRouter(gql, rest)

	raw, _, err := r.Get(context.Background(), "/orgs/o/members", nil, false)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := servedBy(raw); got != string(transportGraphQL) {
		t.Fatalf("served by %q, want graphql (retried within budget)", got)
	}
	if gql.calls != 3 {
		t.Fatalf("graphql attempts = %d, want 3 (2 retries + success)", gql.calls)
	}
	if rest.calls != 0 {
		t.Fatalf("rest should not be reached, calls = %d", rest.calls)
	}
}

func TestRouterFallThroughOnExhaustedThrottle(t *testing.T) {
	noSleep(t)
	// graphql throttles past its local budget -> router falls through to rest.
	throttle := &GhError{Status: 503, Body: "unavailable"}
	gql := &fakeTransport{k: transportGraphQL, errs: []error{throttle}}
	rest := &fakeTransport{k: transportREST}
	r := newFakeRouter(gql, rest)

	raw, _, err := r.Get(context.Background(), "/orgs/o/members", nil, false)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := servedBy(raw); got != string(transportREST) {
		t.Fatalf("served by %q, want rest (fell through)", got)
	}
	if gql.calls != localRetries+1 {
		t.Fatalf("graphql attempts = %d, want %d", gql.calls, localRetries+1)
	}
}

// An unservable error (graphql can't serve / git can't clone) falls through to
// REST immediately, with no local retry.
func TestRouterUnservableFallsThroughWithoutRetry(t *testing.T) {
	gql := &fakeTransport{k: transportGraphQL, errs: []error{errUnservable}}
	rest := &fakeTransport{k: transportREST}
	r := newFakeRouter(gql, rest)

	raw, _, err := r.Get(context.Background(), "/orgs/o/members", nil, false)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := servedBy(raw); got != string(transportREST) {
		t.Fatalf("served by %q, want rest (fell through)", got)
	}
	if gql.calls != 1 {
		t.Fatalf("graphql attempts = %d, want 1 (no retry on unservable)", gql.calls)
	}
}

func TestRouterDefinitiveErrorNoFallThrough(t *testing.T) {
	// a 404/permission soft-fail is definitive: collectors handle it. The router
	// must surface it as-is without retry or fall-through.
	notFound := &GhError{Status: 404, Body: "not found"}
	gql := &fakeTransport{k: transportGraphQL, errs: []error{notFound}}
	rest := &fakeTransport{k: transportREST}
	r := newFakeRouter(gql, rest)

	_, _, err := r.Get(context.Background(), "/orgs/o/members", nil, false)
	var ghErr *GhError
	if !errors.As(err, &ghErr) || ghErr.Status != 404 {
		t.Fatalf("err = %v, want GhError 404", err)
	}
	if gql.calls != 1 {
		t.Fatalf("graphql attempts = %d, want 1 (no retry on definitive)", gql.calls)
	}
	if rest.calls != 0 {
		t.Fatalf("rest should not be reached, calls = %d", rest.calls)
	}
}

func TestRouterForceRESTPinsToFloor(t *testing.T) {
	git := &fakeTransport{k: transportGit}
	gql := &fakeTransport{k: transportGraphQL}
	rest := &fakeTransport{k: transportREST}
	r := newFakeRouter(git, gql, rest)
	r.forceREST = true

	// even a git-preferred surface must route to rest under TRAJAN_FORCE_REST.
	raw, _, err := r.Get(context.Background(), "/repos/o/p/contents/.github/workflows/ci.yml", nil, false)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := servedBy(raw); got != string(transportREST) {
		t.Fatalf("forceREST served by %q, want rest", got)
	}
	if git.calls != 0 || gql.calls != 0 {
		t.Fatalf("forceREST leaked to git=%d graphql=%d", git.calls, gql.calls)
	}
}

func TestRouterNoCapableTransportErrors(t *testing.T) {
	// only graphql registered, but a rest-floor surface has no capable
	// registered transport -> explicit error (not a silent nil).
	gql := &fakeTransport{k: transportGraphQL}
	r := newFakeRouter(gql)

	_, _, err := r.Get(context.Background(), "/orgs/o/actions/secrets", nil, false)
	if err == nil {
		t.Fatal("expected error for rest-floor surface with no rest transport")
	}
}

func TestNewRouterRegistersRESTAndHonorsForceREST(t *testing.T) {
	t.Setenv("TRAJAN_FORCE_REST", "")
	r := newRouter(NewClient("tok"))
	t.Cleanup(func() { closeRouter(r) })
	if _, ok := r.transports[transportREST]; !ok {
		t.Fatal("newRouter must register a rest transport")
	}
	if r.forceREST {
		t.Fatal("forceREST should be false when TRAJAN_FORCE_REST is empty")
	}

	t.Setenv("TRAJAN_FORCE_REST", "1")
	r2 := newRouter(NewClient("tok"))
	t.Cleanup(func() { closeRouter(r2) })
	if !r2.forceREST {
		t.Fatal("forceREST should be true when TRAJAN_FORCE_REST is set")
	}
	if _, ok := r2.transports[transportGit]; ok {
		t.Fatal("forceREST must not register the git transport")
	}
}

func TestClassifyGetSurfaces(t *testing.T) {
	cases := map[string]surface{
		"/repos/o/p/contents/.github/workflows/ci.yml": surfaceWorkflowFiles,
		"/repos/o/p/branches":                          surfaceBranchRefs,
		"/repos/o/p/branches/main/protection":          surfaceRESTFloor,
		"/repos/o/p/commits/v1":                        surfaceRefResolve,
		// rulesets / environments / teams / outside collaborators / branch
		// protection are not graphql-mappable -> rest floor (D2.3 fidelity gate).
		"/orgs/o/rulesets":               surfaceRESTFloor,
		"/repos/o/p/rulesets":            surfaceRESTFloor,
		"/repos/o/p/environments/prod":   surfaceRESTFloor,
		"/orgs/o":                        surfaceRESTFloor,
		"/orgs/o/teams":                  surfaceRESTFloor,
		"/orgs/o/outside_collaborators":  surfaceRESTFloor,
		"/orgs/o/actions/secrets":        surfaceRESTFloor,
		"/orgs/o/hooks":                  surfaceRESTFloor,
		"/repos/o/p/collaborators":       surfaceRESTFloor,
		"/repos/o/p/actions/secrets":     surfaceRESTFloor,
		// deploy keys stay on the rest floor: graphql cannot reproduce the REST
		// numeric `id` the deploy-key-reuse correlator reads.
		"/repos/o/p/keys": surfaceRESTFloor,
		// graphql-mappable surfaces
		"/orgs/o/members":   surfaceOrgMembers,
		"/repos/o/p":        surfaceRepoMeta,
		"/repos/o/p/topics": surfaceRepoTopics,
	}
	for p, want := range cases {
		if got := classifyGet(p); got != want {
			t.Errorf("classifyGet(%q) = %q, want %q", p, got, want)
		}
	}
}
