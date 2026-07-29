package gitlab

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// insecure=true must skip TLS verification so a self-signed self-hosted cert
// (the firing-range 3.136.153.111 case) is reachable; insecure=false must reject
// it.
func TestInsecureTLSWiring(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	if _, _, err := NewClient(srv.URL, "t", true, 1).Get(context.Background(), "/x", nil, false); err != nil {
		t.Errorf("insecure=true against self-signed cert: %v, want success", err)
	}
	if _, _, err := NewClient(srv.URL, "t", false, 1).Get(context.Background(), "/x", nil, false); err == nil {
		t.Error("insecure=false against self-signed cert = nil error, want TLS verification failure")
	}
}

// Paginate must stop when X-Next-Page fails to advance (<= current page), even
// though the server keeps claiming there's a next page — otherwise a broken
// server would loop to the 10000 cap.
func TestPaginateStopsOnNonAdvancingNext(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("X-Next-Page", "1") // never advances past page 1
		w.Write([]byte(`[{"id":1}]`))
	}))
	defer srv.Close()

	items, err := NewClient(srv.URL, "t", false, 1).Paginate(context.Background(), "/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Errorf("server hit %d times, want 1 (non-advancing next must stop)", hits)
	}
	if len(items) != 1 {
		t.Errorf("items = %d, want 1", len(items))
	}
}

// A non-array body from a paginated endpoint is returned as a single element so
// callers stay uniform instead of erroring on the type mismatch.
func TestPaginateNonArrayBodySingleElement(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"single":true}`))
	}))
	defer srv.Close()

	items, err := NewClient(srv.URL, "t", false, 1).Paginate(context.Background(), "/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || string(items[0]) != `{"single":true}` {
		t.Errorf("items = %v, want one element {\"single\":true}", items)
	}
}

// per_page=100 is forced on every paginated request.
func TestPaginateSetsPerPage(t *testing.T) {
	var perPage string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		perPage = r.URL.Query().Get("per_page")
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	NewClient(srv.URL, "t", false, 1).Paginate(context.Background(), "/x", nil)
	if perPage != "100" {
		t.Errorf("per_page = %q, want 100", perPage)
	}
}

// 5xx responses are retried (with a backoff sleep) before finally surfacing an
// error; a subsequent success returns cleanly.
func TestServerErrorRetriesThenSucceeds(t *testing.T) {
	orig := sleepFn
	sleepFn = func(context.Context, float64) {}
	defer func() { sleepFn = orig }()

	attempt := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempt++
		if attempt < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	if _, _, err := NewClient(srv.URL, "t", false, 1).Get(context.Background(), "/x", nil, false); err != nil {
		t.Fatalf("Get after transient 502s: %v", err)
	}
	if attempt != 3 {
		t.Errorf("attempts = %d, want 3 (two retries)", attempt)
	}
}

func TestServerErrorExhaustsRetries(t *testing.T) {
	orig := sleepFn
	sleepFn = func(context.Context, float64) {}
	defer func() { sleepFn = orig }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, _, err := NewClient(srv.URL, "t", false, 1).Get(context.Background(), "/x", nil, false)
	if softStatus(err) != http.StatusInternalServerError {
		t.Errorf("err = %v, want a 500 GitLabError after exhausting retries", err)
	}
}

// allow404 turns a 404 into a nil body with no error (the softGet contract);
// without it, a 404 is a hard error.
func TestGetAllow404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "t", false, 1)

	raw, _, err := c.Get(context.Background(), "/x", nil, true)
	if err != nil || raw != nil {
		t.Errorf("Get(allow404) = (%s,%v), want (nil,nil)", raw, err)
	}
	if _, _, err := c.Get(context.Background(), "/x", nil, false); !IsNotFoundError(err) {
		t.Errorf("Get(allow404=false) err = %v, want a 404 error", err)
	}
}

// GraphQL must POST to <instance>/api/graphql, NOT under /api/v4.
func TestGraphQLEndpointPath(t *testing.T) {
	var gotPath, gotMethod, gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod, gotToken = r.URL.Path, r.Method, r.Header.Get("PRIVATE-TOKEN")
		w.Write([]byte(`{"data":{}}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "gqltok", false, 1)
	if _, err := c.GraphQL(context.Background(), "query{x}", nil); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/graphql" {
		t.Errorf("GraphQL path = %q, want /api/graphql", gotPath)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("GraphQL method = %q, want POST", gotMethod)
	}
	if gotToken != "gqltok" {
		t.Errorf("GraphQL PRIVATE-TOKEN = %q, want gqltok", gotToken)
	}
}

// The token must never appear in %v / %#v / %s of a client.
func TestClientRedactsToken(t *testing.T) {
	c := NewClient("https://gitlab.com", "super-secret-token", false, 1)
	var v any = c
	for _, s := range []string{fmt.Sprintf("%v", v), fmt.Sprintf("%#v", v), fmt.Sprintf("%s", v)} {
		if strings.Contains(s, "super-secret-token") {
			t.Errorf("formatted client leaked token: %s", s)
		}
		if !strings.Contains(s, "REDACTED") {
			t.Errorf("formatted client = %q, want a [REDACTED] marker", s)
		}
	}
}

// GitLabError truncates a very long body so an error string stays bounded.
func TestGitLabErrorBodyTruncated(t *testing.T) {
	e := &GitLabError{Status: 500, URL: "/x", Body: strings.Repeat("a", 1000)}
	if n := len(e.Error()); n > 500 {
		t.Errorf("error string len = %d, want bounded (~<500)", n)
	}
}

func TestVerifyTLSServerAcceptsOwnCert(t *testing.T) {
	// Guard: httptest's TLS cert really is self-signed (so the insecure test above
	// is meaningful).
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: false}}}
	if _, err := c.Get(srv.URL); err == nil {
		t.Fatal("expected self-signed cert to fail default verification")
	}
}
