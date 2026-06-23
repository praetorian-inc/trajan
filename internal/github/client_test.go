package github

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(srv *httptest.Server) *Client {
	return NewClient("test-token")
}

func captureSleeps(t *testing.T) (*[]float64, func()) {
	t.Helper()
	var rec []float64
	orig := sleepFn
	sleepFn = func(_ context.Context, sec float64) { rec = append(rec, sec) }
	return &rec, func() { sleepFn = orig }
}

func TestGet200Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "yes")
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	body, hdr, err := c.Get(context.Background(), srv.URL+"/x", nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("body = %q", body)
	}
	if hdr.Get("X-Custom") != "yes" {
		t.Fatalf("missing custom header: %v", hdr)
	}
}

func TestGet404AllowReturnsNilWithHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "h")
		w.WriteHeader(404)
		w.Write([]byte(`not found`))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	body, hdr, err := c.Get(context.Background(), srv.URL+"/missing", nil, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if body != nil {
		t.Fatalf("expected nil body, got %q", body)
	}
	if hdr.Get("X-Custom") != "h" {
		t.Fatalf("expected headers returned on 404, got %v", hdr)
	}
}

func TestGet404NoAllowIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(`nope`))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	_, _, err := c.Get(context.Background(), srv.URL+"/missing", nil, false)
	var ghErr *GhError
	if !errors.As(err, &ghErr) {
		t.Fatalf("expected *GhError, got %v", err)
	}
	if ghErr.Status != 404 {
		t.Fatalf("status = %d", ghErr.Status)
	}
}

func TestGet502ThenRetried(t *testing.T) {
	rec, restore := captureSleeps(t)
	defer restore()

	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.WriteHeader(502)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":1}`))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	body, _, err := c.Get(context.Background(), srv.URL+"/x", nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != `{"ok":1}` {
		t.Fatalf("body = %q", body)
	}
	if atomic.LoadInt32(&n) != 2 {
		t.Fatalf("expected 2 attempts, got %d", n)
	}
	if len(*rec) != 1 || (*rec)[0] != 2 {
		t.Fatalf("expected one 2s sleep, got %v", *rec)
	}
}

func TestGet403RetryAfterSleepsCapped(t *testing.T) {
	rec, restore := captureSleeps(t)
	defer restore()

	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.Header().Set("Retry-After", "300") // exceeds the 120 cap
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	if _, _, err := c.Get(context.Background(), srv.URL+"/x", nil, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*rec) != 1 {
		t.Fatalf("expected exactly one sleep, got %v", *rec)
	}
	if (*rec)[0] != 120 {
		t.Fatalf("expected sleep capped at 120, got %v", (*rec)[0])
	}
}

func TestGet403RateLimitResetSleep(t *testing.T) {
	rec, restore := captureSleeps(t)
	defer restore()

	reset := time.Now().Unix() + 10
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset, 10))
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	if _, _, err := c.Get(context.Background(), srv.URL+"/x", nil, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*rec) != 1 {
		t.Fatalf("expected one sleep, got %v", *rec)
	}
	// reset-now ~10, +1 slack => ~11
	if (*rec)[0] <= 0 || (*rec)[0] > 120 {
		t.Fatalf("reset-path sleep out of range: %v", (*rec)[0])
	}
	if (*rec)[0] > 12 {
		t.Fatalf("reset-path sleep should be ~11s, got %v", (*rec)[0])
	}
}

func TestGetSixAttemptExhaustion(t *testing.T) {
	rec, restore := captureSleeps(t)
	defer restore()

	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(503)
	}))
	defer srv.Close()
	c := newTestClient(srv)

	_, _, err := c.Get(context.Background(), srv.URL+"/x", nil, false)
	var ghErr *GhError
	if !errors.As(err, &ghErr) {
		t.Fatalf("expected *GhError after exhaustion, got %v", err)
	}
	// exhaustion surfaces the last status (503), not a synthetic 0
	if ghErr.Status != 503 {
		t.Fatalf("expected last-response status 503 after exhaustion, got %+v", ghErr)
	}
	if atomic.LoadInt32(&n) != 6 {
		t.Fatalf("expected 6 attempts, got %d", n)
	}
	if len(*rec) != 6 {
		t.Fatalf("expected 6 sleeps, got %v", *rec)
	}
}

func TestGetRawAlwaysErrorsOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(`missing`))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	_, _, err := c.GetRaw(context.Background(), srv.URL+"/x", nil, "application/vnd.github.raw")
	var ghErr *GhError
	if !errors.As(err, &ghErr) {
		t.Fatalf("expected *GhError on 404, got %v", err)
	}
	if ghErr.Status != 404 {
		t.Fatalf("status = %d", ghErr.Status)
	}
}

func TestGetRawAcceptOverride(t *testing.T) {
	var gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		w.WriteHeader(200)
		w.Write([]byte("raw-bytes"))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	body, _, err := c.GetRaw(context.Background(), srv.URL+"/x", nil, "application/vnd.github.raw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != "raw-bytes" {
		t.Fatalf("body = %q", body)
	}
	if gotAccept != "application/vnd.github.raw" {
		t.Fatalf("Accept override not applied, got %q", gotAccept)
	}
}

func TestPaginateFollowsLinkAcrossTwoPages(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/page1":
			if r.URL.Query().Get("per_page") == "" {
				t.Errorf("expected per_page on first request, got none")
			}
			w.Header().Set("Link", `<`+srv.URL+`/page2>; rel="next"`)
			w.WriteHeader(200)
			w.Write([]byte(`[{"id":1},{"id":2}]`))
		case "/page2":
			// the Link follow-up must not carry our params
			w.WriteHeader(200)
			w.Write([]byte(`[{"id":3}]`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	c := newTestClient(srv)

	// drive paginateFrom directly so the first request can target the test server
	items, err := c.paginateFrom(context.Background(), srv.URL+"/page1", url.Values{}, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 items across 2 pages, got %d: %v", len(items), items)
	}
}

func TestPaginateItemsEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"total_count":2,"items":[{"id":1},{"id":2}]}`))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	items, err := c.paginateFrom(context.Background(), srv.URL+"/search", url.Values{}, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items from items envelope, got %d", len(items))
	}
}

func TestPaginateTotalCountEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"total_count":3,"repository_selection":"all","secrets":[{"name":"A"},{"name":"B"},{"name":"C"}]}`))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	items, err := c.paginateFrom(context.Background(), srv.URL+"/secrets", url.Values{}, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 items from total_count envelope, got %d", len(items))
	}
}

func TestPaginateBareArrayEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`[{"id":1},{"id":2},{"id":3},{"id":4}]`))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	items, err := c.paginateFrom(context.Background(), srv.URL+"/repos", url.Values{}, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 4 {
		t.Fatalf("expected 4 items from bare array, got %d", len(items))
	}
}

func TestGetContentWithSHABase64(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		// base64("hello") = aGVsbG8=
		w.Write([]byte(`{"type":"file","encoding":"base64","content":"aGVsbG8=","sha":"deadbeef"}`))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	body, sha, ok, err := c.GetContentWithSHA(context.Background(), srv.URL+"/contents/x", "", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected ok=true")
	}
	if string(body) != "hello" {
		t.Fatalf("body = %q", body)
	}
	if sha != "deadbeef" {
		t.Fatalf("sha = %q", sha)
	}
}

func TestGetContentWithSHASymlinkReturnsNotOk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"type":"symlink","sha":"abc"}`))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	body, sha, ok, err := c.GetContentWithSHA(context.Background(), srv.URL+"/contents/x", "", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok || body != nil || sha != "" {
		t.Fatalf("symlink should yield (nil,\"\",false), got (%q,%q,%v)", body, sha, ok)
	}
}

func TestGetContentWithSHARefThreadedAsParam(t *testing.T) {
	var gotRef string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRef = r.URL.Query().Get("ref")
		w.WriteHeader(200)
		w.Write([]byte(`{"type":"file","encoding":"base64","content":"eA==","sha":"s"}`))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	if _, _, _, err := c.GetContentWithSHA(context.Background(), srv.URL+"/contents/x", "feature/foo", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotRef != "feature/foo" {
		t.Fatalf("ref not threaded, got %q", gotRef)
	}
}

func TestResolveRefCommitSHA404ReturnsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(`no commit`))
	}))
	defer srv.Close()
	// ResolveRefCommitSHA builds its URL from apiBase, so point it at the test server
	orig := apiBase
	apiBase = srv.URL
	defer func() { apiBase = orig }()
	c := newTestClient(srv)

	sha, err := c.ResolveRefCommitSHA(context.Background(), "o", "r", "deleted-branch")
	if err != nil {
		t.Fatalf("expected nil error on 404, got %v", err)
	}
	if sha != "" {
		t.Fatalf("expected empty sha, got %q", sha)
	}
}

func TestNextLink(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"", ""},
		{`<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=5>; rel="last"`, "https://api.github.com/x?page=2"},
		{`<https://api.github.com/x?page=1>; rel="prev"`, ""},
	}
	for _, tc := range cases {
		if got := nextLink(tc.header); got != tc.want {
			t.Errorf("nextLink(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}

func TestQuoteKeepSlash(t *testing.T) {
	cases := []struct{ in, want string }{
		{"main", "main"},
		{"feature/foo", "feature/foo"},
		{"refs/heads/a b", "refs/heads/a%20b"},
		{"weird#?ref", "weird%23%3Fref"},
		{"a%b", "a%25b"},
	}
	for _, tc := range cases {
		if got := quoteKeepSlash(tc.in); got != tc.want {
			t.Errorf("quoteKeepSlash(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
