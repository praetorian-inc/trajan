package github

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// A 5xx may have created the resource, so the one thing Mutate must not do is
// send the request again.
func TestMutate5xxIsAmbiguousAndSentOnce(t *testing.T) {
	rec, restore := captureSleeps(t)
	defer restore()

	var posts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&posts, 1)
		w.WriteHeader(502)
		w.Write([]byte(`<html>Server Error</html>`))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	_, status, err := c.Mutate(context.Background(), http.MethodPost, srv.URL+"/repos/o/r/pulls", map[string]any{"title": "t"})
	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("a 5xx must be reported as an unknown outcome, got %v", err)
	}
	if status != 502 {
		t.Fatalf("status = %d, want 502", status)
	}
	if got := atomic.LoadInt32(&posts); got != 1 {
		t.Fatalf("the POST was issued %d times; a retried create makes two resources", got)
	}
	if len(*rec) != 0 {
		t.Fatalf("a 5xx must not be waited out, slept %v", *rec)
	}
}

// The one rejection Mutate does retry is a rate limit, which provably applied
// nothing — and the retry has to carry the same body as the first attempt.
func TestMutateRetriesOnceAfterSecondaryLimit(t *testing.T) {
	rec, restore := captureSleeps(t)
	defer restore()

	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		if len(bodies) == 1 {
			w.WriteHeader(429)
			w.Write([]byte(`{"message":"You have exceeded a secondary rate limit."}`))
			return
		}
		w.WriteHeader(201)
		w.Write([]byte(`{"number":7}`))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	raw, status, err := c.Mutate(context.Background(), http.MethodPost, srv.URL+"/repos/o/r/pulls", map[string]any{"title": "t"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != 201 || string(raw) != `{"number":7}` {
		t.Fatalf("status = %d raw = %q", status, raw)
	}
	if len(bodies) != 2 || bodies[0] != bodies[1] {
		t.Fatalf("the retry must resend the same payload, got %q", bodies)
	}
	if len(*rec) != 1 || (*rec)[0] != 60 {
		t.Fatalf("expected one 60s secondary-limit wait, got %v", *rec)
	}
}

func TestMutatePermissionDeniedIsNotRetried(t *testing.T) {
	rec, restore := captureSleeps(t)
	defer restore()

	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(403)
		w.Write([]byte(`{"message":"Resource not accessible by integration"}`))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	_, status, err := c.Mutate(context.Background(), http.MethodPost, srv.URL+"/repos/o/r/issues", nil)
	var ghErr *GhError
	if !errors.As(err, &ghErr) || status != 403 {
		t.Fatalf("expected a 403 *GhError, got status %d err %v", status, err)
	}
	if atomic.LoadInt32(&n) != 1 || len(*rec) != 0 {
		t.Fatalf("a permission 403 must fail at once: %d attempts, slept %v", n, *rec)
	}
}
