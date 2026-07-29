package gitlab

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// WhoAmI must send the PRIVATE-TOKEN and tolerate the optional
// /personal_access_tokens/self endpoint 404ing (project/group tokens) without
// erroring — the identity from /user is enough.
func TestWhoAmIPATSelf404NonFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v4/user":
			w.Write([]byte(`{"username":"alice","name":"Alice","is_admin":false}`))
		case "/api/v4/personal_access_tokens/self":
			w.WriteHeader(http.StatusNotFound) // project/group token -> no PAT self
		case "/api/v4/groups":
			w.Write([]byte(`[{"full_path":"g/one"}]`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	origURL := FlagURL
	FlagURL = srv.URL
	t.Setenv("GITLAB_TOKEN", "tok")
	defer func() { FlagURL = origURL }()

	if err := WhoAmI(context.Background()); err != nil {
		t.Fatalf("WhoAmI with a 404 on PAT-self must be non-fatal: %v", err)
	}
}

// A failing /user (the one required call) is fatal — there is no identity to report.
func TestWhoAmIUserErrorFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	origURL := FlagURL
	FlagURL = srv.URL
	t.Setenv("GITLAB_TOKEN", "bad")
	defer func() { FlagURL = origURL }()

	if err := WhoAmI(context.Background()); err == nil {
		t.Fatal("WhoAmI with a 401 on /user = nil error, want fatal")
	}
}

// The rate limiter tracks GitLab's un-prefixed RateLimit-* headers; the request
// loop feeds every response through Update, so a Snapshot after a call reflects the
// server's advertised remaining budget.
func TestRateLimiterTracksHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("RateLimit-Limit", "500")
		w.Header().Set("RateLimit-Remaining", "497")
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "t", false, 1)
	if _, _, err := c.Get(context.Background(), "/x", nil, false); err != nil {
		t.Fatal(err)
	}
	limit, remaining := c.limiter.Snapshot()
	if limit != 500 || remaining != 497 {
		t.Errorf("snapshot = %d/%d, want 497/500 from RateLimit-* headers", remaining, limit)
	}
}
