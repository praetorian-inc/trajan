package gitlab

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeBaseURL(t *testing.T) {
	cases := map[string]string{
		"":                      DefaultBaseURL,
		"https://gitlab.com":    "https://gitlab.com/api/v4",
		"https://gitlab.com/":   "https://gitlab.com/api/v4",
		"https://3.136.153.111": "https://3.136.153.111/api/v4",
		"https://x.io/api/v4":   "https://x.io/api/v4",
	}
	for in, want := range cases {
		if got := normalizeBaseURL(in); got != want {
			t.Errorf("normalizeBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPrivateTokenHeaderAndPagination(t *testing.T) {
	var gotToken string
	var page1Sent bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("PRIVATE-TOKEN")
		if r.URL.Query().Get("page") == "1" {
			page1Sent = true
			w.Header().Set("X-Next-Page", "2")
			w.Write([]byte(`[{"id":1}]`))
			return
		}
		w.Write([]byte(`[{"id":2}]`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "secret-tok", false, 1)
	items, err := c.Paginate(context.Background(), "/projects", nil)
	if err != nil {
		t.Fatalf("Paginate: %v", err)
	}
	if gotToken != "secret-tok" {
		t.Errorf("PRIVATE-TOKEN = %q, want secret-tok", gotToken)
	}
	if !page1Sent {
		t.Error("page 1 was not requested")
	}
	if len(items) != 2 {
		t.Errorf("accumulated %d items across pages, want 2", len(items))
	}
}

func TestRetryAfterHonored(t *testing.T) {
	var slept float64
	orig := sleepFn
	sleepFn = func(_ context.Context, sec float64) { slept += sec }
	defer func() { sleepFn = orig }()

	attempt := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		if attempt == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "t", false, 1)
	if _, _, err := c.Get(context.Background(), "/x", nil, false); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if slept != 7 {
		t.Errorf("slept %.0fs on 429, want 7 (Retry-After)", slept)
	}
}

func TestIsSoftClassification(t *testing.T) {
	cases := map[int]bool{401: true, 403: true, 404: true, 400: false, 500: false, 429: false}
	for status, want := range cases {
		err := &GitLabError{Status: status}
		if got := isSoft(err); got != want {
			t.Errorf("isSoft(HTTP %d) = %v, want %v", status, got, want)
		}
	}
}
