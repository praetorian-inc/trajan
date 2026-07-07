package github

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func TestResolveTokenGhTokenBeatsGitHubToken(t *testing.T) {
	t.Setenv("GH_TOKEN", "  gh-token  ")
	t.Setenv("GITHUB_TOKEN", "github-token")

	tok, err := ResolveToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "gh-token" {
		t.Fatalf("expected GH_TOKEN to win (trimmed), got %q", tok)
	}
}

func TestResolveTokenGitHubTokenFallback(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "github-token")

	tok, err := ResolveToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "github-token" {
		t.Fatalf("expected GITHUB_TOKEN fallback, got %q", tok)
	}
}

func TestResolveTokenMissingBothNoGhReturnsErrNoToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	// empty PATH so the `gh auth token` fallback can't find gh
	t.Setenv("PATH", t.TempDir())

	_, err := ResolveToken(context.Background())
	if !errors.Is(err, engine.ErrNoToken) {
		t.Fatalf("expected ErrNoToken, got %v", err)
	}
}

func TestAuthTransportSetsHeaders(t *testing.T) {
	tr := &authTransport{token: "abc", base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != "Bearer abc" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("Accept"); got != accept {
			t.Errorf("Accept = %q, want %q", got, accept)
		}
		if got := r.Header.Get("X-GitHub-Api-Version"); got != apiVersion {
			t.Errorf("X-GitHub-Api-Version = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != userAgent {
			t.Errorf("User-Agent = %q", got)
		}
		return &http.Response{StatusCode: 200, Body: http.NoBody, Header: make(http.Header)}, nil
	})}
	req, _ := http.NewRequest(http.MethodGet, "https://api.github.com/x", nil)
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
}

func TestAuthTransportPreservesAcceptOverride(t *testing.T) {
	tr := &authTransport{token: "abc", base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Accept"); got != "application/vnd.github.raw" {
			t.Errorf("Accept override not preserved, got %q", got)
		}
		return &http.Response{StatusCode: 200, Body: http.NoBody, Header: make(http.Header)}, nil
	})}
	req, _ := http.NewRequest(http.MethodGet, "https://api.github.com/x", nil)
	req.Header.Set("Accept", "application/vnd.github.raw")
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
