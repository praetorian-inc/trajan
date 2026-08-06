package github

import (
	"context"
	"log/slog"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func ResolveToken(ctx context.Context, explicit string) (string, error) {
	if c, ok := engine.ResolveGitHub(explicit); ok {
		return c.Value, nil
	}
	if out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output(); err == nil {
		if tok := strings.TrimSpace(string(out)); tok != "" {
			slog.Info("using credential", "source", "gh auth token")
			return tok, nil
		}
	}
	return "", engine.ErrNoToken
}

type authTransport struct {
	token string
	base  http.RoundTripper
}

func (t *authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+t.token)
	if r.Header.Get("Accept") == "" {
		r.Header.Set("Accept", accept)
	}
	r.Header.Set("X-GitHub-Api-Version", apiVersion)
	r.Header.Set("User-Agent", userAgent)
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r)
}

func NewClient(token string) *Client {
	return &Client{
		http:  &http.Client{Timeout: 60 * time.Second, Transport: &authTransport{token: token}},
		token: token,
	}
}
