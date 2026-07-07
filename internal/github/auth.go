package github

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func ResolveToken(ctx context.Context) (string, error) {
	for _, k := range []string{"GH_TOKEN", "GITHUB_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v, nil
		}
	}
	if out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output(); err == nil {
		if tok := strings.TrimSpace(string(out)); tok != "" {
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
