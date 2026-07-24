package gitlab

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	userAgent      = "trajan-prototype/0.1"
	DefaultBaseURL = "https://gitlab.com/api/v4"
	DefaultTimeout = 30 * time.Second
)

// GitLab is the surface collectors depend on; Client is the production impl.
type GitLab interface {
	Get(ctx context.Context, path string, params url.Values, allow404 bool) (json.RawMessage, http.Header, error)
	GetRaw(ctx context.Context, path string, params url.Values) ([]byte, http.Header, error)
	Paginate(ctx context.Context, path string, params url.Values) ([]json.RawMessage, error)
	GraphQL(ctx context.Context, query string, vars map[string]any) (json.RawMessage, error)
}

type Client struct {
	http    *http.Client
	baseURL string // ".../api/v4"
	token   string
	limiter *RateLimiter
}

var _ GitLab = (*Client)(nil)

// NewClient builds a REST client. baseURL is the instance root ("https://gitlab.com"
// or a self-hosted URL); "/api/v4" is appended if absent. insecure skips TLS verify
// for self-signed self-hosted certs. concurrency is bound by the engine's runner,
// so the client does not self-limit.
func NewClient(baseURL, token string, insecure bool, concurrency int) *Client {
	baseURL = normalizeBaseURL(baseURL)
	tr := http.DefaultTransport
	if insecure {
		tr = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	return &Client{
		http:    &http.Client{Timeout: DefaultTimeout, Transport: tr},
		baseURL: baseURL,
		token:   token,
		limiter: NewRateLimiter(),
	}
}

func normalizeBaseURL(baseURL string) string {
	if baseURL == "" {
		return DefaultBaseURL
	}
	if strings.HasSuffix(baseURL, "/api/v4") {
		return baseURL
	}
	return strings.TrimRight(baseURL, "/") + "/api/v4"
}

// GoString / String redact the token so a %#v / %v of a client never leaks it.
func (c *Client) String() string {
	return fmt.Sprintf("Client{baseURL: %q, token: [REDACTED]}", c.baseURL)
}
func (c *Client) GoString() string { return c.String() }

type GitLabError struct {
	Status int
	URL    string
	Body   string
}

func (e *GitLabError) Error() string {
	b := e.Body
	if len(b) > 400 {
		b = b[:400]
	}
	return fmt.Sprintf("HTTP %d from %s: %s", e.Status, e.URL, b)
}

func IsPermissionError(err error) bool { return softStatus(err) == http.StatusForbidden }
func IsNotFoundError(err error) bool   { return softStatus(err) == http.StatusNotFound }

var sleepFn = sleep

func sleep(ctx context.Context, sec float64) {
	if sec <= 0 {
		return
	}
	t := time.NewTimer(time.Duration(sec * float64(time.Second)))
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (c *Client) buildURL(p string, params url.Values) string {
	u := c.baseURL + p
	if enc := params.Encode(); enc != "" {
		u += "?" + enc
	}
	return u
}

func (c *Client) do(ctx context.Context, method, rawURL, accept string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", c.token)
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

func readAllClose(resp *http.Response) []byte {
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return b
}

// sleepForRateLimit honors Retry-After on 429 (seconds; default 60 per GitLab);
// returns true if it slept.
func (c *Client) sleepForRateLimit(ctx context.Context, resp *http.Response) bool {
	if resp.StatusCode != http.StatusTooManyRequests {
		return false
	}
	sec := 60.0
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if d, err := strconv.ParseFloat(ra, 64); err == nil {
			sec = d
		}
	}
	sleepFn(ctx, min(sec, 120))
	return true
}

// request is the shared retry loop. body is []byte (not io.Reader) so it can be
// re-sent on each retry. A 404 with allow404 yields (nil, header, nil).
func (c *Client) request(ctx context.Context, method, u, accept string, body []byte, allow404 bool) ([]byte, http.Header, error) {
	var lastStatus int
	var lastBody []byte
	for attempt := 0; attempt < 5; attempt++ {
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		resp, err := c.do(ctx, method, u, accept, rdr)
		if err != nil {
			return nil, nil, err
		}
		c.limiter.Update(resp.Header)
		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return readAllClose(resp), resp.Header, nil
		case resp.StatusCode == 404 && allow404:
			hdr := resp.Header
			resp.Body.Close()
			return nil, hdr, nil
		case resp.StatusCode >= 500:
			lastStatus, lastBody = resp.StatusCode, readAllClose(resp)
			sleepFn(ctx, 1.5*float64(attempt+1))
			continue
		default:
			if c.sleepForRateLimit(ctx, resp) {
				lastStatus, lastBody = resp.StatusCode, readAllClose(resp)
				continue
			}
			b := readAllClose(resp)
			return nil, nil, &GitLabError{Status: resp.StatusCode, URL: u, Body: string(b)}
		}
	}
	return nil, nil, &GitLabError{Status: lastStatus, URL: u, Body: string(lastBody)}
}

func (c *Client) Get(ctx context.Context, p string, params url.Values, allow404 bool) (json.RawMessage, http.Header, error) {
	b, hdr, err := c.request(ctx, http.MethodGet, c.buildURL(p, params), "application/json", nil, allow404)
	if err != nil {
		return nil, nil, err
	}
	return json.RawMessage(b), hdr, nil
}

func (c *Client) GetRaw(ctx context.Context, p string, params url.Values) ([]byte, http.Header, error) {
	return c.request(ctx, http.MethodGet, c.buildURL(p, params), "text/plain", nil, true)
}

// GraphQL posts to <instance>/api/graphql (not under /api/v4) and returns the raw
// envelope so callers can read both `data` and `errors`.
func (c *Client) GraphQL(ctx context.Context, query string, vars map[string]any) (json.RawMessage, error) {
	gqlURL := strings.TrimSuffix(c.baseURL, "/api/v4") + "/api/graphql"
	buf, err := json.Marshal(map[string]any{"query": query, "variables": vars})
	if err != nil {
		return nil, err
	}
	b, _, err := c.request(ctx, http.MethodPost, gqlURL, "application/json", buf, false)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}
