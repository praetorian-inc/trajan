package ado

import (
	"bytes"
	"context"
	"encoding/base64"
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
	userAgent = "trajan-prototype/0.1"

	// Individual surfaces override these where a preview is required.
	APIVersion        = "7.1"
	APIVersionPreview = "7.1-preview.1"
	APIVersionSEP     = "7.1-preview.4" // service endpoints
	APIVersionGraph   = "7.1-preview.1" // vssps graph

	maxRateLimitSleep = 120.0
)

// Keyed by the short host name collectors pass. A var, not a const, so tests can
// repoint these at an httptest server.
var hostBase = map[string]string{
	"core":      "https://dev.azure.com",
	"vsrm":      "https://vsrm.dev.azure.com",
	"feeds":     "https://feeds.dev.azure.com",
	"extmgmt":   "https://extmgmt.dev.azure.com",
	"vssps":     "https://vssps.dev.azure.com",
	"almsearch": "https://almsearch.dev.azure.com",
}

type ADO interface {
	Get(ctx context.Context, host, api, path string, params url.Values, allow404 bool) (json.RawMessage, http.Header, error)
	GetRaw(ctx context.Context, host, api, path string, params url.Values) ([]byte, http.Header, error)
	Post(ctx context.Context, host, api, path string, params url.Values, body any) (json.RawMessage, error)
	Paginate(ctx context.Context, host, api, path string, params url.Values) ([]json.RawMessage, error)
}

type Client struct {
	http    *http.Client
	org     string
	authz   string
	limiter rateLimiter
}

var _ ADO = (*Client)(nil)

func NewClient(org, pat string) *Client {
	return newClient(org, "Basic "+base64.StdEncoding.EncodeToString([]byte(":"+pat)))
}

func NewClientBearer(org, token string) *Client {
	return newClient(org, "Bearer "+token)
}

func newClient(org, authz string) *Client {
	return &Client{
		http:  &http.Client{Timeout: 90 * time.Second},
		org:   org,
		authz: authz,
	}
}

type AdoError struct {
	Status int
	URL    string
	Body   string
}

func (e *AdoError) Error() string {
	b := e.Body
	if len(b) > 400 {
		b = b[:400]
	}
	return fmt.Sprintf("HTTP %d from %s: %s", e.Status, e.URL, b)
}

// overridable so tests can record sleeps without waiting
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

func (c *Client) buildURL(host, path string, params url.Values, api string) (string, error) {
	base, ok := hostBase[host]
	if !ok {
		return "", fmt.Errorf("unknown ado host %q", host)
	}
	q := url.Values{}
	for k, v := range params {
		q[k] = v
	}
	if q.Get("api-version") == "" && api != "" {
		q.Set("api-version", api)
	}
	u := base + "/" + c.org + path
	if enc := q.Encode(); enc != "" {
		u += "?" + enc
	}
	return u, nil
}

func (c *Client) do(ctx context.Context, method, rawURL, accept string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", c.authz)
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

func (c *Client) sleepForRateLimit(ctx context.Context, resp *http.Response) bool {
	if resp.StatusCode != http.StatusTooManyRequests {
		return false
	}
	sec := 30.0
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if d, err := strconv.ParseFloat(ra, 64); err == nil {
			sec = d
		}
	}
	sleepFn(ctx, min(sec, maxRateLimitSleep))
	return true
}

// body is []byte rather than io.Reader so it can be re-sent on each retry: a Reader
// would be at EOF after the first attempt and send an empty body on a 429/5xx retry.
// A 404 with allow404 yields (nil, header, nil). An HTML response means an invalid
// PAT and becomes an AdoError, so it soft-fails instead of corrupting stored JSON.
func (c *Client) request(ctx context.Context, method, u, accept string, body []byte, allow404 bool) ([]byte, http.Header, error) {
	var lastStatus int
	var lastBody []byte
	for attempt := 0; attempt < 5; attempt++ {
		c.limiter.wait(ctx)
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		resp, err := c.do(ctx, method, u, accept, rdr)
		if err != nil {
			return nil, nil, err
		}
		c.limiter.update(resp.Header)
		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			hdr := resp.Header
			b := readAllClose(resp)
			if strings.HasPrefix(hdr.Get("Content-Type"), "text/html") {
				return nil, nil, &AdoError{Status: resp.StatusCode, URL: u,
					Body: "server returned HTML (invalid or expired PAT)"}
			}
			return b, hdr, nil
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
			return nil, nil, &AdoError{Status: resp.StatusCode, URL: u, Body: string(b)}
		}
	}
	return nil, nil, &AdoError{Status: lastStatus, URL: u, Body: string(lastBody)}
}

func (c *Client) Get(ctx context.Context, host, api, path string, params url.Values, allow404 bool) (json.RawMessage, http.Header, error) {
	u, err := c.buildURL(host, path, params, api)
	if err != nil {
		return nil, nil, err
	}
	b, hdr, err := c.request(ctx, http.MethodGet, u, "application/json", nil, allow404)
	if err != nil {
		return nil, nil, err
	}
	return json.RawMessage(b), hdr, nil
}

func (c *Client) GetRaw(ctx context.Context, host, api, path string, params url.Values) ([]byte, http.Header, error) {
	u, err := c.buildURL(host, path, params, api)
	if err != nil {
		return nil, nil, err
	}
	return c.request(ctx, http.MethodGet, u, "text/plain", nil, true)
}

func (c *Client) Post(ctx context.Context, host, api, path string, params url.Values, body any) (json.RawMessage, error) {
	u, err := c.buildURL(host, path, params, api)
	if err != nil {
		return nil, err
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	b, _, err := c.request(ctx, http.MethodPost, u, "application/json", buf, false)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}
