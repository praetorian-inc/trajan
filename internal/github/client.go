package github

import (
	"context"
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
	userAgent  = "trajan-prototype/0.1"
	accept     = "application/vnd.github+json"
	apiVersion = "2022-11-28"
)

// var not const so client tests can repoint it at an httptest server
var apiBase = "https://api.github.com"

type GitHub interface {
	Get(ctx context.Context, p string, params url.Values, allow404 bool) (json.RawMessage, http.Header, error)
	GetRaw(ctx context.Context, p string, params url.Values, accept string) ([]byte, http.Header, error)
	GetContentWithSHA(ctx context.Context, p, ref string, allow404 bool) ([]byte, string, bool, error)
	ResolveRefCommitSHA(ctx context.Context, owner, repo, ref string) (string, error)
	Paginate(ctx context.Context, p string, params url.Values, perPage int) ([]json.RawMessage, error)
}

type Client struct {
	http  *http.Client
	token string
}

var _ GitHub = (*Client)(nil)

type GhError struct {
	Status int
	URL    string
	Body   string
}

func (e *GhError) Error() string {
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

func (c *Client) do(ctx context.Context, method, rawURL string, params url.Values, acceptOverride string, body io.Reader) (*http.Response, error) {
	if len(params) > 0 {
		if strings.Contains(rawURL, "?") {
			rawURL += "&" + params.Encode()
		} else {
			rawURL += "?" + params.Encode()
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	if acceptOverride != "" {
		req.Header.Set("Accept", acceptOverride)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

func readAllClose(resp *http.Response) ([]byte, error) {
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	return b, err
}

// Both rate limits answer 403 or 429. Retry-After is checked first because it is
// the only header a secondary limit is guaranteed to carry, then primary
// exhaustion (remaining 0, wait for the reset), then the headerless case.
func (c *Client) sleepForRateLimit(ctx context.Context, resp *http.Response, body []byte, attempt int) bool {
	if resp.StatusCode != 403 && resp.StatusCode != 429 {
		return false
	}
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if d, err := strconv.ParseFloat(ra, 64); err == nil {
			sleepFn(ctx, min(d, 120))
			return true
		}
	}
	if resp.Header.Get("X-RateLimit-Remaining") == "0" {
		if rs := resp.Header.Get("X-RateLimit-Reset"); rs != "" {
			if reset, err := strconv.ParseFloat(rs, 64); err == nil {
				d := max(0, reset-float64(time.Now().Unix())) + 1
				sleepFn(ctx, min(d, 120))
				return true
			}
		}
	}
	// Gated on 429 or a body that names the limit: a 403 is far more often a
	// permission denial, and sleeping through six of those would turn every
	// soft-failed optional surface into a ten-minute stall.
	if resp.StatusCode == 429 || secondaryLimit(body) {
		sleepFn(ctx, float64(min(60<<min(attempt, 4), 120)))
		return true
	}
	return false
}

// The message is the only thing separating a headerless secondary limit from a
// permission denial. Both wordings are live: hosted GitHub says "secondary rate
// limit", older GHES "abuse detection".
func secondaryLimit(body []byte) bool {
	msg := strings.ToLower(string(body))
	return strings.Contains(msg, "secondary rate") || strings.Contains(msg, "abuse detection")
}

func resolveURL(pathOrURL string) string {
	if strings.HasPrefix(pathOrURL, "http") {
		return pathOrURL
	}
	return apiBase + pathOrURL
}

func (c *Client) Get(ctx context.Context, pathOrURL string, params url.Values, allow404 bool) (json.RawMessage, http.Header, error) {
	u := resolveURL(pathOrURL)
	var lastStatus int
	var lastBody []byte
	for i := 0; i < 6; i++ {
		resp, err := c.do(ctx, http.MethodGet, u, params, "", nil)
		if err != nil {
			return nil, nil, err
		}
		switch {
		case resp.StatusCode == 200:
			b, rerr := readAllClose(resp)
			if rerr != nil {
				return nil, nil, fmt.Errorf("read response body from %s: %w", u, rerr)
			}
			return json.RawMessage(b), resp.Header, nil
		case resp.StatusCode == 404 && allow404:
			hdr := resp.Header
			resp.Body.Close()
			return nil, hdr, nil
		case resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504:
			b, _ := readAllClose(resp)
			lastStatus, lastBody = resp.StatusCode, b
			sleepFn(ctx, 2)
			continue
		default:
			b, _ := readAllClose(resp)
			if c.sleepForRateLimit(ctx, resp, b, i) {
				lastStatus, lastBody = resp.StatusCode, b
				continue
			}
			return nil, nil, &GhError{Status: resp.StatusCode, URL: u, Body: string(b)}
		}
	}
	// surface the last response's status/body (not 0) so downstream soft-degrade on 403/404 still matches
	return nil, nil, &GhError{Status: lastStatus, URL: u, Body: string(lastBody)}
}

func (c *Client) GetRaw(ctx context.Context, pathOrURL string, params url.Values, acceptOverride string) ([]byte, http.Header, error) {
	u := resolveURL(pathOrURL)
	var lastStatus int
	var lastBody []byte
	for i := 0; i < 6; i++ {
		resp, err := c.do(ctx, http.MethodGet, u, params, acceptOverride, nil)
		if err != nil {
			return nil, nil, err
		}
		switch resp.StatusCode {
		case 200:
			b, rerr := readAllClose(resp)
			if rerr != nil {
				return nil, nil, fmt.Errorf("read response body from %s: %w", u, rerr)
			}
			return b, resp.Header, nil
		case 502, 503, 504:
			b, _ := readAllClose(resp)
			lastStatus, lastBody = resp.StatusCode, b
			sleepFn(ctx, 2)
			continue
		default:
			b, _ := readAllClose(resp)
			if c.sleepForRateLimit(ctx, resp, b, i) {
				lastStatus, lastBody = resp.StatusCode, b
				continue
			}
			return nil, nil, &GhError{Status: resp.StatusCode, URL: u, Body: string(b)}
		}
	}
	return nil, nil, &GhError{Status: lastStatus, URL: u, Body: string(lastBody)}
}

// Follows the redirect to a short-lived signed URL (Actions run logs, artifact
// archives) by hand: the storage host rejects a request carrying an Authorization
// header, and authTransport would re-add ours on every redirect http.Client follows.
func (c *Client) GetDownload(ctx context.Context, pathOrURL string) ([]byte, error) {
	u := resolveURL(pathOrURL)
	api := &http.Client{
		Transport:     c.http.Transport,
		Timeout:       c.http.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := api.Do(req)
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == 200:
		b, rerr := readAllClose(resp)
		if rerr != nil {
			return nil, fmt.Errorf("read response body from %s: %w", u, rerr)
		}
		return b, nil
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		loc := resp.Header.Get("Location")
		resp.Body.Close()
		if loc == "" {
			return nil, &GhError{Status: resp.StatusCode, URL: u, Body: "redirect carries no Location header"}
		}
		return getSigned(ctx, loc)
	default:
		b, _ := readAllClose(resp)
		return nil, &GhError{Status: resp.StatusCode, URL: u, Body: string(b)}
	}
}

// No credential of ours is attached, and the query string — the signature — is
// stripped from any error, because an error string reaches a run directory and a
// report.
func getSigned(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("download from %s: %w", redactQuery(rawURL), err)
	}
	if resp.StatusCode != 200 {
		b, _ := readAllClose(resp)
		return nil, &GhError{Status: resp.StatusCode, URL: redactQuery(rawURL), Body: string(b)}
	}
	b, err := readAllClose(resp)
	if err != nil {
		return nil, fmt.Errorf("read response body from %s: %w", redactQuery(rawURL), err)
	}
	return b, nil
}

func redactQuery(rawURL string) string {
	if i := strings.IndexByte(rawURL, '?'); i >= 0 {
		return rawURL[:i] + "?<signature redacted>"
	}
	return rawURL
}

// uses the JSON envelope (not vnd.github.raw) so the response carries the SHA;
// never returns an empty body paired with a real SHA
func (c *Client) GetContentWithSHA(ctx context.Context, pathOrURL, ref string, allow404 bool) ([]byte, string, bool, error) {
	var params url.Values
	if ref != "" {
		params = url.Values{"ref": []string{ref}}
	}
	raw, _, err := c.Get(ctx, pathOrURL, params, allow404)
	if err != nil {
		return nil, "", false, err
	}
	if raw == nil {
		return nil, "", false, nil
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(raw, &data); err != nil {
		// a directory is a JSON array, not an object: not a file
		return nil, "", false, nil
	}
	objType := decodeString(data["type"])
	if objType == "symlink" || objType == "submodule" {
		// their SHA is the symlink blob / pinned gitlink, not file contents at this path
		return nil, "", false, nil
	}
	encoding := decodeString(data["encoding"])
	sha := decodeString(data["sha"])
	switch encoding {
	case "base64":
		content := decodeString(data["content"])
		decoded, derr := base64Decode(content)
		if derr != nil {
			return nil, "", false, nil
		}
		return decoded, sha, true, nil
	case "none":
		// 1-100 MB file: JSON envelope body is empty by design, so refetch raw and pair with the SHA we have
		body, _, rerr := c.GetRaw(ctx, pathOrURL, params, "application/vnd.github.raw+json")
		if rerr != nil {
			var ghErr *GhError
			if asGhError(rerr, &ghErr) {
				return nil, "", false, nil
			}
			return nil, "", false, rerr
		}
		return body, sha, true, nil
	default:
		return nil, "", false, nil
	}
}

// a 404 (typo'd/deleted ref) returns ("", nil), not an error
func (c *Client) ResolveRefCommitSHA(ctx context.Context, owner, repo, ref string) (string, error) {
	quoted := quoteKeepSlash(ref)
	raw, _, err := c.Get(ctx, fmt.Sprintf("/repos/%s/%s/commits/%s", owner, repo, quoted), nil, true)
	if err != nil {
		return "", err
	}
	if raw == nil {
		return "", nil
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(raw, &data); err != nil {
		return "", nil
	}
	return decodeString(data["sha"]), nil
}
