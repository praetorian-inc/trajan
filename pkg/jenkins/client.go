package jenkins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

const (
	DefaultTimeout        = 30 * time.Second
	MaxConcurrentRequests = 20
)

// Client is a Jenkins REST API client
type Client struct {
	httpClient *http.Client
	baseURL    string
	token      string
	username   string
	semaphore  *semaphore.Weighted

	crumb        *CrumbInfo
	crumbMu      sync.Mutex
	crumbFetched bool
}

// String implements fmt.Stringer to prevent token leakage in logs
func (c *Client) String() string {
	if c == nil {
		return "Client{nil}"
	}
	return fmt.Sprintf("Client{baseURL: %q, token: [REDACTED]}", c.baseURL)
}

// GoString implements fmt.GoStringer to prevent token leakage with %#v format
func (c *Client) GoString() string {
	if c == nil {
		return "(*Client)(nil)"
	}
	return fmt.Sprintf("&Client{baseURL: %q, token: [REDACTED]}", c.baseURL)
}

// ClientOption configures a Client
type ClientOption func(*Client)

// WithTimeout sets the HTTP client timeout
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// WithConcurrency sets the maximum concurrent requests
func WithConcurrency(maxVal int64) ClientOption {
	return func(c *Client) {
		if maxVal > 0 {
			c.semaphore = semaphore.NewWeighted(maxVal)
		}
	}
}

// WithHTTPTransport sets a custom HTTP transport on the underlying client.
// The cookie jar on the client is preserved.
func WithHTTPTransport(transport http.RoundTripper) ClientOption {
	return func(c *Client) {
		c.httpClient.Transport = transport
	}
}

// WithUsername sets the username for HTTP Basic authentication
func WithUsername(username string) ClientOption {
	return func(c *Client) {
		c.username = username
	}
}

// setAuth sets the appropriate authentication header on the request.
// If both username and token are set, HTTP Basic auth is used.
// Otherwise, no auth header is set (anonymous access).
func (c *Client) setAuth(req *http.Request) {
	if c.username != "" && c.token != "" {
		req.SetBasicAuth(c.username, c.token)
	}
}

// NewClient creates a new Jenkins API client
func NewClient(baseURL, token string, opts ...ClientOption) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}

	jar, _ := cookiejar.New(nil)
	c := &Client{
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
			Jar:     jar,
		},
		baseURL:   baseURL,
		token:     token,
		semaphore: semaphore.NewWeighted(MaxConcurrentRequests),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// getJSON performs a GET request and decodes the JSON response
func (c *Client) getJSON(ctx context.Context, path string, v interface{}) error {
	if err := c.semaphore.Acquire(ctx, 1); err != nil {
		return fmt.Errorf("acquiring semaphore: %w", err)
	}
	defer c.semaphore.Release(1)

	reqURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error: status %d for %s", resp.StatusCode, path)
	}

	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	return nil
}

// getRaw performs a GET request and returns the raw response body
func (c *Client) getRaw(ctx context.Context, path string) ([]byte, error) {
	if err := c.semaphore.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("acquiring semaphore: %w", err)
	}
	defer c.semaphore.Release(1)

	reqURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: status %d for %s", resp.StatusCode, path)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return body, nil
}

// fetchCrumb retrieves and caches the CSRF crumb. Safe for concurrent use.
// Retries on transient errors; caches success and 404 permanently.
func (c *Client) fetchCrumb(ctx context.Context) (*CrumbInfo, error) {
	c.crumbMu.Lock()
	defer c.crumbMu.Unlock()

	if c.crumbFetched {
		return c.crumb, nil
	}

	var info CrumbInfo
	err := c.getJSON(ctx, "/crumbIssuer/api/json", &info)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			c.crumb = nil
			c.crumbFetched = true
			return nil, nil
		}
		return nil, err
	}

	c.crumb = &info
	c.crumbFetched = true
	return c.crumb, nil
}

func (c *Client) CSRFDisabled() bool {
	return c.crumbFetched && c.crumb == nil
}

// postForm performs a POST request with form data, auto-attaching crumb.
func (c *Client) postForm(ctx context.Context, path string, data map[string]string) ([]byte, error) {
	// Fetch crumb before acquiring semaphore to avoid double-acquire deadlock
	// (fetchCrumb -> getJSON also acquires the semaphore)
	crumb, err := c.fetchCrumb(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching crumb: %w", err)
	}

	if err := c.semaphore.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("acquiring semaphore: %w", err)
	}
	defer c.semaphore.Release(1)

	form := url.Values{}
	for k, v := range data {
		form.Set(k, v)
	}

	reqURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.setAuth(req)

	if crumb != nil {
		req.Header.Set(crumb.CrumbRequestField, crumb.Crumb)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error: status %d for %s: %s", resp.StatusCode, path, string(body))
	}

	return body, nil
}

// postRaw performs a POST request with raw body data, auto-attaching crumb.
func (c *Client) postRaw(ctx context.Context, path, contentType string, data []byte) ([]byte, error) {
	// Fetch crumb before acquiring semaphore to avoid double-acquire deadlock
	// (fetchCrumb -> getJSON also acquires the semaphore)
	crumb, err := c.fetchCrumb(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching crumb: %w", err)
	}

	if err := c.semaphore.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("acquiring semaphore: %w", err)
	}
	defer c.semaphore.Release(1)

	reqURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", contentType)
	c.setAuth(req)
	if crumb != nil {
		req.Header.Set(crumb.CrumbRequestField, crumb.Crumb)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error: status %d for %s: %s", resp.StatusCode, path, string(body))
	}

	return body, nil
}

// GetServerInfo returns Jenkins server metadata.
// Parses version from X-Jenkins response header.
func (c *Client) GetServerInfo(ctx context.Context) (*ServerInfo, error) {
	if err := c.semaphore.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("acquiring semaphore: %w", err)
	}
	defer c.semaphore.Release(1)

	reqURL := c.baseURL + "/api/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: status %d", resp.StatusCode)
	}

	var info ServerInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	info.Version = resp.Header.Get("X-Jenkins")
	return &info, nil
}

// GetWhoAmI returns the authenticated user's identity.
func (c *Client) GetWhoAmI(ctx context.Context) (*WhoAmI, error) {
	var who WhoAmI
	if err := c.getJSON(ctx, "/whoAmI/api/json", &who); err != nil {
		return nil, err
	}
	return &who, nil
}

// ListNodes returns all build agents/nodes.
func (c *Client) ListNodes(ctx context.Context) ([]Node, error) {
	var resp NodesResponse
	if err := c.getJSON(ctx, "/computer/api/json?tree=computer[displayName,offline,temporarilyOffline,idle,numExecutors,assignedLabels[name]]", &resp); err != nil {
		return nil, err
	}
	return resp.Computer, nil
}

// ListPlugins returns all installed plugins.
func (c *Client) ListPlugins(ctx context.Context) ([]PluginInfo, error) {
	var resp PluginsResponse
	if err := c.getJSON(ctx, "/pluginManager/api/json?tree=plugins[shortName,version,active,enabled,hasUpdate,longName]&depth=1", &resp); err != nil {
		return nil, err
	}
	return resp.Plugins, nil
}

// PostScript executes a Groovy script via the script console.
// Returns the script output text.
func (c *Client) PostScript(ctx context.Context, script string) (string, error) {
	body, err := c.postForm(ctx, "/scriptText", map[string]string{"script": script})
	if err != nil {
		return "", fmt.Errorf("executing script: %w", err)
	}
	return string(body), nil
}

// CheckScriptConsole probes whether /script is accessible.
// Returns (accessible bool, statusCode int, error).
func (c *Client) CheckScriptConsole(ctx context.Context) (bool, int, error) {
	if err := c.semaphore.Acquire(ctx, 1); err != nil {
		return false, 0, fmt.Errorf("acquiring semaphore: %w", err)
	}
	defer c.semaphore.Release(1)

	reqURL := c.baseURL + "/script"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return false, 0, err
	}
	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body) // drain body

	return resp.StatusCode == http.StatusOK, resp.StatusCode, nil
}

// ListJobsRecursive returns all jobs including those in folders.
func (c *Client) ListJobsRecursive(ctx context.Context) ([]Job, error) {
	var resp JobsResponse
	if err := c.getJSON(ctx, "/api/json?tree=jobs[name,url,color,fullName,_class,jobs[name,url,color,fullName,_class]]", &resp); err != nil {
		return nil, err
	}
	return flattenJobs(resp.Jobs, ""), nil
}

// CreateJob creates a new Jenkins job with the given config XML.
func (c *Client) CreateJob(ctx context.Context, name, configXML string) error {
	_, err := c.postRaw(ctx, "/createItem?name="+url.QueryEscape(name), "application/xml", []byte(configXML))
	if err != nil {
		return fmt.Errorf("creating job %s: %w", name, err)
	}
	return nil
}

// encodeJobPath encodes a Jenkins job name for use in URLs.
// Splits on "/" (folder separators), URL-encodes each segment, and rejoins with "/job/".
func encodeJobPath(name string) string {
	segments := strings.Split(name, "/")
	for i, seg := range segments {
		segments[i] = url.PathEscape(seg)
	}
	return strings.Join(segments, "/job/")
}

// DeleteJob deletes a Jenkins job by name.
func (c *Client) DeleteJob(ctx context.Context, name string) error {
	jobPath := encodeJobPath(name)
	_, err := c.postForm(ctx, fmt.Sprintf("/job/%s/doDelete", jobPath), nil)
	return err
}

// TriggerBuild triggers a build for the named job.
func (c *Client) TriggerBuild(ctx context.Context, name string) error {
	jobPath := encodeJobPath(name)
	_, err := c.postForm(ctx, fmt.Sprintf("/job/%s/build", jobPath), nil)
	return err
}

// GetBuildConsole returns console output for a specific build.
func (c *Client) GetBuildConsole(ctx context.Context, name string, buildNum int) (string, error) {
	jobPath := encodeJobPath(name)
	body, err := c.getRaw(ctx, fmt.Sprintf("/job/%s/%d/consoleText", jobPath, buildNum))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// GetLastBuild returns info about the last build of a job.
func (c *Client) GetLastBuild(ctx context.Context, name string) (*BuildInfo, error) {
	jobPath := encodeJobPath(name)
	var info BuildInfo
	if err := c.getJSON(ctx, fmt.Sprintf("/job/%s/lastBuild/api/json?tree=number,result,timestamp,duration,url", jobPath), &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// flattenJobs recursively flattens nested folder jobs into a single slice.
func flattenJobs(jobs []Job, prefix string) []Job {
	var result []Job
	for _, j := range jobs {
		if len(j.Jobs) > 0 {
			// This is a folder — recurse
			folderPath := j.Name
			if prefix != "" {
				folderPath = prefix + "/" + j.Name
			}
			result = append(result, flattenJobs(j.Jobs, folderPath)...)
		} else {
			if prefix != "" {
				j.FullName = prefix + "/" + j.Name
				j.InFolder = true
			}
			result = append(result, j)
		}
	}
	return result
}
