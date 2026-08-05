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

// Exists to keep the token out of logs.
func (c *Client) String() string {
	if c == nil {
		return "Client{nil}"
	}
	return fmt.Sprintf("Client{baseURL: %q, token: [REDACTED]}", c.baseURL)
}

// Exists to keep the token out of %#v output.
func (c *Client) GoString() string {
	if c == nil {
		return "(*Client)(nil)"
	}
	return fmt.Sprintf("&Client{baseURL: %q, token: [REDACTED]}", c.baseURL)
}

type ClientOption func(*Client)

func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

func WithConcurrency(maxVal int64) ClientOption {
	return func(c *Client) {
		if maxVal > 0 {
			c.semaphore = semaphore.NewWeighted(maxVal)
		}
	}
}

// The cookie jar on the client is preserved.
func WithHTTPTransport(transport http.RoundTripper) ClientOption {
	return func(c *Client) {
		c.httpClient.Transport = transport
	}
}

func WithUsername(username string) ClientOption {
	return func(c *Client) {
		c.username = username
	}
}

// Basic auth only when both username and token are set; otherwise anonymous.
func (c *Client) setAuth(req *http.Request) {
	if c.username != "" && c.token != "" {
		req.SetBasicAuth(c.username, c.token)
	}
}

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

// A 404 (CSRF disabled) is cached permanently; a transient error is not, so the
// next call retries. Safe for concurrent use.
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

func (c *Client) postForm(ctx context.Context, path string, data map[string]string) ([]byte, error) {
	// Before the semaphore: fetchCrumb -> getJSON acquires it too, which would deadlock.
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

func (c *Client) postRaw(ctx context.Context, path, contentType string, data []byte) ([]byte, error) {
	// Before the semaphore: fetchCrumb -> getJSON acquires it too, which would deadlock.
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

// The version comes from the X-Jenkins response header, not the JSON body.
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

func (c *Client) GetWhoAmI(ctx context.Context) (*WhoAmI, error) {
	var who WhoAmI
	if err := c.getJSON(ctx, "/whoAmI/api/json", &who); err != nil {
		return nil, err
	}
	return &who, nil
}

func (c *Client) ListNodes(ctx context.Context) ([]Node, error) {
	var resp NodesResponse
	if err := c.getJSON(ctx, "/computer/api/json?tree=computer[displayName,offline,temporarilyOffline,idle,numExecutors,assignedLabels[name]]", &resp); err != nil {
		return nil, err
	}
	return resp.Computer, nil
}

func (c *Client) ListPlugins(ctx context.Context) ([]PluginInfo, error) {
	var resp PluginsResponse
	if err := c.getJSON(ctx, "/pluginManager/api/json?tree=plugins[shortName,version,active,enabled,hasUpdate,longName]&depth=1", &resp); err != nil {
		return nil, err
	}
	return resp.Plugins, nil
}

func (c *Client) PostScript(ctx context.Context, script string) (string, error) {
	body, err := c.postForm(ctx, "/scriptText", map[string]string{"script": script})
	if err != nil {
		return "", fmt.Errorf("executing script: %w", err)
	}
	return string(body), nil
}

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

func (c *Client) ListJobsRecursive(ctx context.Context) ([]Job, error) {
	var resp JobsResponse
	if err := c.getJSON(ctx, "/api/json?tree=jobs[name,url,color,fullName,_class,jobs[name,url,color,fullName,_class]]", &resp); err != nil {
		return nil, err
	}
	return flattenJobs(resp.Jobs, ""), nil
}

func (c *Client) CreateJob(ctx context.Context, name, configXML string) error {
	_, err := c.postRaw(ctx, "/createItem?name="+url.QueryEscape(name), "application/xml", []byte(configXML))
	if err != nil {
		return fmt.Errorf("creating job %s: %w", name, err)
	}
	return nil
}

// Folder segments are URL-encoded individually and rejoined with "/job/".
func encodeJobPath(name string) string {
	segments := strings.Split(name, "/")
	for i, seg := range segments {
		segments[i] = url.PathEscape(seg)
	}
	return strings.Join(segments, "/job/")
}

func (c *Client) DeleteJob(ctx context.Context, name string) error {
	jobPath := encodeJobPath(name)
	_, err := c.postForm(ctx, fmt.Sprintf("/job/%s/doDelete", jobPath), nil)
	return err
}

func (c *Client) TriggerBuild(ctx context.Context, name string) error {
	jobPath := encodeJobPath(name)
	_, err := c.postForm(ctx, fmt.Sprintf("/job/%s/build", jobPath), nil)
	return err
}

func (c *Client) GetBuildConsole(ctx context.Context, name string, buildNum int) (string, error) {
	jobPath := encodeJobPath(name)
	body, err := c.getRaw(ctx, fmt.Sprintf("/job/%s/%d/consoleText", jobPath, buildNum))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (c *Client) GetLastBuild(ctx context.Context, name string) (*BuildInfo, error) {
	jobPath := encodeJobPath(name)
	var info BuildInfo
	if err := c.getJSON(ctx, fmt.Sprintf("/job/%s/lastBuild/api/json?tree=number,result,timestamp,duration,url", jobPath), &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func flattenJobs(jobs []Job, prefix string) []Job {
	var result []Job
	for _, j := range jobs {
		if len(j.Jobs) > 0 {
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
