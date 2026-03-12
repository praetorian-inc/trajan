// pkg/github/client.go
package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/sync/semaphore"
)

const (
	DefaultBaseURL        = "https://api.github.com"
	DefaultTimeout        = 30 * time.Second
	MaxConcurrentRequests = 90 // GitHub limit is 100, use 90 for buffer
)

// Client is a GitHub REST API client with rate limiting
type Client struct {
	httpClient  *http.Client
	baseURL     string
	token       string
	rateLimiter *RateLimiter
	semaphore   *semaphore.Weighted // Concurrent request limiter
}

// String implements fmt.Stringer to prevent token leakage in logs
func (c *Client) String() string {
	if c == nil {
		return "Client{nil}"
	}

	return fmt.Sprintf("Client{baseURL: %q, token: [REDACTED], rateLimiter: %+v}",
		c.baseURL,
		c.rateLimiter,
	)
}

// GoString implements fmt.GoStringer to prevent token leakage with %#v format
func (c *Client) GoString() string {
	if c == nil {
		return "(*Client)(nil)"
	}

	return fmt.Sprintf("&Client{baseURL: %q, token: [REDACTED], rateLimiter: %#v}",
		c.baseURL,
		c.rateLimiter,
	)
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
func WithConcurrency(max int64) ClientOption {
	return func(c *Client) {
		if max > 0 {
			c.semaphore = semaphore.NewWeighted(max)
		}
	}
}

// WithHTTPTransport sets a custom HTTP transport on the underlying client.
func WithHTTPTransport(transport http.RoundTripper) ClientOption {
	return func(c *Client) {
		c.httpClient.Transport = transport
	}
}

// NewClient creates a new GitHub REST client
func NewClient(baseURL, token string, opts ...ClientOption) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	c := &Client{
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		baseURL:     baseURL,
		token:       token,
		rateLimiter: NewRateLimiter(),
		semaphore:   semaphore.NewWeighted(MaxConcurrentRequests),
	}

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	return c
}

// User represents a GitHub user
type User struct {
	Login string `json:"login"`
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// Owner represents a repository owner
type Owner struct {
	Login string `json:"login"`
	ID    int    `json:"id"`
	Type  string `json:"type"`
}

// Permissions represents repository permissions
type Permissions struct {
	Admin bool `json:"admin"`
	Push  bool `json:"push"`
	Pull  bool `json:"pull"`
}

// Repository represents a GitHub repository
type Repository struct {
	ID            int         `json:"id"`
	Name          string      `json:"name"`
	FullName      string      `json:"full_name"`
	Owner         Owner       `json:"owner"`
	DefaultBranch string      `json:"default_branch"`
	Private       bool        `json:"private"`
	Archived      bool        `json:"archived"`
	HTMLURL       string      `json:"html_url"`
	Permissions   Permissions `json:"permissions"`
}

// WorkflowFile represents a workflow file from the API
type WorkflowFile struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	SHA         string `json:"sha"`
	Size        int    `json:"size"`
	URL         string `json:"url"`
	DownloadURL string `json:"download_url"`
	Content     string `json:"content"` // base64 encoded
	Encoding    string `json:"encoding"`
}

// do performs an HTTP request with rate limiting and concurrency control
func (c *Client) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	// Acquire concurrency slot
	if err := c.semaphore.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("acquiring concurrency slot: %w", err)
	}
	defer c.semaphore.Release(1)

	// Wait if rate limited
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit wait: %w", err)
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Only set Authorization header if token is provided (allow anonymous access for public repos)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "trajan/1.0 (https://github.com/praetorian-inc/trajan)")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}

	// Update rate limiter from response
	c.rateLimiter.Update(resp.Header)

	return resp, nil
}

// get performs a GET request and decodes JSON response
func (c *Client) get(ctx context.Context, path string, v interface{}) error {
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	return json.NewDecoder(resp.Body).Decode(v)
}

// GetUser returns the authenticated user
func (c *Client) GetUser(ctx context.Context) (*User, error) {
	var user User
	if err := c.get(ctx, "/user", &user); err != nil {
		return nil, fmt.Errorf("getting user: %w", err)
	}
	return &user, nil
}

// GetRepository returns a single repository
func (c *Client) GetRepository(ctx context.Context, owner, repo string) (*Repository, error) {
	var repository Repository
	path := fmt.Sprintf("/repos/%s/%s", owner, repo)
	if err := c.get(ctx, path, &repository); err != nil {
		return nil, fmt.Errorf("getting repository: %w", err)
	}
	return &repository, nil
}

// ListOrgRepos lists repositories for an organization
func (c *Client) ListOrgRepos(ctx context.Context, org string) ([]Repository, error) {
	var repos []Repository
	page := 1
	perPage := 100

	for {
		var pageRepos []Repository
		path := fmt.Sprintf("/orgs/%s/repos?per_page=%d&page=%d", org, perPage, page)
		if err := c.get(ctx, path, &pageRepos); err != nil {
			return nil, fmt.Errorf("listing org repos: %w", err)
		}

		if len(pageRepos) == 0 {
			break
		}

		repos = append(repos, pageRepos...)
		page++
	}

	return repos, nil
}

// ListUserRepos lists repositories for a user
// If user is empty string, lists repositories for the authenticated user
func (c *Client) ListUserRepos(ctx context.Context, user string) ([]Repository, error) {
	var repos []Repository
	page := 1
	perPage := 100

	for {
		var pageRepos []Repository
		var path string

		if user == "" {
			// Authenticated user endpoint (singular /user/)
			// Include owner, collaborator, and organization_member affiliations
			// Include all visibilities (public, private, internal)
			path = fmt.Sprintf("/user/repos?affiliation=owner,collaborator,organization_member&visibility=all&per_page=%d&page=%d", perPage, page)
		} else {
			// Specific user endpoint (plural /users/)
			path = fmt.Sprintf("/users/%s/repos?per_page=%d&page=%d", user, perPage, page)
		}

		if err := c.get(ctx, path, &pageRepos); err != nil {
			return nil, fmt.Errorf("listing user repos: %w", err)
		}

		if len(pageRepos) == 0 {
			break
		}

		repos = append(repos, pageRepos...)
		page++
	}

	return repos, nil
}

// GetWorkflowFiles returns workflow files for a repository
func (c *Client) GetWorkflowFiles(ctx context.Context, owner, repo string) ([]WorkflowFile, error) {
	path := fmt.Sprintf("/repos/%s/%s/contents/.github/workflows", owner, repo)

	var files []WorkflowFile
	if err := c.get(ctx, path, &files); err != nil {
		// 404 means no workflows directory - not an error
		if strings.Contains(err.Error(), "404") {
			return nil, nil
		}
		return nil, err
	}

	// Filter to only .yml/.yaml files
	var workflows []WorkflowFile
	for _, f := range files {
		if strings.HasSuffix(f.Name, ".yml") || strings.HasSuffix(f.Name, ".yaml") {
			workflows = append(workflows, f)
		}
	}

	return workflows, nil
}

// GetWorkflowContent returns the content of a workflow file
func (c *Client) GetWorkflowContent(ctx context.Context, owner, repo, path string) ([]byte, error) {
	apiPath := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, path)

	var file WorkflowFile
	if err := c.get(ctx, apiPath, &file); err != nil {
		return nil, fmt.Errorf("getting workflow content: %w", err)
	}

	// Decode base64 content
	if file.Encoding == "base64" {
		return decodeBase64(file.Content)
	}

	return []byte(file.Content), nil
}

// GetWorkflowContentAtRef returns the content of a workflow file at a specific git ref
func (c *Client) GetWorkflowContentAtRef(ctx context.Context, owner, repo, path, ref string) ([]byte, error) {
	apiPath := fmt.Sprintf("/repos/%s/%s/contents/%s?ref=%s", owner, repo, path, ref)

	var file WorkflowFile
	if err := c.get(ctx, apiPath, &file); err != nil {
		return nil, fmt.Errorf("getting workflow content at ref: %w", err)
	}

	// Decode base64 content
	if file.Encoding == "base64" {
		return decodeBase64(file.Content)
	}

	return []byte(file.Content), nil
}

// GetFileMetadata returns metadata (including SHA) for a file via the contents API
func (c *Client) GetFileMetadata(ctx context.Context, owner, repo, path string) (*WorkflowFile, error) {
	apiPath := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, path)

	var file WorkflowFile
	if err := c.get(ctx, apiPath, &file); err != nil {
		return nil, fmt.Errorf("getting file metadata: %w", err)
	}

	return &file, nil
}

// decodeBase64 decodes base64 content (GitHub returns with newlines)
func decodeBase64(s string) ([]byte, error) {
	// GitHub returns content with newlines
	s = strings.ReplaceAll(s, "\n", "")
	return base64.StdEncoding.DecodeString(s)
}

// getWithRetry performs a GET request with exponential backoff for retryable errors
// Retries on: 429 (rate limit), 500, 502, 503, 504 (server errors)
// Does NOT retry on: 400, 401, 403, 404 (client errors)
func (c *Client) getWithRetry(ctx context.Context, path string, v interface{}, maxRetries int) error {
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err := c.do(ctx, http.MethodGet, path, nil)
		if err != nil {
			lastErr = err
			continue
		}

		// Success case - decode and return
		if resp.StatusCode == http.StatusOK {
			defer resp.Body.Close() // Only defer on success (returns immediately)
			return json.NewDecoder(resp.Body).Decode(v)
		}

		// Read body for error message, then close immediately
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close() // Close NOW, not deferred

		// Check if retryable
		switch resp.StatusCode {
		case 429: // Rate limited
			lastErr = &APIError{StatusCode: 429, Message: string(body)}

			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
			fmt.Fprintf(os.Stderr, "Rate limited by API (429), retrying in %v...\n", backoff)

			select {
			case <-time.After(backoff):
				// Continue to next attempt
			case <-ctx.Done():
				return ctx.Err()
			}

		case 500, 502, 503, 504: // Server errors - use exponential backoff
			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			if backoff > 60*time.Second {
				backoff = 60 * time.Second // Cap at 60 seconds
			}

			select {
			case <-time.After(backoff):
				// Continue to next attempt
			case <-ctx.Done():
				return ctx.Err()
			}

			lastErr = &APIError{StatusCode: resp.StatusCode, Message: string(body)}

		default:
			// Non-retryable error (4xx except 429)
			return &APIError{StatusCode: resp.StatusCode, Message: string(body)}
		}
	}

	return fmt.Errorf("max retries (%d) exceeded: %w", maxRetries, lastErr)
}

// RateLimiter returns the rate limiter for inspection
func (c *Client) RateLimiter() *RateLimiter {
	return c.rateLimiter
}

// HTTPClient returns the underlying HTTP client
// This is used by tokenprobe for making raw HTTP requests
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}

// ListAuthenticatedUserOrgs lists organizations for the authenticated user
func (c *Client) ListAuthenticatedUserOrgs(ctx context.Context) ([]Organization, error) {
	var orgs []Organization
	page := 1
	perPage := 100

	for {
		var pageOrgs []Organization
		path := fmt.Sprintf("/user/orgs?per_page=%d&page=%d", perPage, page)
		if err := c.get(ctx, path, &pageOrgs); err != nil {
			return nil, fmt.Errorf("listing user orgs: %w", err)
		}

		if len(pageOrgs) == 0 {
			break
		}

		orgs = append(orgs, pageOrgs...)
		page++
	}

	return orgs, nil
}

// GetOrgDetails returns detailed information about an organization
func (c *Client) GetOrgDetails(ctx context.Context, org string) (*OrgDetail, error) {
	var detail OrgDetail
	path := fmt.Sprintf("/orgs/%s", org)
	if err := c.get(ctx, path, &detail); err != nil {
		return nil, fmt.Errorf("getting org details: %w", err)
	}
	return &detail, nil
}

// ForkRepository forks a repository to the authenticated user's account
func (c *Client) ForkRepository(ctx context.Context, owner, repo string) (*Repository, error) {
	path := fmt.Sprintf("/repos/%s/%s/forks", owner, repo)
	resp, err := c.do(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, fmt.Errorf("forking repository: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var fork Repository
	if err := json.NewDecoder(resp.Body).Decode(&fork); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &fork, nil
}

// GetRunners lists self-hosted runners for a repository
func (c *Client) GetRunners(ctx context.Context, owner, repo string) ([]Runner, error) {
	path := fmt.Sprintf("/repos/%s/%s/actions/runners", owner, repo)

	var response RunnersResponse
	if err := c.get(ctx, path, &response); err != nil {
		return nil, fmt.Errorf("getting runners: %w", err)
	}

	return response.Runners, nil
}

// GetRunnerRegistrationToken gets a registration token for self-hosted runners
func (c *Client) GetRunnerRegistrationToken(ctx context.Context, owner, repo string) (string, error) {
	path := fmt.Sprintf("/repos/%s/%s/actions/runners/registration-token", owner, repo)

	resp, err := c.do(ctx, http.MethodPost, path, nil)
	if err != nil {
		return "", fmt.Errorf("getting runner registration token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}

	return result.Token, nil
}

// GetWorkflowRunLogs downloads workflow run logs
func (c *Client) GetWorkflowRunLogs(ctx context.Context, owner, repo string, runID int64) ([]byte, error) {
	path := fmt.Sprintf("/repos/%s/%s/actions/runs/%d/logs", owner, repo, runID)

	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("getting workflow run logs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	logs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading logs: %w", err)
	}

	return logs, nil
}

// CreateGist creates a new gist
func (c *Client) CreateGist(ctx context.Context, description string, public bool, files map[string]string) (*Gist, error) {
	// Convert files map to GitHub gist format
	gistFiles := make(map[string]map[string]string)
	for filename, content := range files {
		gistFiles[filename] = map[string]string{"content": content}
	}

	payload := map[string]interface{}{
		"description": description,
		"public":      public,
		"files":       gistFiles,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling payload: %w", err)
	}

	resp, err := c.do(ctx, http.MethodPost, "/gists", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("creating gist: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var gist Gist
	if err := json.NewDecoder(resp.Body).Decode(&gist); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &gist, nil
}

// DeleteGist deletes a gist
func (c *Client) DeleteGist(ctx context.Context, gistID string) error {
	path := fmt.Sprintf("/gists/%s", gistID)

	resp, err := c.do(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("deleting gist: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// CreateDeployKey adds a deploy key to a repository
func (c *Client) CreateDeployKey(ctx context.Context, owner, repo string, input DeployKeyInput) (*DeployKey, error) {
	path := fmt.Sprintf("/repos/%s/%s/keys", owner, repo)

	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshaling input: %w", err)
	}

	resp, err := c.do(ctx, http.MethodPost, path, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("creating deploy key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var key DeployKey
	if err := json.NewDecoder(resp.Body).Decode(&key); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &key, nil
}

// DeleteDeployKey removes a deploy key from a repository
func (c *Client) DeleteDeployKey(ctx context.Context, owner, repo string, keyID int64) error {
	path := fmt.Sprintf("/repos/%s/%s/keys/%d", owner, repo, keyID)

	resp, err := c.do(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("deleting deploy key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetLatestRunnerRelease gets the latest actions/runner release info
func (c *Client) GetLatestRunnerRelease(ctx context.Context) (*RunnerRelease, error) {
	path := "/repos/actions/runner/releases/latest"

	var release RunnerRelease
	if err := c.get(ctx, path, &release); err != nil {
		return nil, fmt.Errorf("getting latest runner release: %w", err)
	}

	return &release, nil
}

// WorkflowArtifact represents a GitHub Actions workflow artifact
type WorkflowArtifact struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Size int64  `json:"size_in_bytes"`
}

// ListWorkflowRunArtifacts lists artifacts for a workflow run
func (c *Client) ListWorkflowRunArtifacts(ctx context.Context, owner, repo string, runID int64) ([]WorkflowArtifact, error) {
	path := fmt.Sprintf("/repos/%s/%s/actions/runs/%d/artifacts", owner, repo, runID)

	var result struct {
		TotalCount int64              `json:"total_count"`
		Artifacts  []WorkflowArtifact `json:"artifacts"`
	}

	if err := c.get(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing artifacts: %w", err)
	}

	return result.Artifacts, nil
}

// DownloadArtifact downloads a workflow artifact
func (c *Client) DownloadArtifact(ctx context.Context, owner, repo string, artifactID int64) ([]byte, error) {
	path := fmt.Sprintf("/repos/%s/%s/actions/artifacts/%d/zip", owner, repo, artifactID)

	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("downloading artifact: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	artifact, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading artifact: %w", err)
	}

	return artifact, nil
}
