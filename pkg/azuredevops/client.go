package azuredevops

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/sync/semaphore"
)

const (
	DefaultTimeout        = 30 * time.Second
	MaxConcurrentRequests = 100             // Conservative limit for TSTU model
	APIVersion            = "7.1"           // GA version, used by build, permissions, projects.
	APIVersionPreview     = "7.1-preview.1" // Preview version required by Graph, Tokens, ConnectionData, Identities APIs
)

type Client struct {
	httpClient  *http.Client
	orgURL      string // https://dev.azure.com/organization
	pat         string
	bearerToken string // Azure Entra ID OAuth bearer token (takes precedence over PAT)
	rateLimiter *RateLimiter
	semaphore   *semaphore.Weighted
}

// Prevents token leakage when a Client is logged.
func (c *Client) String() string {
	if c == nil {
		return "Client{nil}"
	}

	return fmt.Sprintf("Client{orgURL: %q, pat: [REDACTED], bearerToken: [REDACTED], rateLimiter: %+v}",
		c.orgURL,
		c.rateLimiter,
	)
}

// Prevents token leakage under %#v.
func (c *Client) GoString() string {
	if c == nil {
		return "(*Client)(nil)"
	}

	return fmt.Sprintf("&Client{orgURL: %q, pat: [REDACTED], bearerToken: [REDACTED], rateLimiter: %#v}",
		c.orgURL,
		c.rateLimiter,
	)
}

type ClientOption func(*Client)

func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

func WithConcurrency(maxConc int64) ClientOption {
	return func(c *Client) {
		if maxConc > 0 {
			c.semaphore = semaphore.NewWeighted(maxConc)
		}
	}
}

// When set, the client uses Bearer auth instead of Basic auth with PAT.
func WithBearerToken(token string) ClientOption {
	return func(c *Client) {
		c.bearerToken = token
	}
}

func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = hc
	}
}

// Browser (WASM) builds route through a local proxy to bypass Azure DevOps CORS restrictions.
func WithHTTPTransport(transport http.RoundTripper) ClientOption {
	return func(c *Client) {
		c.httpClient.Transport = transport
	}
}

func NewClient(orgURL, pat string, opts ...ClientOption) *Client {
	c := &Client{
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
			// Go's default policy strips Authorization on a cross-domain redirect, which breaks
			// bearer auth when ADO redirects between hosts (e.g. dev.azure.com -> vssps.dev.azure.com).
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				if auth := via[0].Header.Get("Authorization"); auth != "" {
					req.Header.Set("Authorization", auth)
				}
				return nil
			},
		},
		orgURL:      orgURL,
		pat:         pat,
		rateLimiter: NewRateLimiter(),
		semaphore:   semaphore.NewWeighted(MaxConcurrentRequests),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

func (c *Client) GetProject(ctx context.Context, projectNameOrID string) (*Project, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/_apis/projects/%s?api-version=%s", encodedProject, APIVersion)

	var project Project
	if err := c.getJSON(ctx, path, &project); err != nil {
		return nil, fmt.Errorf("getting project: %w", err)
	}

	return &project, nil
}

func (c *Client) ListRepositories(ctx context.Context, projectNameOrID string) ([]Repository, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/git/repositories?api-version=%s", encodedProject, APIVersion)

	var result RepositoryList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing repositories: %w", err)
	}

	return result.Value, nil
}

func (c *Client) GetRepository(ctx context.Context, projectNameOrID, repoNameOrID string) (*Repository, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	encodedRepo := url.PathEscape(repoNameOrID)
	path := fmt.Sprintf("/%s/_apis/git/repositories/%s?api-version=%s",
		encodedProject, encodedRepo, APIVersion)

	var repo Repository
	if err := c.getJSON(ctx, path, &repo); err != nil {
		return nil, fmt.Errorf("getting repository: %w", err)
	}

	return &repo, nil
}

func (c *Client) GetRepoFileContent(ctx context.Context, project, repoName, filePath string) (string, error) {
	encodedProject := url.PathEscape(project)
	encodedRepo := url.PathEscape(repoName)
	encodedPath := url.QueryEscape(filePath)
	path := fmt.Sprintf("/%s/_apis/git/repositories/%s/items?path=%s&includeContent=true&api-version=%s",
		encodedProject, encodedRepo, encodedPath, APIVersion)

	var result struct {
		Content string `json:"content"`
	}
	if err := c.getJSON(ctx, path, &result); err != nil {
		return "", err // Don't wrap - caller handles not-found gracefully
	}
	return result.Content, nil
}

// ref should be a branch name, tag, or commit SHA
func (c *Client) GetWorkflowFile(ctx context.Context, projectNameOrID, repoNameOrID, filePath, ref string) ([]byte, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	encodedRepo := url.PathEscape(repoNameOrID)
	encodedPath := url.QueryEscape(filePath)

	var apiPath string
	if ref == "" {
		apiPath = fmt.Sprintf("/%s/_apis/git/repositories/%s/items?path=/%s&api-version=%s",
			encodedProject, encodedRepo, encodedPath, APIVersion)
	} else {
		encodedRef := url.QueryEscape(ref)
		apiPath = fmt.Sprintf("/%s/_apis/git/repositories/%s/items?path=/%s&versionDescriptor.version=%s&api-version=%s",
			encodedProject, encodedRepo, encodedPath, encodedRef, APIVersion)
	}

	return c.getRaw(ctx, apiPath)
}

// The rate limiter and semaphore are shared, so every per-host client draws on one budget.
func (c *Client) WithBaseURL(newBaseURL string) *Client {
	return &Client{
		httpClient:  c.httpClient,
		orgURL:      newBaseURL,
		pat:         c.pat,
		bearerToken: c.bearerToken,
		rateLimiter: c.rateLimiter,
		semaphore:   c.semaphore,
	}
}

// User management, groups, tokens and memberships live on the VSSPS host.
func (c *Client) VSSPSClient() *Client {
	return c.WithBaseURL(replaceHost(c.orgURL, "vssps.dev.azure.com"))
}

// Code search lives on the AlmSearch host.
func (c *Client) SearchClient() *Client {
	return c.WithBaseURL(replaceHost(c.orgURL, "almsearch.dev.azure.com"))
}

// Release pipelines live on the VSRM host.
func (c *Client) VSRMClient() *Client {
	return c.WithBaseURL(replaceHost(c.orgURL, "vsrm.dev.azure.com"))
}

// Azure Artifacts feeds live on the Feeds host.
func (c *Client) FeedsClient() *Client {
	return c.WithBaseURL(replaceHost(c.orgURL, "feeds.dev.azure.com"))
}

func replaceHost(rawURL, newHost string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	parsed.Host = newHost
	return parsed.String()
}
