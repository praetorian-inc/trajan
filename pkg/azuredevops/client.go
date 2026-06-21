// pkg/platforms/azuredevops/client.go
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
	APIVersion            = "7.1"           // Azure DevOps REST API version (GA - used by build, permissions, projects, etc.)
	APIVersionPreview     = "7.1-preview.1" // Preview version required by Graph, Tokens, ConnectionData, Identities APIs
)

// Client is an Azure DevOps REST API v7.1 client with TSTU-based rate limiting
type Client struct {
	httpClient  *http.Client
	orgURL      string // https://dev.azure.com/organization
	pat         string // Personal Access Token
	bearerToken string // Azure Entra ID OAuth bearer token (takes precedence over PAT)
	rateLimiter *RateLimiter
	semaphore   *semaphore.Weighted
}

// String implements fmt.Stringer to prevent token leakage in logs
func (c *Client) String() string {
	if c == nil {
		return "Client{nil}"
	}

	return fmt.Sprintf("Client{orgURL: %q, pat: [REDACTED], bearerToken: [REDACTED], rateLimiter: %+v}",
		c.orgURL,
		c.rateLimiter,
	)
}

// GoString implements fmt.GoStringer to prevent token leakage with %#v format
func (c *Client) GoString() string {
	if c == nil {
		return "(*Client)(nil)"
	}

	return fmt.Sprintf("&Client{orgURL: %q, pat: [REDACTED], bearerToken: [REDACTED], rateLimiter: %#v}",
		c.orgURL,
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
func WithConcurrency(maxConc int64) ClientOption {
	return func(c *Client) {
		if maxConc > 0 {
			c.semaphore = semaphore.NewWeighted(maxConc)
		}
	}
}

// WithBearerToken sets an Azure Entra ID OAuth bearer token for authentication.
// When set, the client uses Bearer auth instead of Basic auth with PAT.
func WithBearerToken(token string) ClientOption {
	return func(c *Client) {
		c.bearerToken = token
	}
}

// WithHTTPClient replaces the underlying HTTP client (useful for testing).
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = hc
	}
}

// WithHTTPTransport sets a custom HTTP transport on the underlying client.
// Used in browser (WASM) context to route requests through a local proxy,
// bypassing Azure DevOps CORS restrictions.
func WithHTTPTransport(transport http.RoundTripper) ClientOption {
	return func(c *Client) {
		c.httpClient.Transport = transport
	}
}

// NewClient creates a new Azure DevOps REST API v7.1 client
// Authentication: Uses PAT via Basic Auth (empty username, PAT as password)
// Reference: https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/
func NewClient(orgURL, pat string, opts ...ClientOption) *Client {
	c := &Client{
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
			// Preserve Authorization header on redirects within Azure DevOps hosts.
			// Go's default policy strips the header on cross-domain redirects,
			// which breaks bearer token auth when ADO redirects between hosts
			// (e.g., dev.azure.com -> vssps.dev.azure.com).
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				// Preserve auth header if staying within Azure DevOps domains
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

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	return c
}

// GetProject retrieves a single project by name or ID
func (c *Client) GetProject(ctx context.Context, projectNameOrID string) (*Project, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/_apis/projects/%s?api-version=%s", encodedProject, APIVersion)

	var project Project
	if err := c.getJSON(ctx, path, &project); err != nil {
		return nil, fmt.Errorf("getting project: %w", err)
	}

	return &project, nil
}

// ListRepositories lists all repositories in a project
func (c *Client) ListRepositories(ctx context.Context, projectNameOrID string) ([]Repository, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/git/repositories?api-version=%s", encodedProject, APIVersion)

	var result RepositoryList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing repositories: %w", err)
	}

	return result.Value, nil
}

// GetRepository retrieves a single repository
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

// GetRepoFileContent retrieves the content of a file from a repository.
// API: GET {org}/{project}/_apis/git/repositories/{repo}/items?path={path}&includeContent=true&api-version=7.1-preview.1
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

// GetWorkflowFile retrieves a file from a repository (e.g., azure-pipelines.yml)
// path should be the file path (e.g., "azure-pipelines.yml" or ".azuredevops/pipelines/ci.yml")
// ref should be a branch name, tag, or commit SHA
func (c *Client) GetWorkflowFile(ctx context.Context, projectNameOrID, repoNameOrID, filePath, ref string) ([]byte, error) {
	// Azure DevOps API: GET {org}/{project}/_apis/git/repositories/{repo}/items?path={path}&versionDescriptor.version={ref}&api-version=7.1
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

// WithBaseURL creates a new Client sharing the same httpClient, PAT, rateLimiter,
// and semaphore but targeting a different base URL. Used for Azure DevOps multi-host endpoints.
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

// VSSPSClient returns a client for the VSSPS endpoint (vssps.dev.azure.com)
// used for user management, groups, tokens, and memberships.
func (c *Client) VSSPSClient() *Client {
	return c.WithBaseURL(replaceHost(c.orgURL, "vssps.dev.azure.com"))
}

// SearchClient returns a client for the AlmSearch endpoint (almsearch.dev.azure.com)
// used for code search functionality.
func (c *Client) SearchClient() *Client {
	return c.WithBaseURL(replaceHost(c.orgURL, "almsearch.dev.azure.com"))
}

// VSRMClient returns a client for the VSRM endpoint (vsrm.dev.azure.com)
// used for release pipeline management.
func (c *Client) VSRMClient() *Client {
	return c.WithBaseURL(replaceHost(c.orgURL, "vsrm.dev.azure.com"))
}

// FeedsClient returns a client for the Feeds endpoint (feeds.dev.azure.com)
// used for Azure Artifacts package management.
func (c *Client) FeedsClient() *Client {
	return c.WithBaseURL(replaceHost(c.orgURL, "feeds.dev.azure.com"))
}

// replaceHost replaces the host in the URL while preserving the path.
func replaceHost(rawURL, newHost string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	parsed.Host = newHost
	return parsed.String()
}
