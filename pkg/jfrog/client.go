// pkg/platforms/jfrog/client.go
package jfrog

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

const (
	DefaultTimeout        = 30 * time.Second
	MaxConcurrentRequests = 100 // Conservative limit for JFrog API
)

// Client is an HTTP client for JFrog REST API
type Client struct {
	httpClient  *http.Client
	baseURL     string
	accessToken string // Access Token (Bearer auth) - preferred
	apiKey      string // API Key (X-JFrog-Art-Api header) - deprecated but still used
	username    string // Username for basic auth
	password    string // Password for basic auth
	semaphore   *semaphore.Weighted
	tokenMu     sync.Mutex // protects EnsureToken from concurrent calls
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

// WithHTTPTransport sets a custom HTTP transport on the underlying client.
func WithHTTPTransport(transport http.RoundTripper) ClientOption {
	return func(c *Client) {
		c.httpClient.Transport = transport
	}
}

// NewClient creates a new JFrog API client with functional options
// baseURL: JFrog instance URL (e.g., https://acme.jfrog.io)
// token: Access Token for Bearer auth (preferred method)
func NewClient(baseURL, token string, opts ...ClientOption) *Client {
	c := &Client{
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		baseURL:     strings.TrimSuffix(baseURL, "/"),
		accessToken: token,
		semaphore:   semaphore.NewWeighted(MaxConcurrentRequests),
	}

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	return c
}

// ClientConfig holds JFrog client configuration (for backward compatibility)
type ClientConfig struct {
	BaseURL     string        // JFrog instance URL (e.g., https://acme.jfrog.io)
	APIKey      string        // API Key (X-JFrog-Art-Api header) - deprecated but still used
	AccessToken string        // Access Token (Bearer auth) - preferred
	Username    string        // Username for basic auth
	Password    string        // Password for basic auth
	Timeout     time.Duration // Request timeout
	Concurrency int64         // Maximum concurrent requests
}

// NewClientWithConfig creates a new JFrog API client from a configuration struct
// This constructor supports all authentication methods:
// - Access Token (Bearer auth) - preferred
// - API Key (X-JFrog-Art-Api header) - deprecated but still used
// - Basic auth (username/password)
func NewClientWithConfig(config ClientConfig) *Client {
	if config.Timeout == 0 {
		config.Timeout = DefaultTimeout
	}

	concurrency := config.Concurrency
	if concurrency == 0 {
		concurrency = MaxConcurrentRequests
	}

	c := &Client{
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		baseURL:     strings.TrimSuffix(config.BaseURL, "/"),
		accessToken: config.AccessToken,
		apiKey:      config.APIKey,
		username:    config.Username,
		password:    config.Password,
		semaphore:   semaphore.NewWeighted(concurrency),
	}

	return c
}

// Get performs a GET request to the JFrog API
func (c *Client) Get(ctx context.Context, path string) (*http.Response, error) {
	return c.do(ctx, "GET", path, nil)
}

// Post performs a POST request to the JFrog API
func (c *Client) Post(ctx context.Context, path string, body io.Reader) (*http.Response, error) {
	return c.do(ctx, "POST", path, body)
}

// Delete performs a DELETE request to the JFrog API
func (c *Client) Delete(ctx context.Context, path string) (*http.Response, error) {
	return c.do(ctx, "DELETE", path, nil)
}

// PostAQL performs a POST request to the AQL search API with text/plain content type
func (c *Client) PostAQL(ctx context.Context, query string) (*http.Response, error) {
	if err := c.semaphore.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("acquiring semaphore: %w", err)
	}

	reqURL := c.buildURL("/api/search/aql")

	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(query))
	if err != nil {
		c.semaphore.Release(1)
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set authentication headers
	c.setAuthHeaders(req)

	// AQL requires text/plain content type
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.semaphore.Release(1)
		return nil, err
	}

	c.semaphore.Release(1)
	return resp, nil
}

// buildURL constructs the full URL for a given path.
// For JFrog Cloud SaaS, Artifactory APIs require the /artifactory prefix.
func (c *Client) buildURL(path string) string {
	// Check if path starts with /api/ (Artifactory APIs)
	if len(path) >= 5 && path[:5] == "/api/" {
		return c.baseURL + "/artifactory" + path
	}
	// All other paths (including /pipelines/) use as-is
	return c.baseURL + path
}

// setAuthHeaders sets authentication headers on the request
// Priority: Access Token > API Key > Basic Auth
func (c *Client) setAuthHeaders(req *http.Request) {
	if c.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	} else if c.apiKey != "" {
		req.Header.Set("X-JFrog-Art-Api", c.apiKey)
	} else if c.username != "" && c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}
}

// do performs an HTTP request with authentication and concurrency control
func (c *Client) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	if err := c.semaphore.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("acquiring semaphore: %w", err)
	}

	reqURL := c.buildURL(path)

	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		c.semaphore.Release(1)
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set authentication headers
	c.setAuthHeaders(req)

	// Set common headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.semaphore.Release(1)
		return nil, err
	}

	c.semaphore.Release(1)
	return resp, nil
}

// BaseURL returns the configured base URL
func (c *Client) BaseURL() string {
	return c.baseURL
}

// GetAccessToken returns the current access token, obtaining one via credentials if needed
func (c *Client) GetAccessToken(ctx context.Context) (string, error) {
	if c.accessToken != "" {
		return c.accessToken, nil
	}

	// No token, try to get one via username/password
	if c.username == "" || c.password == "" {
		return "", fmt.Errorf("no access token and no credentials available")
	}

	// Call JFrog Access API to get token
	token, err := c.exchangeCredentialsForToken(ctx)
	if err != nil {
		return "", err
	}

	// Don't persist the token - return it for gRPC auth without changing
	// how subsequent REST API calls authenticate
	return token, nil
}

// EnsureToken ensures the client has an access token for Bearer auth.
// If username/password are provided but no token exists, exchanges credentials for a token.
// This is required for JFrog Cloud SaaS endpoints like /api/security/users/ that only accept Bearer auth.
func (c *Client) EnsureToken(ctx context.Context) error {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	// Already have a token - nothing to do
	if c.accessToken != "" {
		return nil
	}

	// No token and no credentials - cannot obtain token
	if c.username == "" || c.password == "" {
		return nil
	}

	// Exchange username/password for access token
	token, err := c.exchangeCredentialsForToken(ctx)
	if err != nil {
		return fmt.Errorf("exchanging credentials for token: %w", err)
	}

	// Persist the token for subsequent API calls
	c.accessToken = token
	return nil
}

// exchangeCredentialsForToken exchanges username/password for a JWT access token.
// Uses the Artifactory Security Token API (/api/security/token) which accepts Basic Auth.
//
// This creates an Artifactory-issued token (sub: jfrt@...) which works for:
// - Artifactory REST APIs (repositories, artifacts, builds, pipelines)
// - General JFrog platform operations
//
// IMPORTANT: For JFrog ML Secret Management, a Federation-issued token (sub: jfac@...)
// with "applied-permissions/admin" scope is required. Such tokens can only be created:
// - Via the JFrog UI (Identity & Access → Access Tokens → Generate Admin Token)
// - Via the Access API using an existing Federation token
// For ML secrets, provide the token directly via JFrog.Token in the config.
//
// NOTE: This only works for JFrog instances that support Basic Auth authentication.
// For JFrog instances using SSO/SAML/OAuth, Basic Auth is disabled and this will fail.
// In such cases, provide a JWT access token directly via JFrog.Token in the config.
//
// See: https://jfrog.com/help/r/jfrog-rest-apis/create-a-token
func (c *Client) exchangeCredentialsForToken(ctx context.Context) (string, error) {
	// Use the Artifactory security token endpoint (accepts Basic Auth)
	// NOT the Access API endpoint which requires an existing Bearer token
	reqURL := c.baseURL + "/artifactory/api/security/token"

	// Request a token with applied-permissions/user scope and broader audience for better API access
	// - applied-permissions/user: grants user-level permissions
	// - expires_in=31536000: 1 year expiration
	// - refreshable=true: allows token refresh
	// - audience=*@*: broad audience for cross-service access
	body := strings.NewReader("username=" + c.username + "&scope=applied-permissions/user&expires_in=31536000&refreshable=true&audience=*@*")
	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, body)
	if err != nil {
		return "", fmt.Errorf("creating token request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == 401 {
			return "", fmt.Errorf("token request failed (401 Unauthorized): Basic auth not accepted. "+
				"This JFrog instance may use SSO/SAML. Provide a JWT access token via JFrog.Token instead. "+
				"Response: %s", string(respBody))
		}
		return "", fmt.Errorf("token request error (%d): %s", resp.StatusCode, string(respBody))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("parsing token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("no access_token in response")
	}

	return tokenResp.AccessToken, nil
}

// extractUsernameFromJWT extracts the username from a JWT access token
// JWT format: header.payload.signature
// The payload contains a "sub" claim like "jfac@.../users/username@domain.com"
func (c *Client) extractUsernameFromJWT() string {
	if c.accessToken == "" {
		return ""
	}

	// Split JWT into parts
	parts := strings.Split(c.accessToken, ".")
	if len(parts) != 3 {
		return ""
	}

	// Decode base64url-encoded payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}

	// Parse JSON payload
	var claims struct {
		Sub string `json:"sub"` // Format: jfac@.../users/username@domain.com
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}

	// Extract username from sub claim (after last /users/)
	if idx := strings.LastIndex(claims.Sub, "/users/"); idx >= 0 {
		return claims.Sub[idx+7:] // +7 to skip "/users/"
	}

	return ""
}

// GetUser retrieves the current authenticated user information
// Uses GET /artifactory/api/security/users/{username}
// This endpoint works with basic auth and returns detailed user info
func (c *Client) GetUser(ctx context.Context) (*User, error) {
	var username string

	// Determine username based on authentication method
	if c.username != "" {
		// Basic auth - use configured username
		username = c.username
	} else if c.accessToken != "" {
		// Token auth - extract username from JWT
		username = c.extractUsernameFromJWT()
		if username == "" {
			return nil, fmt.Errorf("cannot determine username from token")
		}
	} else {
		return nil, fmt.Errorf("no authentication credentials available")
	}

	// URL-encode username (@ becomes %40, etc.)
	encodedUsername := url.QueryEscape(username)
	path := "/api/security/users/" + encodedUsername

	resp, err := c.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return &user, nil
}

// GetSystemInfo retrieves system information (version, license, addons)
func (c *Client) GetSystemInfo(ctx context.Context) (map[string]interface{}, error) {
	resp, err := c.Get(ctx, "/api/system")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}
