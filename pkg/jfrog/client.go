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

type Client struct {
	httpClient  *http.Client
	baseURL     string
	accessToken string
	apiKey      string // Sent as X-JFrog-Art-Api; deprecated by JFrog.
	username    string
	password    string
	semaphore   *semaphore.Weighted
	tokenMu     sync.Mutex // protects EnsureToken from concurrent calls
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

func WithHTTPTransport(transport http.RoundTripper) ClientOption {
	return func(c *Client) {
		c.httpClient.Transport = transport
	}
}

func NewClient(baseURL, token string, opts ...ClientOption) *Client {
	c := &Client{
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		baseURL:     strings.TrimSuffix(baseURL, "/"),
		accessToken: token,
		semaphore:   semaphore.NewWeighted(MaxConcurrentRequests),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Legacy configuration shape kept for existing callers.
type ClientConfig struct {
	BaseURL     string
	APIKey      string // Sent as X-JFrog-Art-Api; deprecated by JFrog.
	AccessToken string
	Username    string
	Password    string
	Timeout     time.Duration
	Concurrency int64
}

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

func (c *Client) Get(ctx context.Context, path string) (*http.Response, error) {
	return c.do(ctx, "GET", path, nil)
}

func (c *Client) Post(ctx context.Context, path string, body io.Reader) (*http.Response, error) {
	return c.do(ctx, "POST", path, body)
}

func (c *Client) Delete(ctx context.Context, path string) (*http.Response, error) {
	return c.do(ctx, "DELETE", path, nil)
}

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

// JFrog Cloud SaaS requires the /artifactory prefix on Artifactory APIs.
func (c *Client) buildURL(path string) string {
	if len(path) >= 5 && path[:5] == "/api/" {
		return c.baseURL + "/artifactory" + path
	}
	// Everything else, /pipelines/ included, must not get the prefix.
	return c.baseURL + path
}

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

	c.setAuthHeaders(req)

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

func (c *Client) BaseURL() string {
	return c.baseURL
}

func (c *Client) GetAccessToken(ctx context.Context) (string, error) {
	if c.accessToken != "" {
		return c.accessToken, nil
	}

	if c.username == "" || c.password == "" {
		return "", fmt.Errorf("no access token and no credentials available")
	}

	token, err := c.exchangeCredentialsForToken(ctx)
	if err != nil {
		return "", err
	}

	// Deliberately not persisted: REST calls keep authenticating as before.
	return token, nil
}

// Required for JFrog Cloud SaaS endpoints such as /api/security/users, which
// accept Bearer auth only.
func (c *Client) EnsureToken(ctx context.Context) error {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	if c.accessToken != "" {
		return nil
	}

	if c.username == "" || c.password == "" {
		return nil
	}

	token, err := c.exchangeCredentialsForToken(ctx)
	if err != nil {
		return fmt.Errorf("exchanging credentials for token: %w", err)
	}

	c.accessToken = token
	return nil
}

// Uses the Artifactory Security Token API, which accepts Basic Auth and returns a
// jfrt@ token valid for Artifactory REST APIs. It fails outright on SSO/SAML
// instances, where Basic Auth is disabled. JFrog ML Secret Management instead needs
// a Federation-issued jfac@ token with applied-permissions/admin, which only the
// JFrog UI or the Access API can mint: pass one as JFrog.Token.
// https://jfrog.com/help/r/jfrog-rest-apis/create-a-token
func (c *Client) exchangeCredentialsForToken(ctx context.Context) (string, error) {
	// Not the Access API endpoint: that one needs an existing Bearer token.
	reqURL := c.baseURL + "/artifactory/api/security/token"

	// audience=*@* so the token crosses services; expires_in is one year.
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

func (c *Client) extractUsernameFromJWT() string {
	if c.accessToken == "" {
		return ""
	}

	parts := strings.Split(c.accessToken, ".")
	if len(parts) != 3 {
		return ""
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}

	var claims struct {
		Sub string `json:"sub"` // Format: jfac@.../users/username@domain.com
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}

	if idx := strings.LastIndex(claims.Sub, "/users/"); idx >= 0 {
		return claims.Sub[idx+7:] // +7 to skip "/users/"
	}

	return ""
}

func (c *Client) GetUser(ctx context.Context) (*User, error) {
	var username string

	if c.username != "" {
		username = c.username
	} else if c.accessToken != "" {
		username = c.extractUsernameFromJWT()
		if username == "" {
			return nil, fmt.Errorf("cannot determine username from token")
		}
	} else {
		return nil, fmt.Errorf("no authentication credentials available")
	}

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
