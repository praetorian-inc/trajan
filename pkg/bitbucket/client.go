package bitbucket

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/sync/semaphore"
)

const (
	// DefaultBaseURL is the Bitbucket Cloud REST API v2 base URL.
	DefaultBaseURL = "https://api.bitbucket.org"
	// DefaultTimeout is the default HTTP client timeout.
	DefaultTimeout = 30 * time.Second
	// MaxConcurrentRequests is the default concurrency limit.
	MaxConcurrentRequests = 50
)

// AuthMode selects the authentication mechanism for the Bitbucket API.
type AuthMode int

const (
	// AuthBearer uses "Authorization: Bearer {token}" (access tokens with ATCTT3x prefix).
	AuthBearer AuthMode = iota
	// AuthBasic uses "Authorization: Basic base64(email:token)" (API tokens with ATATT3x prefix).
	AuthBasic
)

// Client is a Bitbucket Cloud REST API v2 client with concurrency control.
type Client struct {
	httpClient *http.Client
	baseURL    string
	token      string
	email      string // Non-empty only for AuthBasic
	authMode   AuthMode
	semaphore  *semaphore.Weighted
}

// String implements fmt.Stringer to prevent token leakage in logs.
func (c *Client) String() string {
	if c == nil {
		return "Client{nil}"
	}
	return fmt.Sprintf("Client{baseURL: %q, authMode: %d, token: [REDACTED]}", c.baseURL, c.authMode)
}

// GoString implements fmt.GoStringer to prevent token leakage with %#v format.
func (c *Client) GoString() string {
	if c == nil {
		return "(*Client)(nil)"
	}
	return fmt.Sprintf("&Client{baseURL: %q, authMode: %d, token: [REDACTED]}", c.baseURL, c.authMode)
}

// setAuth sets the Authorization header on req based on the client's auth mode.
func (c *Client) setAuth(req *http.Request) {
	switch c.authMode {
	case AuthBasic:
		creds := base64.StdEncoding.EncodeToString([]byte(c.email + ":" + c.token))
		req.Header.Set("Authorization", "Basic "+creds)
	default:
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithEmail sets the email address used for Basic authentication.
func WithEmail(email string) ClientOption {
	return func(c *Client) { c.email = email }
}

// WithAuthMode sets the authentication mode (Bearer or Basic).
func WithAuthMode(mode AuthMode) ClientOption {
	return func(c *Client) { c.authMode = mode }
}

// WithBaseURL overrides the default Bitbucket API base URL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) { c.baseURL = baseURL }
}

// WithTimeout sets the HTTP client timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) { c.httpClient.Timeout = timeout }
}

// WithConcurrency sets the maximum number of concurrent requests.
func WithConcurrency(maxVal int64) ClientOption {
	return func(c *Client) {
		if maxVal > 0 {
			c.semaphore = semaphore.NewWeighted(maxVal)
		}
	}
}

// WithHTTPTransport sets a custom HTTP transport on the underlying client.
func WithHTTPTransport(transport http.RoundTripper) ClientOption {
	return func(c *Client) { c.httpClient.Transport = transport }
}

// NewClient creates a new Bitbucket Cloud REST API v2 client.
// The token is required. Use ClientOption functions to configure
// auth mode, base URL, email (for Basic auth), and other settings.
func NewClient(token string, opts ...ClientOption) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: DefaultTimeout},
		baseURL:    DefaultBaseURL,
		token:      token,
		authMode:   AuthBearer,
		semaphore:  semaphore.NewWeighted(MaxConcurrentRequests),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}
