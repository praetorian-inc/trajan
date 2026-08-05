package bitbucket

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/sync/semaphore"
)

const (
	DefaultBaseURL        = "https://api.bitbucket.org"
	DefaultTimeout        = 30 * time.Second
	MaxConcurrentRequests = 50
)

type AuthMode int

const (
	// AuthBearer uses "Authorization: Bearer {token}" (access tokens with ATCTT3x prefix).
	AuthBearer AuthMode = iota
	// AuthBasic uses "Authorization: Basic base64(email:token)" (API tokens with ATATT3x prefix).
	AuthBasic
)

type Client struct {
	httpClient *http.Client
	baseURL    string
	token      string
	email      string // Non-empty only for AuthBasic
	authMode   AuthMode
	semaphore  *semaphore.Weighted
}

// Exists to keep the token out of logs.
func (c *Client) String() string {
	if c == nil {
		return "Client{nil}"
	}
	return fmt.Sprintf("Client{baseURL: %q, authMode: %d, token: [REDACTED]}", c.baseURL, c.authMode)
}

// Exists to keep the token out of %#v output.
func (c *Client) GoString() string {
	if c == nil {
		return "(*Client)(nil)"
	}
	return fmt.Sprintf("&Client{baseURL: %q, authMode: %d, token: [REDACTED]}", c.baseURL, c.authMode)
}

func (c *Client) setAuth(req *http.Request) {
	switch c.authMode {
	case AuthBasic:
		creds := base64.StdEncoding.EncodeToString([]byte(c.email + ":" + c.token))
		req.Header.Set("Authorization", "Basic "+creds)
	default:
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

type ClientOption func(*Client)

func WithEmail(email string) ClientOption {
	return func(c *Client) { c.email = email }
}

func WithAuthMode(mode AuthMode) ClientOption {
	return func(c *Client) { c.authMode = mode }
}

func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) { c.httpClient.Timeout = timeout }
}

func WithConcurrency(maxVal int64) ClientOption {
	return func(c *Client) {
		if maxVal > 0 {
			c.semaphore = semaphore.NewWeighted(maxVal)
		}
	}
}

func WithHTTPTransport(transport http.RoundTripper) ClientOption {
	return func(c *Client) { c.httpClient.Transport = transport }
}

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
