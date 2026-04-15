package bitbucket

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/praetorian-inc/trajan/pkg/platforms/shared/proxy"
)

// Platform implements the platforms.Platform interface for Bitbucket Cloud.
type Platform struct {
	client *Client
	config platforms.Config
}

// NewPlatform creates a new Bitbucket platform adapter.
func NewPlatform() *Platform {
	return &Platform{}
}

// Name returns the platform identifier.
func (p *Platform) Name() string {
	return "bitbucket"
}

// Init initializes the platform with configuration.
func (p *Platform) Init(ctx context.Context, config platforms.Config) error {
	p.config = config

	// Build client options
	var opts []ClientOption
	if config.Timeout > 0 {
		opts = append(opts, WithTimeout(config.Timeout))
	}
	if config.Concurrency > 0 {
		opts = append(opts, WithConcurrency(int64(config.Concurrency)))
	}

	// Resolve proxy transport
	transport := config.HTTPTransport
	if transport == nil {
		t, err := proxy.NewTransport(proxy.Config{
			HTTPProxy:  config.HTTPProxy,
			SOCKSProxy: config.SOCKSProxy,
		})
		if err != nil {
			return fmt.Errorf("configuring proxy: %w", err)
		}
		transport = t
	}
	if transport != nil {
		opts = append(opts, WithHTTPTransport(transport))
	}

	// Detect auth mode from token prefix
	token := config.Token
	if strings.HasPrefix(token, "ATATT3x") {
		// API token — requires email for Basic auth
		email := ""
		if config.Bitbucket != nil {
			email = config.Bitbucket.Email
		}
		if email == "" {
			return fmt.Errorf("--email is required for API token auth (use --email or set BITBUCKET_EMAIL/BB_EMAIL env var)")
		}
		opts = append(opts, WithAuthMode(AuthBasic), WithEmail(email))
	}
	// ATCTT3x or unknown prefix → default AuthBearer (set by NewClient)

	p.client = NewClient(token, opts...)
	return nil
}

// Client returns the underlying Bitbucket client.
func (p *Platform) Client() *Client {
	return p.client
}

// Scan retrieves repositories and workflows from the target.
// This is a stub — full implementation will land in a future task.
func (p *Platform) Scan(ctx context.Context, target platforms.Target) (*platforms.ScanResult, error) {
	return nil, fmt.Errorf("bitbucket scan not yet implemented")
}

// EnumerateToken retrieves metadata about the authenticated token,
// including its type, scopes, associated user (if any), and rate limit info.
func (p *Platform) EnumerateToken(ctx context.Context) (*TokenEnumerateResult, error) {
	result := &TokenEnumerateResult{
		Errors: make([]string, 0),
	}

	tokenInfo, user, rateLimit, err := p.client.GetTokenInfo(ctx)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("getting token info: %v", err))
		return result, nil // Return partial result
	}

	result.TokenInfo = tokenInfo
	result.User = user
	result.RateLimit = rateLimit

	return result, nil
}

// Ensure Platform implements the interface.
var _ platforms.Platform = (*Platform)(nil)
