package bitbucket

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/praetorian-inc/trajan/pkg/platforms/shared/proxy"
)

type Platform struct {
	client *Client
	config platforms.Config
}

func NewPlatform() *Platform {
	return &Platform{}
}

func (p *Platform) Name() string {
	return "bitbucket"
}

func (p *Platform) Init(ctx context.Context, config platforms.Config) error {
	p.config = config

	var opts []ClientOption
	if config.Timeout > 0 {
		opts = append(opts, WithTimeout(config.Timeout))
	}
	if config.Concurrency > 0 {
		opts = append(opts, WithConcurrency(int64(config.Concurrency)))
	}

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

	token := config.Token
	if strings.HasPrefix(token, "ATATT3x") {
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

func (p *Platform) Client() *Client {
	return p.client
}

func (p *Platform) Scan(ctx context.Context, target platforms.Target) (*platforms.ScanResult, error) {
	return nil, fmt.Errorf("bitbucket scan not yet implemented")
}

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

var _ platforms.Platform = (*Platform)(nil)
