// Package proxy provides shared HTTP/SOCKS5 proxy transport configuration.
package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

type Config struct {
	// URL such as "http://proxy:8080". Setting it also disables TLS verification.
	HTTPProxy string

	// URL such as "socks5://user:pass@proxy:1080"; credentials in the URL are used.
	SOCKSProxy string

	// Forced on when HTTPProxy is set.
	SkipTLSVerify bool
}

func (c Config) HasProxy() bool { return c.HTTPProxy != "" || c.SOCKSProxy != "" }

// Returns (nil, nil) when neither a proxy nor SkipTLSVerify is configured.
func NewTransport(config Config) (http.RoundTripper, error) {
	if !config.HasProxy() && !config.SkipTLSVerify {
		return nil, nil
	}

	if config.HTTPProxy != "" && config.SOCKSProxy != "" {
		return nil, fmt.Errorf("cannot use both HTTP and SOCKS proxy simultaneously")
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if config.SkipTLSVerify || config.HTTPProxy != "" {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // Intentional for proxy testing/Burp interception
		}
	}

	if config.HTTPProxy != "" {
		proxyURL, err := url.Parse(config.HTTPProxy)
		if err != nil {
			return nil, fmt.Errorf("parsing HTTP proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	if config.SOCKSProxy != "" {
		proxyURL, err := url.Parse(config.SOCKSProxy)
		if err != nil {
			return nil, fmt.Errorf("parsing SOCKS proxy URL: %w", err)
		}

		auth := &proxy.Auth{}
		if proxyURL.User != nil {
			auth.User = proxyURL.User.Username()
			auth.Password, _ = proxyURL.User.Password()
		}

		dialer, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("creating SOCKS5 dialer: %w", err)
		}

		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		}
	}

	return transport, nil
}
