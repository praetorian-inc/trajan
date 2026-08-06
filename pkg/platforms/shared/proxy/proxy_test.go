package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTransport_NoProxy(t *testing.T) {
	config := Config{}
	transport, err := NewTransport(config)
	require.NoError(t, err)
	assert.Nil(t, transport)
}

func TestNewTransport_BothProxiesError(t *testing.T) {
	config := Config{
		HTTPProxy:  "http://proxy.example.com:8080",
		SOCKSProxy: "socks5://proxy.example.com:1080",
	}
	transport, err := NewTransport(config)
	assert.Error(t, err)
	assert.Nil(t, transport)
	assert.Contains(t, err.Error(), "cannot use both HTTP and SOCKS proxy simultaneously")
}

func TestNewTransport_InvalidHTTPProxyURL(t *testing.T) {
	config := Config{
		HTTPProxy: "://invalid-url",
	}
	transport, err := NewTransport(config)
	assert.Error(t, err)
	assert.Nil(t, transport)
	assert.Contains(t, err.Error(), "parsing HTTP proxy URL")
}

// The negative case is the one that matters: certificate verification must stay
// on for every configuration that did not ask for it.
func TestNewTransport_TLSVerificationPolicy(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		insecure bool
	}{
		{"explicit skip", Config{SkipTLSVerify: true}, true},
		{"http proxy implies skip", Config{HTTPProxy: "http://proxy.example.com:8080"}, true},
		{"http proxy with explicit skip", Config{HTTPProxy: "http://proxy.example.com:8080", SkipTLSVerify: true}, true},
		{"socks proxy keeps verification", Config{SOCKSProxy: "socks5://proxy.example.com:1080"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport, err := NewTransport(tt.config)
			require.NoError(t, err)

			tr, ok := transport.(*http.Transport)
			require.True(t, ok)

			if !tt.insecure {
				assert.Nil(t, tr.TLSClientConfig)
				return
			}
			require.NotNil(t, tr.TLSClientConfig)
			assert.True(t, tr.TLSClientConfig.InsecureSkipVerify)
		})
	}
}

func TestNewTransport_HTTPProxyRouting(t *testing.T) {
	transport, err := NewTransport(Config{HTTPProxy: "http://proxy.example.com:8080"})
	require.NoError(t, err)

	tr, ok := transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, tr.Proxy)

	proxyURL, err := tr.Proxy(httptest.NewRequest(http.MethodGet, "https://api.github.com/user", nil))
	require.NoError(t, err)
	require.NotNil(t, proxyURL)
	assert.Equal(t, "http://proxy.example.com:8080", proxyURL.String())

	socks, err := NewTransport(Config{SOCKSProxy: "socks5://proxy.example.com:1080"})
	require.NoError(t, err)
	assert.Nil(t, socks.(*http.Transport).Proxy)
}

func TestNewTransport_SOCKSProxyAuth(t *testing.T) {
	addr, creds := startSOCKSAuthProbe(t)

	transport, err := NewTransport(Config{SOCKSProxy: "socks5://scanner:s3cret@" + addr})
	require.NoError(t, err)

	tr, ok := transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, tr.DialContext)

	// The probe hangs up after the credential exchange, so the dial itself is
	// expected to fail; the wire bytes are the assertion.
	_, _ = tr.DialContext(t.Context(), "tcp", "api.github.com:443")

	select {
	case got := <-creds:
		assert.Equal(t, "scanner", got[0])
		assert.Equal(t, "s3cret", got[1])
	case <-time.After(5 * time.Second):
		t.Fatal("SOCKS5 handshake never reached username/password negotiation")
	}
}

// startSOCKSAuthProbe answers a SOCKS5 greeting by selecting username/password
// auth, then reports the RFC 1929 credentials the dialer put on the wire.
func startSOCKSAuthProbe(t *testing.T) (string, <-chan [2]string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	creds := make(chan [2]string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		greeting := make([]byte, 2)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, make([]byte, greeting[1])); err != nil {
			return
		}
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			return
		}

		head := make([]byte, 2)
		if _, err := io.ReadFull(conn, head); err != nil {
			return
		}
		user := make([]byte, head[1])
		if _, err := io.ReadFull(conn, user); err != nil {
			return
		}
		plen := make([]byte, 1)
		if _, err := io.ReadFull(conn, plen); err != nil {
			return
		}
		pass := make([]byte, plen[0])
		if _, err := io.ReadFull(conn, pass); err != nil {
			return
		}
		creds <- [2]string{string(user), string(pass)}
	}()

	return ln.Addr().String(), creds
}
