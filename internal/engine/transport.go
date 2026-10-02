package engine

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
)

// The instance root reaches every request URL, and an error carrying one reaches _meta.json.
func StripUserinfo(root string) string {
	root = strings.TrimSpace(root)
	u, err := url.Parse(root)
	if err != nil || u.User == nil {
		return root
	}
	u.User = nil
	return u.String()
}

// Cloned, because a bare http.Transport also drops the proxy, HTTP/2 and idle-connection defaults.
func InsecureTransport() http.RoundTripper {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		base = &http.Transport{}
	}
	tr := base.Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return tr
}
