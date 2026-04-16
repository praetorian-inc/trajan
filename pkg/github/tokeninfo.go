package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// TokenType represents the type of GitHub authentication token
type TokenType string

const (
	TokenTypeClassic     TokenType = "classic"
	TokenTypeFineGrained TokenType = "fine_grained"
	TokenTypeUnknown     TokenType = "unknown"
)

// TokenInfo contains metadata about the authenticated GitHub token
type TokenInfo struct {
	User       string     `json:"user"`
	Name       string     `json:"name,omitempty"`
	Type       TokenType  `json:"type"`
	Scopes     []string   `json:"scopes"`
	Expiration *time.Time `json:"expiration,omitempty"`
}

// Response header constants
const (
	headerOAuthScopes     = "X-OAuth-Scopes"
	headerTokenExpiration = "Github-Authentication-Token-Expiration"
)

// parseScopes extracts scopes from the X-OAuth-Scopes header
func parseScopes(header string) []string {
	if header == "" {
		return []string{}
	}

	parts := strings.Split(header, ",")
	scopes := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			scopes = append(scopes, s)
		}
	}
	return scopes
}

// parseExpiration parses the token expiration header
// Supports both formats:
//   - "2024-01-15 09:30:00 UTC" (named timezone)
//   - "2024-01-15 09:30:00 -0500" (numeric offset)
func parseExpiration(header string) *time.Time {
	if header == "" {
		return nil
	}

	// Try named timezone format first
	t, err := time.Parse("2006-01-02 15:04:05 MST", header)
	if err == nil {
		return &t
	}

	// Try numeric offset format
	t, err = time.Parse("2006-01-02 15:04:05 -0700", header)
	if err == nil {
		return &t
	}

	return nil
}

// detectTokenType determines token type from available metadata
// Priority:
// 1. Header-based detection (most reliable)
//   - Classic PATs return X-OAuth-Scopes header
//   - Fine-grained PATs return Github-Authentication-Token-Expiration header
//
// 2. Token prefix detection (fallback for WASM/CORS environments)
//   - Classic PATs: prefix "ghp_" (40 chars total)
//   - Fine-grained PATs: prefix "github_pat_" (93 chars total)
func detectTokenType(scopes []string, hasExpiration bool, token string) TokenType {
	// Priority 1: Header-based detection
	if len(scopes) > 0 {
		return TokenTypeClassic
	}
	if hasExpiration {
		return TokenTypeFineGrained
	}

	// Priority 2: Token prefix detection (CORS/WASM fallback)
	if strings.HasPrefix(token, "ghp_") {
		return TokenTypeClassic
	}
	if strings.HasPrefix(token, "github_pat_") {
		return TokenTypeFineGrained
	}

	return TokenTypeUnknown
}

// GetTokenInfo retrieves metadata about the authenticated token
func (c *Client) GetTokenInfo(ctx context.Context) (*TokenInfo, error) {
	resp, err := c.do(ctx, http.MethodGet, "/user", nil)
	if err != nil {
		return nil, fmt.Errorf("getting token info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token validation failed (%d): %s", resp.StatusCode, body)
	}

	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "text/html") {
		return nil, fmt.Errorf("server returned HTML instead of JSON (Content-Type: %s) — GitHub Enterprise Server may be in maintenance/replication mode, or the --url may be incorrect", ct)
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("decoding user response: %w", err)
	}

	scopes := parseScopes(resp.Header.Get(headerOAuthScopes))
	expiration := parseExpiration(resp.Header.Get(headerTokenExpiration))

	return &TokenInfo{
		User:       user.Login,
		Name:       user.Name,
		Type:       detectTokenType(scopes, expiration != nil, c.token),
		Scopes:     scopes,
		Expiration: expiration,
	}, nil
}
