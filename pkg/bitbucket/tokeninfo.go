package bitbucket

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// TokenType identifies the kind of Bitbucket credential.
type TokenType string

const (
	// TokenTypeWorkspace is a workspace-scoped access token.
	TokenTypeWorkspace TokenType = "workspace_access_token"
	// TokenTypeProject is a project-scoped access token.
	TokenTypeProject TokenType = "project_access_token"
	// TokenTypeRepo is a repository-scoped access token.
	TokenTypeRepo TokenType = "repo_access_token"
	// TokenTypeAPIToken is a user-level API token (ATATT3x prefix).
	TokenTypeAPIToken TokenType = "api_token"
	// TokenTypeUnknown is returned when the credential type header is missing or unrecognized.
	TokenTypeUnknown TokenType = "unknown"
)

// TokenInfo holds metadata about a Bitbucket authentication token,
// derived from the response headers of the /2.0/user endpoint.
type TokenInfo struct {
	Type       TokenType `json:"type"`
	AuthMethod string    `json:"auth_method"` // "bearer" or "basic"
	Scopes     *Scopes   `json:"-"`           // Parsed scopes (excluded from JSON)
	RawScopes  []string  `json:"scopes"`      // Raw scope strings for JSON output
}

// mapCredentialType converts the x-credential-type header value to a TokenType constant.
func mapCredentialType(value string) TokenType {
	switch value {
	case "workspace_access_token":
		return TokenTypeWorkspace
	case "project_access_token":
		return TokenTypeProject
	case "repo_access_token":
		return TokenTypeRepo
	case "api_token":
		return TokenTypeAPIToken
	default:
		return TokenTypeUnknown
	}
}

// GetTokenInfo retrieves token metadata by calling the /2.0/user endpoint
// and inspecting the response headers. For API tokens (Basic auth) the
// endpoint returns 200 with user information. For access tokens (Bearer auth)
// it returns 403, but the headers still contain scope and credential type data.
// A 401 response indicates an invalid token.
func (c *Client) GetTokenInfo(ctx context.Context) (*TokenInfo, *User, *RateLimitInfo, error) {
	resp, err := c.getRawResponse(ctx, "GET", "/2.0/user")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("calling /2.0/user: %w", err)
	}
	defer resp.Body.Close()

	// Parse response headers
	credType := resp.Header.Get("x-credential-type")
	scopeHeader := resp.Header.Get("x-oauth-scopes")

	// Build raw scopes list from header
	var rawScopes []string
	if scopeHeader != "" {
		for _, s := range strings.Split(scopeHeader, ",") {
			trimmed := strings.TrimSpace(s)
			if trimmed != "" {
				rawScopes = append(rawScopes, trimmed)
			}
		}
	}
	if rawScopes == nil {
		rawScopes = []string{}
	}

	// Parse rate limit info (only present when Bitbucket enforces limits)
	var rateLimit *RateLimitInfo
	if limitStr := resp.Header.Get("x-ratelimit-limit"); limitStr != "" {
		rateLimit = &RateLimitInfo{}
		if parsed, parseErr := strconv.Atoi(limitStr); parseErr == nil {
			rateLimit.Limit = parsed
		}
		// x-ratelimit-nearlimit is a numeric threshold, not a boolean
		if nearLimitStr := resp.Header.Get("x-ratelimit-nearlimit"); nearLimitStr != "" {
			if threshold, parseErr := strconv.Atoi(nearLimitStr); parseErr == nil {
				rateLimit.NearLimit = rateLimit.Limit > 0 && threshold > 0
			}
		}
	}

	// Determine scope format based on auth mode
	var format ScopeFormat
	switch c.authMode {
	case AuthBasic:
		format = ScopeFormatFineGrained
	default:
		format = ScopeFormatLegacy
	}

	// Parse scopes
	scopes := ParseScopes(scopeHeader, format)

	// Determine auth method string
	authMethod := "bearer"
	if c.authMode == AuthBasic {
		authMethod = "basic"
	}

	// Handle response based on status code
	switch {
	case resp.StatusCode == http.StatusOK:
		// API token — parse user from body
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, nil, nil, fmt.Errorf("reading response body: %w", readErr)
		}

		var user User
		if jsonErr := json.Unmarshal(body, &user); jsonErr != nil {
			return nil, nil, nil, fmt.Errorf("decoding user: %w", jsonErr)
		}

		info := &TokenInfo{
			Type:       mapCredentialType(credType),
			AuthMethod: authMethod,
			Scopes:     scopes,
			RawScopes:  rawScopes,
		}
		return info, &user, rateLimit, nil

	case resp.StatusCode == http.StatusForbidden:
		// Access token — no user info but headers are valid
		info := &TokenInfo{
			Type:       mapCredentialType(credType),
			AuthMethod: authMethod,
			Scopes:     scopes,
			RawScopes:  rawScopes,
		}
		return info, nil, rateLimit, nil

	case resp.StatusCode == http.StatusUnauthorized:
		if c.authMode == AuthBasic {
			return nil, nil, nil, fmt.Errorf("authentication failed (HTTP 401): verify both email and token are correct")
		}
		return nil, nil, nil, fmt.Errorf("token is invalid (HTTP 401)")

	default:
		return nil, nil, nil, fmt.Errorf("unexpected status %d from /2.0/user", resp.StatusCode)
	}
}
