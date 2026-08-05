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

type TokenType string

const (
	TokenTypeWorkspace TokenType = "workspace_access_token"
	TokenTypeProject   TokenType = "project_access_token"
	TokenTypeRepo      TokenType = "repo_access_token"
	// ATATT3x prefix.
	TokenTypeAPIToken TokenType = "api_token"
	// The x-credential-type header was missing or unrecognized.
	TokenTypeUnknown TokenType = "unknown"
)

// Derived from the /2.0/user response headers.
type TokenInfo struct {
	Type       TokenType `json:"type"`
	AuthMethod string    `json:"auth_method"` // "bearer" or "basic"
	Scopes     *Scopes   `json:"-"`
	RawScopes  []string  `json:"scopes"`
}

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

// Basic auth (API token) gets 200 with a user body; Bearer auth (access token)
// gets 403 whose headers still carry the scope and credential-type data.
// A 401 means the token itself is invalid.
func (c *Client) GetTokenInfo(ctx context.Context) (*TokenInfo, *User, *RateLimitInfo, error) {
	resp, err := c.getRawResponse(ctx, "GET", "/2.0/user")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("calling /2.0/user: %w", err)
	}
	defer resp.Body.Close()

	credType := resp.Header.Get("x-credential-type")
	scopeHeader := resp.Header.Get("x-oauth-scopes")

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

	// The rate-limit headers appear only while Bitbucket is enforcing a limit.
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

	var format ScopeFormat
	switch c.authMode {
	case AuthBasic:
		format = ScopeFormatFineGrained
	default:
		format = ScopeFormatLegacy
	}

	scopes := ParseScopes(scopeHeader, format)

	authMethod := "bearer"
	if c.authMode == AuthBasic {
		authMethod = "basic"
	}

	switch resp.StatusCode {
	case http.StatusOK:
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

	case http.StatusForbidden:
		info := &TokenInfo{
			Type:       mapCredentialType(credType),
			AuthMethod: authMethod,
			Scopes:     scopes,
			RawScopes:  rawScopes,
		}
		return info, nil, rateLimit, nil

	case http.StatusUnauthorized:
		if c.authMode == AuthBasic {
			return nil, nil, nil, fmt.Errorf("authentication failed (HTTP 401): verify both email and token are correct")
		}
		return nil, nil, nil, fmt.Errorf("token is invalid (HTTP 401)")

	default:
		return nil, nil, nil, fmt.Errorf("unexpected status %d from /2.0/user", resp.StatusCode)
	}
}
