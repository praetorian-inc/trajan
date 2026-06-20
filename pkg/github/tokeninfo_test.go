package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseScopes(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected []string
	}{
		{
			name:     "empty header",
			header:   "",
			expected: []string{},
		},
		{
			name:     "single scope",
			header:   "repo",
			expected: []string{"repo"},
		},
		{
			name:     "multiple scopes",
			header:   "repo, workflow, read:org",
			expected: []string{"repo", "workflow", "read:org"},
		},
		{
			name:     "scopes with extra whitespace",
			header:   "  repo ,  workflow  , read:org  ",
			expected: []string{"repo", "workflow", "read:org"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseScopes(tt.header)
			if len(result) != len(tt.expected) {
				t.Errorf("parseScopes() len = %d, want %d", len(result), len(tt.expected))
				return
			}
			for i, s := range result {
				if s != tt.expected[i] {
					t.Errorf("parseScopes()[%d] = %q, want %q", i, s, tt.expected[i])
				}
			}
		})
	}
}

func TestParseExpiration(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		wantNil  bool
		wantYear int // simplified check
	}{
		{
			name:    "empty header",
			header:  "",
			wantNil: true,
		},
		{
			name:     "valid expiration",
			header:   "2024-01-15 09:30:00 UTC",
			wantNil:  false,
			wantYear: 2024,
		},
		{
			name:    "invalid format",
			header:  "not-a-date",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseExpiration(tt.header)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parseExpiration() = %v, want nil", result)
				}
				return
			}
			if result == nil {
				t.Error("parseExpiration() = nil, want non-nil")
				return
			}
			if result.Year() != tt.wantYear {
				t.Errorf("parseExpiration().Year() = %d, want %d", result.Year(), tt.wantYear)
			}
		})
	}
}

func TestDetectTokenType(t *testing.T) {
	tests := []struct {
		name          string
		scopes        []string
		hasExpiration bool
		token         string
		expected      TokenType
	}{
		{
			name:          "classic PAT with scopes",
			scopes:        []string{"repo", "workflow"},
			hasExpiration: false,
			token:         "ghp_test123",
			expected:      TokenTypeClassic,
		},
		{
			name:          "classic PAT with scopes and expiration",
			scopes:        []string{"repo"},
			hasExpiration: true,
			token:         "ghp_test456",
			expected:      TokenTypeClassic,
		},
		{
			name:          "fine-grained PAT (no scopes, has expiration)",
			scopes:        []string{},
			hasExpiration: true,
			token:         "github_pat_test789",
			expected:      TokenTypeFineGrained,
		},
		{
			name:          "unknown (no scopes, no expiration)",
			scopes:        []string{},
			hasExpiration: false,
			token:         "unknown_token",
			expected:      TokenTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectTokenType(tt.scopes, tt.hasExpiration, tt.token)
			if result != tt.expected {
				t.Errorf("detectTokenType() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestClient_GetTokenInfo(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		responseBody   string
		oauthScopes    string
		tokenExpiry    string
		wantErr        bool
		wantUser       string
		wantType       TokenType
		wantScopeCount int
	}{
		{
			name:           "classic PAT",
			statusCode:     http.StatusOK,
			responseBody:   `{"login": "testuser", "name": "Test User"}`,
			oauthScopes:    "repo, workflow",
			tokenExpiry:    "",
			wantErr:        false,
			wantUser:       "testuser",
			wantType:       TokenTypeClassic,
			wantScopeCount: 2,
		},
		{
			name:           "fine-grained PAT",
			statusCode:     http.StatusOK,
			responseBody:   `{"login": "fguser", "name": "FG User"}`,
			oauthScopes:    "",
			tokenExpiry:    "2024-12-31 23:59:59 UTC",
			wantErr:        false,
			wantUser:       "fguser",
			wantType:       TokenTypeFineGrained,
			wantScopeCount: 0,
		},
		{
			name:         "invalid token",
			statusCode:   http.StatusUnauthorized,
			responseBody: `{"message": "Bad credentials"}`,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/user" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				if tt.oauthScopes != "" {
					w.Header().Set("X-OAuth-Scopes", tt.oauthScopes)
				}
				if tt.tokenExpiry != "" {
					w.Header().Set("Github-Authentication-Token-Expiration", tt.tokenExpiry)
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-token")
			info, err := client.GetTokenInfo(context.Background())

			if tt.wantErr {
				if err == nil {
					t.Error("GetTokenInfo() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("GetTokenInfo() unexpected error: %v", err)
				return
			}

			if info.User != tt.wantUser {
				t.Errorf("GetTokenInfo().User = %q, want %q", info.User, tt.wantUser)
			}
			if info.Type != tt.wantType {
				t.Errorf("GetTokenInfo().Type = %q, want %q", info.Type, tt.wantType)
			}
			if len(info.Scopes) != tt.wantScopeCount {
				t.Errorf("GetTokenInfo().Scopes len = %d, want %d", len(info.Scopes), tt.wantScopeCount)
			}
		})
	}
}

func TestIsAppToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{"installation opaque", "ghs_AbCdEf0123456789", true},
		{"installation jwt-shaped", "ghs_eyJhbG.payload.sig", true},
		{"classic PAT", "ghp_AbCdEf0123456789", false},
		{"fine-grained PAT", "github_pat_11ABC", false},
		{"user-to-server", "ghu_AbCdEf0123456789", false},
		{"oauth", "gho_AbCdEf0123456789", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAppToken(tt.token); got != tt.want {
				t.Errorf("IsAppToken(%q) = %v, want %v", tt.token, got, tt.want)
			}
		})
	}
}

func TestDetectTokenType_GitHubApp(t *testing.T) {
	// No scopes, no expiration, ghs_ prefix => github_app
	if got := detectTokenType(nil, false, "ghs_AbCdEf0123456789"); got != TokenTypeGitHubApp {
		t.Errorf("detectTokenType(ghs_) = %q, want %q", got, TokenTypeGitHubApp)
	}
	// ghu_ must NOT be classified as app
	if got := detectTokenType(nil, false, "ghu_AbCdEf0123456789"); got == TokenTypeGitHubApp {
		t.Errorf("detectTokenType(ghu_) = %q, must not be github_app", got)
	}
}

func TestClient_GetTokenInfo_GitHubApp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// App tokens must validate via /installation/repositories, NOT /user.
		if r.URL.Path != "/installation/repositories" {
			t.Errorf("app token hit %s, want /installation/repositories", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"total_count":0,"repository_selection":"selected","repositories":[]}`)
	}))
	defer server.Close()

	client := NewClient(server.URL, "ghs_test")
	info, err := client.GetTokenInfo(context.Background())
	if err != nil {
		t.Fatalf("GetTokenInfo() error = %v", err)
	}
	if info.Type != TokenTypeGitHubApp {
		t.Errorf("Type = %q, want %q", info.Type, TokenTypeGitHubApp)
	}
	if info.User != "" {
		t.Errorf("User = %q, want empty for app token", info.User)
	}
}
