package enumerate

import (
	"context"
	"testing"

	"github.com/praetorian-inc/trajan/pkg/github"
)

func TestOutputTokenConsole(t *testing.T) {
	tests := []struct {
		name   string
		result *github.TokenEnumerateResult
	}{
		{
			name: "classic PAT with scopes",
			result: &github.TokenEnumerateResult{
				TokenInfo: &github.TokenInfo{
					User:   "testuser",
					Name:   "Test User",
					Type:   github.TokenTypeClassic,
					Scopes: []string{"repo", "workflow", "read:org"},
				},
				Organizations: []github.OrganizationInfo{
					{Name: "test-org"},
					{Name: "another-org", Role: "admin"},
				},
				RateLimit: &github.RateLimitInfo{
					Limit:     5000,
					Remaining: 4500,
					Used:      500,
				},
			},
		},
		{
			name: "fine-grained PAT",
			result: &github.TokenEnumerateResult{
				TokenInfo: &github.TokenInfo{
					User: "testuser",
					Type: github.TokenTypeFineGrained,
				},
			},
		},
		{
			name: "with errors",
			result: &github.TokenEnumerateResult{
				TokenInfo: &github.TokenInfo{
					User: "testuser",
					Type: github.TokenTypeClassic,
				},
				Errors: []error{
					context.DeadlineExceeded,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call outputTokenConsole to ensure it doesn't panic
			err := outputTokenConsole(tt.result)

			if err != nil {
				t.Errorf("outputTokenConsole() returned error: %v", err)
			}

			// Basic validation - just ensure it doesn't panic
			// Full output validation would require mocking stdout
		})
	}
}

func TestFormatTokenType(t *testing.T) {
	tests := []struct {
		name      string
		tokenType github.TokenType
		want      string
	}{
		{"classic", github.TokenTypeClassic, "classic personal access token"},
		{"fine-grained", github.TokenTypeFineGrained, "fine-grained personal access token"},
		{"unknown", github.TokenTypeUnknown, "unknown"},
		{
			name:      "github app",
			tokenType: github.TokenTypeGitHubApp,
			want:      "GitHub App installation token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatTokenType(tt.tokenType)
			if got != tt.want {
				t.Errorf("formatTokenType() = %v, want %v", got, tt.want)
			}
		})
	}
}
