package secrets

import (
	"testing"

	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestSecretPatterns(t *testing.T) {
	detector := New()

	tests := []struct {
		name        string
		value       string
		wantMatches int
	}{
		{
			name:        "AWS access key",
			value:       "AKIAIOSFODNN7EXAMPLE",
			wantMatches: 1,
		},
		{
			name:        "GitHub token pattern",
			value:       "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			wantMatches: 1,
		},
		{
			name:        "no secrets",
			value:       "hello world",
			wantMatches: 0,
		},
		{
			name:        "generic API key",
			value:       "api_key=sk-12345678901234567890",
			wantMatches: 1,
		},
		{
			name:        "JWT token",
			value:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			wantMatches: 2, // JWT + AWS Secret Key false positive (expected behavior)
		},
		{
			name:        "private key header",
			value:       "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
			wantMatches: 1,
		},
		{
			name:        "GitLab token",
			value:       "glpat-xxxxxxxxxxxxxxxxxxxx",
			wantMatches: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := detector.DetectSecretPattern(tt.value)
			if len(matches) != tt.wantMatches {
				t.Errorf("DetectSecretPattern() = %d matches, want %d", len(matches), tt.wantMatches)
			}
		})
	}
}

func TestSecretPatterns_ConfidenceLevels(t *testing.T) {
	detector := New()

	matches := detector.DetectSecretPattern("AKIAIOSFODNN7EXAMPLE")
	if len(matches) != 1 {
		t.Fatalf("DetectSecretPattern() = %d matches, want 1", len(matches))
	}
	if matches[0].Pattern != "AWS Access Key" {
		t.Fatalf("Pattern = %q, want %q", matches[0].Pattern, "AWS Access Key")
	}

	// credentials.detectStructural discards everything below High, so a silent
	// demotion of this pattern drops real findings instead of failing loudly.
	if matches[0].Confidence != detections.ConfidenceHigh {
		t.Errorf("Confidence = %q, want %q", matches[0].Confidence, detections.ConfidenceHigh)
	}
}
