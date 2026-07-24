package gitlab

import (
	"testing"
)

func TestDetectTokenType(t *testing.T) {
	cases := []struct {
		username string
		bot      bool
		want     string
	}{
		{"alice", false, "personal_access_token"},
		// A human-looking name that happens to be a bot but matches no prefix.
		{"ci-runner", true, "bot_token"},
		{"project_1234_bot_abcd", true, "project_access_token"},
		{"group_55_bot_xyz", true, "group_access_token"},
		// Prefix present but not a bot -> still personal (bot flag gates the branch).
		{"project_x", false, "personal_access_token"},
		// project_ prefix without the _bot_ infix is not a project token.
		{"project_nobot", true, "bot_token"},
	}
	for _, c := range cases {
		if got := detectTokenType(c.username, c.bot); got != c.want {
			t.Errorf("detectTokenType(%q, bot=%v) = %q, want %q", c.username, c.bot, got, c.want)
		}
	}
}

func TestResolveTokenPrecedence(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "env-gitlab")
	t.Setenv("GL_TOKEN", "env-gl")

	// explicit wins over environment
	if got, _ := ResolveToken("  explicit  "); got != "explicit" {
		t.Errorf("ResolveToken(explicit) = %q, want explicit (trimmed)", got)
	}
	// GITLAB_TOKEN preferred over GL_TOKEN
	if got, _ := ResolveToken(""); got != "env-gitlab" {
		t.Errorf("ResolveToken(env) = %q, want env-gitlab", got)
	}
}

func TestResolveTokenGLFallbackAndMissing(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "")
	t.Setenv("GL_TOKEN", "env-gl")
	if got, _ := ResolveToken(""); got != "env-gl" {
		t.Errorf("ResolveToken(GL_TOKEN only) = %q, want env-gl", got)
	}

	t.Setenv("GL_TOKEN", "")
	if _, err := ResolveToken(""); err != ErrNoToken {
		t.Errorf("ResolveToken(none) err = %v, want ErrNoToken", err)
	}
}

func TestResolveBaseURL(t *testing.T) {
	if got := ResolveBaseURL(""); got != "https://gitlab.com" {
		t.Errorf("ResolveBaseURL(empty) = %q, want gitlab.com default", got)
	}
	if got := ResolveBaseURL("  https://3.136.153.111 "); got != "https://3.136.153.111" {
		t.Errorf("ResolveBaseURL(self-hosted) = %q, want trimmed URL", got)
	}
}
