package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
)

func TestGetTokenForPlatform_GitLab(t *testing.T) {
	oldGitLabToken := os.Getenv("GITLAB_TOKEN")
	oldGLToken := os.Getenv("GL_TOKEN")
	oldToken := token
	defer func() {
		os.Setenv("GITLAB_TOKEN", oldGitLabToken)
		os.Setenv("GL_TOKEN", oldGLToken)
		token = oldToken
	}()

	os.Unsetenv("GITLAB_TOKEN")
	os.Unsetenv("GL_TOKEN")
	token = ""

	// Create a minimal cobra command with --token flag for testing
	cmd := rootCmd
	os.Setenv("GITLAB_TOKEN", "test-gitlab-token")
	result := cmdutil.GetTokenForPlatform(cmd, "gitlab")
	assert.Equal(t, "test-gitlab-token", result)

	os.Unsetenv("GITLAB_TOKEN")
	os.Setenv("GL_TOKEN", "test-gl-token")
	result = cmdutil.GetTokenForPlatform(cmd, "gitlab")
	assert.Equal(t, "test-gl-token", result)

	token = "cli-token"
	result = cmdutil.GetTokenForPlatform(cmd, "gitlab")
	assert.Equal(t, "cli-token", result)
	token = ""
}
