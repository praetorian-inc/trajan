package gitlab

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/internal/registry"
)

// TestRegistration verifies that gitlab platform is registered
func TestRegistration(t *testing.T) {
	// Get platform from registry
	platform, err := registry.GetPlatform("gitlab")
	require.NoError(t, err, "gitlab platform should be registered")
	require.NotNil(t, platform)

	// Verify it's the correct type
	assert.Equal(t, "gitlab", platform.Name())

	// Verify it's a GitLab Platform
	_, ok := platform.(*Platform)
	assert.True(t, ok, "registered platform should be *gitlab.Platform")
}

// TestListPlatforms verifies gitlab appears in platform list
func TestListPlatforms(t *testing.T) {
	platforms := registry.ListPlatforms()

	// Should contain gitlab
	assert.Contains(t, platforms, "gitlab", "gitlab should be in platform list")
	// Note: Other platforms (like github, bitbucket) may or may not be loaded depending on imports
	assert.NotEmpty(t, platforms, "platform list should not be empty")
}
