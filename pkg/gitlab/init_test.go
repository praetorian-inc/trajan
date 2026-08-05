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
