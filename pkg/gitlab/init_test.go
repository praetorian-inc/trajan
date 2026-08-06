package gitlab

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/internal/registry"
)

func TestRegistration(t *testing.T) {
	platform, err := registry.GetPlatform("gitlab")
	require.NoError(t, err, "gitlab platform should be registered")
	require.NotNil(t, platform)

	assert.Equal(t, "gitlab", platform.Name())

	_, ok := platform.(*Platform)
	assert.True(t, ok, "registered platform should be *gitlab.Platform")
}
