package local_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/internal/registry"
	_ "github.com/praetorian-inc/trajan/pkg/local"
)

// TestInit_RegistersLocalPlatform verifies that importing pkg/local triggers its
// init() function, which registers the "local" platform with the global registry.
func TestInit_RegistersLocalPlatform(t *testing.T) {
	p, err := registry.GetPlatform("local")
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "local", p.Name())
}
