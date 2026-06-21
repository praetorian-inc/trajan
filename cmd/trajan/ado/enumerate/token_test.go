package enumerate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenCommandExists(t *testing.T) {
	cmd := newTokenCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "token", cmd.Use)
}

func TestTokenCommandHasDetailedFlag(t *testing.T) {
	cmd := newTokenCmd()
	flag := cmd.Flags().Lookup("detailed")
	require.NotNil(t, flag, "--detailed flag should exist")
	assert.Equal(t, "bool", flag.Value.Type())
}

func TestTokenCommandHasNoSubcommands(t *testing.T) {
	cmd := newTokenCmd()
	assert.Empty(t, cmd.Commands(), "token should have no subcommands")
}

func TestTokenCommandRequiresOrg(t *testing.T) {
	t.Skip("Integration test - requires live ADO instance")
}
