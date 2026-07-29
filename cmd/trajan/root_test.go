package main

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// A local flag that reuses a shorthand already claimed by an inherited persistent
// flag makes cobra panic the first time it resolves the command — so the crash
// only ever surfaces at runtime, on the one subcommand nobody ran. Walk the tree
// and let cobra's own merge be the oracle.
func TestCommandTreeHasNoShorthandCollisions(t *testing.T) {
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		assert.NotPanics(t, func() { c.InheritedFlags() }, c.CommandPath())
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
}

func TestProxyFlag(t *testing.T) {
	// Verify the --proxy flag exists and defaults to empty string
	cmd := rootCmd
	flag := cmd.PersistentFlags().Lookup("proxy")
	assert.NotNil(t, flag, "--proxy flag should exist")
	assert.Equal(t, "", flag.DefValue, "--proxy should default to empty string")
}

func TestSOCKSProxyFlag(t *testing.T) {
	// Verify the --socks-proxy flag exists and defaults to empty string
	cmd := rootCmd
	flag := cmd.PersistentFlags().Lookup("socks-proxy")
	assert.NotNil(t, flag, "--socks-proxy flag should exist")
	assert.Equal(t, "", flag.DefValue, "--socks-proxy should default to empty string")
}
