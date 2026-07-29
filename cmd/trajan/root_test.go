package main

import (
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/internal/ui"
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

// Guards rootCmd.TraverseChildren: without it, an unknown flag ahead of the
// command name swallows the command and cobra reports `unknown command`.
func TestUnknownFlagNamesItself(t *testing.T) {
	for _, args := range [][]string{
		{"--bogus", "github", "scan"},
		{"--token", "x", "--bogus", "github", "scan"},
		{"github", "--bogus", "scan"},
		{"github", "scan", "--bogus"},
		{"--bogus"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			err := executeArgs(t, args...)
			assert.ErrorContains(t, err, "unknown flag: --bogus")
		})
	}
}

// TraverseChildren changes when each level's flags are parsed; its known weak
// spot is a flag placed after a positional argument.
func TestFlagPlacementStillParses(t *testing.T) {
	for _, args := range [][]string{
		{"github", "scan", "--path", "/nonexistent"},
		{"github", "scan", "--path", "/nonexistent", "--no-color"},
		{"--no-color", "github", "scan", "--path", "/nonexistent"},
		{"github", "--output-dir", "/nonexistent", "scan", "--path", "/nonexistent"},
		{"github", "report", "--format", "md", "--path", "/nonexistent"},
		{"github", "report", "--path", "/nonexistent", "--format", "md"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			// The run fails on the missing dir; only parsing is under test.
			if err := executeArgs(t, args...); err != nil {
				assert.NotContains(t, err.Error(), "unknown flag")
				assert.NotContains(t, err.Error(), "unknown command")
			}
		})
	}
}

// rootCmd is a singleton and OnInitialize rebinds the global logger once
// parsing succeeds, so both are put back before the next case.
func executeArgs(t *testing.T, args ...string) error {
	t.Helper()
	t.Cleanup(func() {
		debug, verbose, noColor = false, false, false
		ui.Init(ui.Human, false)
	})
	rootCmd.SetArgs(args)
	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(io.Discard)
	return rootCmd.Execute()
}
