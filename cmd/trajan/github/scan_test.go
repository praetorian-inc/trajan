package github

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScanCmd_LocalWithoutPath_ReturnsError tests the flag-validation guard
// that rejects --local without --path. It drives runScan (the cobra RunE)
// directly to avoid cobra's root-command dispatch (scanCmd has a parent via
// init() and calling Execute() on a child routes to the root).
func TestScanCmd_LocalWithoutPath_ReturnsError(t *testing.T) {
	// Reset package-level flag vars to zero values before the test and restore
	// them afterward so other tests in the package are not affected.
	orig_scanLocal := scanLocal
	orig_scanPath := scanPath
	t.Cleanup(func() {
		scanLocal = orig_scanLocal
		scanPath = orig_scanPath
	})

	scanLocal = true
	scanPath = ""

	err := runScan(scanCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--path is required when --local is set")
}
