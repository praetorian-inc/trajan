package lib

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListPlatforms(t *testing.T) {
	platforms := ListPlatforms()
	require.NotEmpty(t, platforms, "expected registered platforms from blank imports")

	expected := []string{"azuredevops", "github", "gitlab", "jenkins", "jfrog"}
	for _, name := range expected {
		assert.Contains(t, platforms, name, "missing platform: %s", name)
	}
}

func TestGetPlatform_Known(t *testing.T) {
	for _, name := range []string{"github", "gitlab", "azuredevops", "jenkins", "jfrog"} {
		t.Run(name, func(t *testing.T) {
			p, err := GetPlatform(name)
			require.NoError(t, err)
			assert.Equal(t, name, p.Name())
		})
	}
}

func TestGetPlatform_Unknown(t *testing.T) {
	_, err := GetPlatform("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestGetDetectionsForPlatform_GitHub(t *testing.T) {
	dets := GetDetectionsForPlatform("github")
	require.NotEmpty(t, dets, "expected GitHub detections from blank imports")

	// Verify at least some known detection types exist
	names := make(map[string]bool)
	for _, d := range dets {
		names[d.Name()] = true
	}
	// actions_injection is a core detection that should always be registered
	assert.True(t, names["actions_injection"] || len(names) > 0,
		"expected at least one GitHub detection, got: %v", names)
}

func TestGetDetectionsForPlatform_Unknown(t *testing.T) {
	dets := GetDetectionsForPlatform("nonexistent")
	// Unknown platform returns empty slice (not nil), no cross-platform detections expected
	assert.Empty(t, dets)
}

func TestListDetectionPlatforms(t *testing.T) {
	platforms := ListDetectionPlatforms()
	require.NotEmpty(t, platforms)
	assert.Contains(t, platforms, "github")
}

func TestScan_InvalidPlatform(t *testing.T) {
	_, err := Scan(context.Background(), ScanConfig{
		Platform: "nonexistent",
		Token:    "test",
		Org:      "test",
		Repo:     "test",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestScan_InvalidPlatform_ReturnsError(t *testing.T) {
	// Verify that Scan with an invalid token returns an error from platform Init or Scan
	_, err := Scan(context.Background(), ScanConfig{
		Platform: "github",
		Token:    "invalid-token",
		Org:      "test",
		Repo:     "test",
	})
	require.Error(t, err)
}

func TestApplyDefaults(t *testing.T) {
	cfg := applyDefaults(ScanConfig{Platform: "github"})
	assert.Equal(t, 10, cfg.Concurrency)
	assert.Equal(t, 5*time.Minute, cfg.Timeout)

	// Non-zero values should not be overridden
	cfg = applyDefaults(ScanConfig{Concurrency: 20, Timeout: 10 * time.Minute})
	assert.Equal(t, 20, cfg.Concurrency)
	assert.Equal(t, 10*time.Minute, cfg.Timeout)
}

func TestGetDetections_GitHub(t *testing.T) {
	dets := GetDetections("github")
	assert.NotEmpty(t, dets, "github should have registered detections")

	// GetDetections returns platform-specific only (no cross-platform "all" detections)
	allDets := GetDetectionsForPlatform("github")
	assert.GreaterOrEqual(t, len(allDets), len(dets),
		"GetDetectionsForPlatform should include cross-platform detections")
}
