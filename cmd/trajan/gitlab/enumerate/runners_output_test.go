package enumerate

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gitlabplatform "github.com/praetorian-inc/trajan/pkg/gitlab"
)

func TestOutputRunnersConsole_GroupEnumeration_DeduplicatesSharedRunners(t *testing.T) {
	// This test demonstrates the bug where a runner shared across multiple projects
	// is counted and displayed multiple times when enumerating by group

	// Simulate two projects in a group, both using the same runner #2
	results := []*gitlabplatform.RunnersEnumerateResult{
		{
			// Project 1
			ProjectRunners: []gitlabplatform.RunnerInfo{
				{
					ID:          2,
					Description: "trajan test",
					Online:      true,
					Status:      "online",
					Tags:        []string{},
				},
			},
			Summary: gitlabplatform.RunnerSummary{
				Total:    1,
				Online:   1,
				Offline:  0,
				Project:  1,
				Group:    0,
				Instance: 0,
			},
		},
		{
			// Project 2 - same runner
			ProjectRunners: []gitlabplatform.RunnerInfo{
				{
					ID:          2,
					Description: "trajan test",
					Online:      true,
					Status:      "online",
					Tags:        []string{},
				},
			},
			Summary: gitlabplatform.RunnerSummary{
				Total:    1,
				Online:   1,
				Offline:  0,
				Project:  1,
				Group:    0,
				Instance: 0,
			},
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := outputRunnersConsole(results, false)
	require.NoError(t, err)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// The bug: currently shows "Total: 2 runners" when there's only 1 unique runner
	// Expected: Should show "Total: 1 runners" or indicate which projects share the runner

	// Test that total count reflects unique runners
	assert.Contains(t, output, "Total: 1 runners",
		"Should show 1 unique runner, not 2. Shared runners should be deduplicated.")

	// Test that runner #2 appears only once in the output
	runnerMentions := strings.Count(output, "#2: trajan test")
	assert.Equal(t, 1, runnerMentions,
		"Runner #2 should appear only once in output, not once per project")
}

func TestOutputRunnersConsole_SingleProject(t *testing.T) {
	// Baseline test: single project should work correctly
	results := []*gitlabplatform.RunnersEnumerateResult{
		{
			ProjectRunners: []gitlabplatform.RunnerInfo{
				{
					ID:          1,
					Description: "Project Runner",
					Online:      true,
					Status:      "online",
					Tags:        []string{"docker"},
				},
			},
			Summary: gitlabplatform.RunnerSummary{
				Total:   1,
				Online:  1,
				Offline: 0,
				Project: 1,
			},
		},
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := outputRunnersConsole(results, false)
	require.NoError(t, err)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	assert.Contains(t, output, "Total: 1 runners")
	assert.Contains(t, output, "#1: Project Runner")
}

func TestOutputRunnersConsole_WithHistoricalRunners(t *testing.T) {
	results := []*gitlabplatform.RunnersEnumerateResult{
		{
			ProjectRunners: []gitlabplatform.RunnerInfo{
				{
					ID:          1,
					Description: "live-runner",
					Online:      true,
					Source:      "api",
				},
			},
			HistoricalRunners: []gitlabplatform.RunnerInfo{
				{
					Description: "historical-runner",
					Version:     "18.9.0",
					Executor:    "docker",
					Source:      "logs",
					LastSeenAt:  "2026-02-23T10:00:00Z",
				},
			},
			Summary: gitlabplatform.RunnerSummary{
				Total:   1,
				Online:  1,
				Project: 1,
			},
		},
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := outputRunnersConsole(results, false)
	require.NoError(t, err)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Should show both live and historical sections
	assert.Contains(t, output, "Project Runners (1):")
	assert.Contains(t, output, "live-runner")
	assert.Contains(t, output, "Historical Runners (from logs)")
	assert.Contains(t, output, "historical-runner")
	assert.Contains(t, output, "Version: 18.9.0")
	assert.Contains(t, output, "Last seen:")
}

func TestOutputRunnersConsole_MultipleProjects_HistoricalRunners(t *testing.T) {
	// This test demonstrates Issue #2: historical runners from projects 2-10
	// are silently dropped due to 'break' statement in runners_output.go:100

	results := []*gitlabplatform.RunnersEnumerateResult{
		{
			// Project 1 - has historical runner "old-runner-1"
			ProjectRunners: []gitlabplatform.RunnerInfo{
				{ID: 1, Description: "live-runner-1", Online: true, Source: "api"},
			},
			HistoricalRunners: []gitlabplatform.RunnerInfo{
				{
					Description: "old-runner-1",
					Version:     "17.0.0",
					Executor:    "shell",
					Source:      "logs",
					LastSeenAt:  "2026-01-15T10:00:00Z",
				},
			},
			Summary: gitlabplatform.RunnerSummary{Total: 1, Online: 1, Project: 1},
		},
		{
			// Project 2 - has historical runner "old-runner-2"
			ProjectRunners: []gitlabplatform.RunnerInfo{
				{ID: 2, Description: "live-runner-2", Online: true, Source: "api"},
			},
			HistoricalRunners: []gitlabplatform.RunnerInfo{
				{
					Description: "old-runner-2",
					Version:     "18.5.0",
					Executor:    "docker",
					Source:      "logs",
					LastSeenAt:  "2026-02-10T15:30:00Z",
				},
			},
			Summary: gitlabplatform.RunnerSummary{Total: 1, Online: 1, Project: 1},
		},
		{
			// Project 3 - has historical runner "old-runner-3"
			ProjectRunners: []gitlabplatform.RunnerInfo{
				{ID: 3, Description: "live-runner-3", Online: true, Source: "api"},
			},
			HistoricalRunners: []gitlabplatform.RunnerInfo{
				{
					Description: "old-runner-3",
					Version:     "18.9.0",
					Executor:    "kubernetes",
					Source:      "logs",
					LastSeenAt:  "2026-02-20T08:00:00Z",
				},
			},
			Summary: gitlabplatform.RunnerSummary{Total: 1, Online: 1, Project: 1},
		},
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := outputRunnersConsole(results, false)
	require.NoError(t, err)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// BUG: Currently only "old-runner-1" appears because of break statement
	// FIX: All three historical runners should appear (deduplicated)

	assert.Contains(t, output, "old-runner-1",
		"Historical runner from project 1 should be displayed")
	assert.Contains(t, output, "old-runner-2",
		"Historical runner from project 2 should be displayed (currently dropped due to break)")
	assert.Contains(t, output, "old-runner-3",
		"Historical runner from project 3 should be displayed (currently dropped due to break)")

	// Verify versions are shown for all runners
	assert.Contains(t, output, "17.0.0", "Version from old-runner-1")
	assert.Contains(t, output, "18.5.0", "Version from old-runner-2")
	assert.Contains(t, output, "18.9.0", "Version from old-runner-3")
}
