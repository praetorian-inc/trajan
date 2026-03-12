package main

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/stretchr/testify/assert"
)

func TestOutputFindingsConsole_TableFormat(t *testing.T) {
	result := &platforms.ScanResult{
		Repositories: []platforms.Repository{
			{Owner: "owner", Name: "repo"},
		},
		Workflows: map[string][]platforms.Workflow{
			"owner/repo": {{Name: "CI"}},
		},
	}

	findings := []detections.Finding{
		{
			Type:       detections.VulnUnpinnedAction,
			Severity:   detections.SeverityHigh,
			Repository: "owner/repo",
		},
		{
			Type:       detections.VulnUnpinnedAction,
			Severity:   detections.SeverityHigh,
			Repository: "owner/repo",
		},
	}

	// Capture output
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := cmdutil.OutputFindingsConsole(result, findings)
	assert.NoError(t, err)

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	os.Stdout = old
	output := buf.String()

	// Verify table format elements
	assert.Contains(t, output, "=== trajan Scan Results ===")
	assert.Contains(t, output, "Repositories scanned: 1")
	assert.Contains(t, output, "owner/repo")
	assert.Contains(t, output, "SEVERITY")
	assert.Contains(t, output, "unpinned_action")
	// Only types with actual findings are shown
	assert.Contains(t, output, "2") // Count for unpinned_action
}
