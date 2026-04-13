package output

import (
	"bytes"
	"testing"

	"github.com/olekukonko/tablewriter"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/stretchr/testify/assert"
)

func TestGetDescription(t *testing.T) {
	tests := []struct {
		vulnType detections.VulnerabilityType
		want     string
	}{
		{detections.VulnUnpinnedAction, "Actions using version tags instead of SHA"},
		{detections.VulnExcessivePermissions, "Missing or excessive permissions block"},
		{detections.VulnActionsInjection, "Potential command injection via context"},
	}

	for _, tt := range tests {
		t.Run(string(tt.vulnType), func(t *testing.T) {
			got := getDescription(tt.vulnType)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		severity detections.Severity
		want     int
	}{
		{detections.SeverityCritical, 0},
		{detections.SeverityHigh, 1},
		{detections.SeverityMedium, 2},
		{detections.SeverityLow, 3},
		{detections.SeverityInfo, 4},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			got := severityRank(tt.severity)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAggregateByRepo(t *testing.T) {
	findings := []detections.Finding{
		{Type: detections.VulnUnpinnedAction, Severity: detections.SeverityHigh, Repository: "owner/repo1"},
		{Type: detections.VulnUnpinnedAction, Severity: detections.SeverityHigh, Repository: "owner/repo1"},
		{Type: detections.VulnActionsInjection, Severity: detections.SeverityHigh, Repository: "owner/repo1"},
		{Type: detections.VulnUnpinnedAction, Severity: detections.SeverityHigh, Repository: "owner/repo2"},
	}

	result := AggregateByRepoWithAllTypes(findings)

	// Check repo1 has 2 aggregated findings (both same severity)
	assert.Len(t, result["owner/repo1"], 2)

	// Check repo2 has 1 aggregated finding
	assert.Len(t, result["owner/repo2"], 1)

	// Check counts for repo1
	for _, agg := range result["owner/repo1"] {
		if agg.Type == detections.VulnUnpinnedAction {
			assert.Equal(t, 2, agg.Count)
		}
		if agg.Type == detections.VulnActionsInjection {
			assert.Equal(t, 1, agg.Count)
		}
	}
}

func TestAggregateByRepo_DifferentSeveritiesSeparateRows(t *testing.T) {
	findings := []detections.Finding{
		{Type: detections.VulnExcessivePermissions, Severity: detections.SeverityHigh, Repository: "owner/repo1"},
		{Type: detections.VulnExcessivePermissions, Severity: detections.SeverityMedium, Repository: "owner/repo1"},
		{Type: detections.VulnExcessivePermissions, Severity: detections.SeverityHigh, Repository: "owner/repo1"},
	}

	result := AggregateByRepoWithAllTypes(findings)

	// Should have 2 rows for excessive_permissions: one High (count=2), one Medium (count=1)
	assert.Len(t, result["owner/repo1"], 2, "Same type with different severities should produce separate rows")

	highCount := 0
	mediumCount := 0
	for _, agg := range result["owner/repo1"] {
		assert.Equal(t, detections.VulnExcessivePermissions, agg.Type)
		if agg.Severity == detections.SeverityHigh {
			highCount = agg.Count
		}
		if agg.Severity == detections.SeverityMedium {
			mediumCount = agg.Count
		}
	}
	assert.Equal(t, 2, highCount, "High severity should have count=2")
	assert.Equal(t, 1, mediumCount, "Medium severity should have count=1")
}

func TestRenderTable(t *testing.T) {
	aggregated := []AggregatedFinding{
		{
			Type:        detections.VulnUnpinnedAction,
			Severity:    detections.SeverityHigh,
			Title:       "unpinned_action",
			Description: "Actions using version tags instead of SHA",
			Count:       69,
		},
		{
			Type:        detections.VulnExcessivePermissions,
			Severity:    detections.SeverityHigh,
			Title:       "excessive_permissions",
			Description: "Missing or excessive permissions block",
			Count:       3,
		},
	}

	var buf bytes.Buffer
	RenderTable(&buf, aggregated)
	output := buf.String()

	// Verify table contains expected headers
	assert.Contains(t, output, "SEVERITY")
	assert.Contains(t, output, "TITLE")
	assert.Contains(t, output, "DESCRIPTION")
	assert.Contains(t, output, "COUNT")

	// Verify table contains expected data
	assert.Contains(t, output, "HIGH")
	assert.Contains(t, output, "unpinned_action")
	assert.Contains(t, output, "69")
}

func TestSeverityColor(t *testing.T) {
	tests := []struct {
		severity detections.Severity
		wantCode int // ANSI color code
	}{
		{detections.SeverityCritical, tablewriter.FgHiRedColor},
		{detections.SeverityHigh, tablewriter.FgRedColor},
		{detections.SeverityMedium, tablewriter.FgYellowColor},
		{detections.SeverityLow, tablewriter.FgCyanColor},
		{detections.SeverityInfo, tablewriter.FgWhiteColor},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			got := severityColor(tt.severity)
			assert.Equal(t, tt.wantCode, got)
		})
	}
}

func TestTypeDescriptionsComplete(t *testing.T) {
	// Every type in AllVulnerabilityTypes should have a description
	for _, vt := range detections.AllVulnerabilityTypes {
		desc := getDescription(vt)
		assert.NotEqual(t, string(vt), desc, "typeDescriptions missing entry for %s", vt)
	}
}
