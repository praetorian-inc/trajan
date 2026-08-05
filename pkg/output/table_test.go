package output

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/detections"
)

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
