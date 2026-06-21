// pkg/gitlab/attacks/secretsdump/secretsdump_test.go
package secretsdump

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestCanAttack(t *testing.T) {
	plugin := New()

	// PPE doesn't require vulnerabilities - just permissions
	// So CanAttack should always return true
	findings := []detections.Finding{}

	assert.True(t, plugin.CanAttack(findings))
}
