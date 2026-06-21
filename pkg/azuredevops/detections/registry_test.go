package detections

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/platforms"

	// Import all detections to trigger init() registration
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections/pipelineinjection"
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections/serviceconnections"
)

func TestAzureDevOpsDetections_Registration(t *testing.T) {
	detections := registry.GetDetections(platforms.PlatformAzureDevOps)

	require.NotEmpty(t, detections, "Expected Azure DevOps detections to be registered under 'azuredevops' platform")
	assert.GreaterOrEqual(t, len(detections), 2, "Expected at least 2 Azure DevOps detections (pipeline-injection, service-connections)")

	detectionNames := make(map[string]bool)
	for _, d := range detections {
		detectionNames[d.Name()] = true
	}

	assert.True(t, detectionNames["pipeline-injection"], "pipeline-injection detection should be registered")
	assert.True(t, detectionNames["service-connections"], "service-connections detection should be registered")
}

func TestAzureDevOpsDetections_PlatformField(t *testing.T) {
	detections := registry.GetDetections(platforms.PlatformAzureDevOps)
	require.NotEmpty(t, detections)

	for _, d := range detections {
		assert.Equal(t, platforms.PlatformAzureDevOps, d.Platform(),
			"Detection %s should report platform as 'azuredevops'", d.Name())
	}
}
