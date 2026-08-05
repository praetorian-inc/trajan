package detections

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestAllDetectionsRunWithoutPanic(t *testing.T) {
	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "test-pipeline.yml", "test-pipeline.yml", "testproject/testrepo", nil)
	g.AddNode(wf)

	ctx := context.Background()
	dets := registry.GetDetectionsForPlatform(platforms.PlatformAzureDevOps)
	require.NotEmpty(t, dets, "No detections registered for Azure DevOps platform")

	for _, det := range dets {
		t.Run(det.Name(), func(t *testing.T) {
			findings, err := det.Detect(ctx, g)
			assert.NoError(t, err, "Detection %s should not return error", det.Name())
			_ = findings // a minimal graph may legitimately produce none
		})
	}
}

func TestAtLeast6AzureDetections(t *testing.T) {
	dets := registry.GetDetectionsForPlatform(platforms.PlatformAzureDevOps)
	assert.GreaterOrEqual(t, len(dets), 6, "expected at least 6 Azure DevOps detections")
}
