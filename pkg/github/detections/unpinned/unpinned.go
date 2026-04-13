package unpinned

import (
	"context"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/detections/shared"
	sharedUnpinned "github.com/praetorian-inc/trajan/pkg/detections/shared/unpinned"
)

func init() {
	registry.RegisterDetection("github", "unpinned-action", func() detections.Detection {
		return New()
	})
}

// Detection detects unpinned GitHub Actions
type Detection struct {
	base.BaseDetection
	detector *sharedUnpinned.Detector
}

// New creates a new unpinned action detection
func New() *Detection {
	resolver := shared.NewGitHubUsesResolver()
	validator := shared.NewGitHubPinValidator()

	return &Detection{
		BaseDetection: base.NewBaseDetection("unpinned-action", "github", detections.SeverityLow),
		detector:      sharedUnpinned.New(resolver, validator),
	}
}

// Detect finds unpinned actions in the workflow graph
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	// Get all workflows (no trigger filtering - ALL workflows)
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)

	for _, wfNode := range workflows {
		wf := wfNode.(*graph.WorkflowNode)
		detCtx := shared.NewDetectionContext("github", wf)

		// DFS through all steps
		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			if node.Type() == graph.NodeTypeStep {
				step := node.(*graph.StepNode)

				if finding := d.detector.Detect(step, detCtx); finding != nil {
					// Enhance with detailed evidence
					enhanced := *finding
					enhanced.Workflow = wf.Path // Use path for matching

					// Add line range for the unpinned action
					if step.Line > 0 {
						enhanced.Details = &detections.FindingDetails{
							LineRanges: []detections.LineRange{
								{
									Start: step.Line,
									End:   step.Line,
									Label: "unpinned action",
								},
							},
						}
					}

					findings = append(findings, enhanced)
				}
			}
			return true
		})
	}

	return findings, nil
}
