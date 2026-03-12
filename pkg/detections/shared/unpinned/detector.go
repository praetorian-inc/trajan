// modules/trajan/pkg/detections/shared/unpinned/detector.go
// Package unpinned provides cross-platform unpinned dependency detection
package unpinned

import (
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/shared"
)

// Detector detects unpinned dependencies across platforms
type Detector struct {
	resolver  shared.UsesResolver
	validator shared.PinValidator
}

// New creates a new unpinned dependency detector
func New(resolver shared.UsesResolver, validator shared.PinValidator) *Detector {
	return &Detector{
		resolver:  resolver,
		validator: validator,
	}
}

// Detect checks if a step uses an unpinned dependency
func (d *Detector) Detect(step *graph.StepNode, ctx *shared.DetectionContext) *detections.Finding {
	if step.Uses == "" {
		return nil
	}

	ref, err := d.resolver.Parse(step.Uses)
	if err != nil {
		// Can't parse, skip
		return nil
	}

	// Skip local actions and certain docker images
	if ref.IsLocal {
		return nil
	}

	// Skip docker images (platform-specific handling)
	if ref.Type == shared.UsesTypeDocker {
		return nil
	}

	// Check if pinned
	if d.validator.IsPinned(ref) {
		return nil
	}

	// Generate remediation message
	remediation := "Pin dependency to full commit SHA. "
	if ref.Owner != "" && ref.Repo != "" {
		switch ctx.Platform {
		case "github":
			remediation += "Visit https://github.com/" + ref.Owner + "/" + ref.Repo + " to find the commit SHA."
		case "gitlab":
			remediation += "Visit https://gitlab.com/" + ref.Owner + "/" + ref.Repo + " to find the commit SHA."
		default:
			remediation += "Find the commit SHA for this version in the source repository."
		}
	}

	return &detections.Finding{
		Type:        detections.VulnUnpinnedAction,
		Platform:    ctx.Platform,
		Class:       detections.GetVulnerabilityClass(detections.VulnUnpinnedAction),
		Severity:    detections.SeverityLow,
		Confidence:  detections.ConfidenceHigh,
		Complexity:  detections.ComplexityZeroClick,
		Repository:  ctx.Repository,
		Workflow:    ctx.Workflow.Name,
		Step:        step.Name,
		Line:        step.Line,
		Evidence:    step.Uses,
		Remediation: remediation,
	}
}

// Ensure Detector implements shared.Detector
var _ shared.Detector = (*Detector)(nil)
