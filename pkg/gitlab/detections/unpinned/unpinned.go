package unpinned

import (
	"context"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/gitlab/detections/common"
)

func init() {
	registry.RegisterDetection("gitlab", "unpinned-include", func() detections.Detection {
		return New()
	})
}

// Detection detects unpinned GitLab CI includes
type Detection struct {
	base.BaseDetection
}

// New creates a new unpinned include detection
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("unpinned-include", "gitlab", detections.SeverityLow),
	}
}

// Detect finds unpinned includes in the workflow graph
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	// Get all workflows
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)

	for _, wfNode := range workflows {
		wf := wfNode.(*graph.WorkflowNode)

		// Only process root workflows to avoid duplicates
		if !common.IsRootWorkflow(g, wf) {
			continue
		}

		// Analyze each include
		for _, inc := range wf.Includes {
			if finding := d.checkInclude(wf, inc); finding != nil {
				findings = append(findings, *finding)
			}
		}
	}

	return findings, nil
}

// checkInclude checks if an include is properly pinned
func (d *Detection) checkInclude(wf *graph.WorkflowNode, inc graph.Include) *detections.Finding {
	switch inc.Type {
	case "project":
		// Project includes must be pinned to a commit SHA
		if !isCommitSHA(inc.Ref) {
			var evidence string
			if inc.Ref == "" {
				evidence = "Unpinned project include: " + inc.Project + inc.Path + " (no ref specified)"
			} else {
				evidence = "Unpinned project include: " + inc.Project + inc.Path + " (ref: " + inc.Ref + " is not a commit SHA)"
			}

			metadata := make(map[string]interface{})
			metadata["includeType"] = "project"
			metadata["project"] = inc.Project
			metadata["file"] = inc.Path
			metadata["ref"] = inc.Ref

			// Synthesize line range for include block (typically at top of file)
			lineRanges := []detections.LineRange{
				{
					Start: 1,
					End:   5, // Include blocks typically at lines 1-5
					Label: "unpinned include",
				},
			}

			return &detections.Finding{
				Type:        detections.VulnUnpinnedAction,
				Platform:    "gitlab",
				Class:       detections.GetVulnerabilityClass(detections.VulnUnpinnedAction),
				Severity:    detections.SeverityLow,
				Confidence:  detections.ConfidenceHigh,
				Complexity:  detections.ComplexityZeroClick,
				Repository:  wf.RepoSlug,
				Workflow:    wf.Path,
				Line:        1, // Includes typically at line 1
				Evidence:    evidence,
				Remediation: "Pin project includes to a full commit SHA to prevent supply chain attacks. Visit " + inc.Project + " to find the commit SHA for the current version.",
				Details: &detections.FindingDetails{
					LineRanges: lineRanges,
					Metadata:   metadata,
				},
			}
		}

	case "remote":
		// Remote includes are always risky (no pinning mechanism in GitLab for remote)
		metadata := make(map[string]interface{})
		metadata["includeType"] = "remote"
		metadata["remoteURL"] = inc.Remote

		lineRanges := []detections.LineRange{
			{
				Start: 1,
				End:   5,
				Label: "remote include",
			},
		}

		return &detections.Finding{
			Type:        detections.VulnUnpinnedAction,
			Platform:    "gitlab",
			Class:       detections.GetVulnerabilityClass(detections.VulnUnpinnedAction),
			Severity:    detections.SeverityLow,
			Confidence:  detections.ConfidenceHigh,
			Complexity:  detections.ComplexityZeroClick,
			Repository:  wf.RepoSlug,
			Workflow:    wf.Path,
			Line:        1,
			Evidence:    "Remote include from untrusted source: " + inc.Remote,
			Remediation: "Avoid remote includes. Use project or local includes instead. Remote includes cannot be pinned and are vulnerable to supply chain attacks.",
			Details: &detections.FindingDetails{
				LineRanges: lineRanges,
				Metadata:   metadata,
			},
		}

	case "local":
		// Local includes are version-controlled with the repository - no finding
		return nil

	case "template":
		// GitLab-managed templates are trusted - no finding
		return nil
	}

	return nil
}

// isCommitSHA checks if a ref is a valid 40-character hex commit SHA
func isCommitSHA(ref string) bool {
	if len(ref) != 40 {
		return false
	}
	for _, c := range ref {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
