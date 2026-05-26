package anonymous

import (
	"context"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/jenkins"
)

func init() {
	registry.RegisterDetection("jenkins", "anonymous-access", func() detections.Detection {
		return New()
	})
}

// Detection detects whether anonymous access is enabled on the Jenkins instance.
type Detection struct {
	base.BaseDetection
}

// New creates a new Jenkins anonymous access detection
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("anonymous-access", "jenkins", detections.SeverityHigh),
	}
}

// RequiresAPI reports that this detection cannot run in --local mode; it
// requires a live Jenkins client to query the running instance.
func (d *Detection) RequiresAPI() bool { return true }

// Detect checks if the Jenkins instance allows anonymous access
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	clientData, ok := g.GetMetadata("jenkins_client")
	if !ok {
		return nil, nil
	}
	client := clientData.(*jenkins.Client)

	whoAmI, err := client.GetWhoAmI(ctx)
	if err != nil {
		return nil, nil
	}

	if !whoAmI.Anonymous {
		return nil, nil
	}

	return []detections.Finding{{
		Type:        detections.VulnJenkinsAnonymousAccess,
		Platform:    "jenkins",
		Class:       detections.ClassConfiguration,
		Severity:    detections.SeverityHigh,
		Confidence:  detections.ConfidenceHigh,
		Repository:  "jenkins-instance",
		Workflow:    "/whoAmI",
		Evidence:    "Jenkins instance allows anonymous access. Unauthenticated users can read Jenkins resources.",
		Remediation: "Disable anonymous access in Jenkins security configuration. Require authentication for all access.",
	}}, nil
}
