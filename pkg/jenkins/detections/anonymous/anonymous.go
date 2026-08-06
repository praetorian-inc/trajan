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

type Detection struct {
	base.BaseDetection
}

func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("anonymous-access", "jenkins", detections.SeverityHigh),
	}
}

// Needs a live Jenkins client, so it cannot run in --local mode.
func (d *Detection) RequiresAPI() bool { return true }

func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	clientData, ok := g.GetMetadata("jenkins_client")
	if !ok {
		return nil, nil
	}
	client, ok := clientData.(*jenkins.Client)
	if !ok {
		return nil, nil
	}

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
