package csrf

import (
	"context"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/jenkins"
)

func init() {
	registry.RegisterDetection("jenkins", "csrf-disabled", func() detections.Detection {
		return New()
	})
}

type Detection struct {
	base.BaseDetection
}

func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("csrf-disabled", "jenkins", detections.SeverityMedium),
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

	serverInfo, err := client.GetServerInfo(ctx)
	if err != nil {
		return nil, nil
	}

	if serverInfo.UseCrumbs {
		return nil, nil // CSRF is enabled, no issue
	}

	return []detections.Finding{{
		Type:        detections.VulnJenkinsCSRFDisabled,
		Platform:    "jenkins",
		Class:       detections.ClassConfiguration,
		Severity:    detections.SeverityMedium,
		Confidence:  detections.ConfidenceHigh,
		Repository:  "jenkins-instance",
		Workflow:    "/crumbIssuer",
		Evidence:    "Jenkins CSRF protection (crumb issuer) is disabled. This makes the instance vulnerable to cross-site request forgery attacks.",
		Remediation: "Enable CSRF protection in Jenkins global security configuration.",
	}}, nil
}
