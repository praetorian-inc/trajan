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

// Detection detects whether CSRF protection is disabled on the Jenkins instance.
type Detection struct {
	base.BaseDetection
}

// New creates a new Jenkins CSRF disabled detection
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("csrf-disabled", "jenkins", detections.SeverityMedium),
	}
}

// RequiresAPI reports that this detection cannot run in --local mode; it
// requires a live Jenkins client to query the running instance.
func (d *Detection) RequiresAPI() bool { return true }

// Detect checks if Jenkins CSRF protection (crumb issuer) is disabled
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
