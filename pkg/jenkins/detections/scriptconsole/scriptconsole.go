package scriptconsole

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/jenkins"
)

func init() {
	registry.RegisterDetection("jenkins", "script-console", func() detections.Detection {
		return New()
	})
}

// Detection detects whether the Jenkins script console is accessible.
// An accessible script console allows arbitrary Groovy/OS command execution.
type Detection struct {
	base.BaseDetection
}

// New creates a new Jenkins script console detection
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("script-console", "jenkins", detections.SeverityCritical),
	}
}

// RequiresAPI reports that this detection cannot run in --local mode; it
// requires a live Jenkins client to query the running instance.
func (d *Detection) RequiresAPI() bool { return true }

// Detect checks if the Jenkins script console is accessible
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	clientData, ok := g.GetMetadata("jenkins_client")
	if !ok {
		return nil, nil
	}
	client, ok := clientData.(*jenkins.Client)
	if !ok {
		return nil, nil
	}

	accessible, statusCode, err := client.CheckScriptConsole(ctx)
	if err != nil {
		return nil, nil // Can't determine — skip silently
	}

	if !accessible {
		return nil, nil
	}

	return []detections.Finding{{
		Type:        detections.VulnJenkinsScriptConsole,
		Platform:    "jenkins",
		Class:       detections.ClassConfiguration,
		Severity:    detections.SeverityCritical,
		Confidence:  detections.ConfidenceHigh,
		Repository:  "jenkins-instance",
		Workflow:    "/script",
		Evidence:    fmt.Sprintf("Jenkins script console is accessible (HTTP %d). This allows arbitrary Groovy/OS command execution.", statusCode),
		Remediation: "Restrict script console access to administrators only. Ensure authentication is required.",
	}}, nil
}
