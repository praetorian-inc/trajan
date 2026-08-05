// Package detections registers the Azure DevOps detections.
package detections

import (
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections/agentsecurity"
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections/ai"
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections/pipelineaccesscontrol"
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections/pipelineinjection"
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections/secretsexposure"
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections/serviceconnections"
)
