package all

// Import statements ensure init functions run in each detection.
// When a new detection is added, this list should be updated.

import (
	// Azure DevOps detections
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections"

	// GitLab detections
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections"

	// Jenkins detections
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/detections"
)
