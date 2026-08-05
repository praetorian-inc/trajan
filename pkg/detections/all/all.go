package all

// Blank imports: each package registers its detections in init.

import (
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections"

	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections"

	_ "github.com/praetorian-inc/trajan/pkg/jenkins/detections"
)
