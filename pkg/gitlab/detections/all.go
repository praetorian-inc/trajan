// Package detections registers the GitLab CI detections.
package detections

import (
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/ai"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/includes"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/injection"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/mrcheckout"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/mrsecrets"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/permissions" // token exposure
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/selfhostedrunner"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/unpinned"
)
