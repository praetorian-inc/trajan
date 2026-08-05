// Package detections registers the Jenkins detections.
package detections

import (
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/detections/agents"
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/detections/anonymous"
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/detections/credentials"
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/detections/csrf"
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/detections/injection"
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/detections/permissions"
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/detections/scriptconsole"
)
