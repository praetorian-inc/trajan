// Package all imports all platform implementations to trigger their init() registration
package all

import (
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops"
	_ "github.com/praetorian-inc/trajan/pkg/bitbucket"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab"
	_ "github.com/praetorian-inc/trajan/pkg/jenkins"
	_ "github.com/praetorian-inc/trajan/pkg/jfrog"
)
