// Package all imports all platform implementations to trigger their init() registration
// Import this package to make all platforms available at runtime
package all

import (
	// Import all platform implementations to trigger init() registration
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops"
	_ "github.com/praetorian-inc/trajan/pkg/bitbucket"
	_ "github.com/praetorian-inc/trajan/pkg/github"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab"
	_ "github.com/praetorian-inc/trajan/pkg/jenkins"
	_ "github.com/praetorian-inc/trajan/pkg/jfrog"
)
