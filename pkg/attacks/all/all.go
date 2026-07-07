// Package all imports all attack plugins to trigger init() registration
package all

import (
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/attacks/agentexec"
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/attacks/aiprobe"
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/attacks/extractconnections"
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/attacks/extractsecurefiles"
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/attacks/persistence"
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/attacks/pipelineinjection"
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/attacks/prattack"
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/attacks/privesc"
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/attacks/secretsdump"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/attacks/aiprobe"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/attacks/runnerexec"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/attacks/secretsdump"
)
