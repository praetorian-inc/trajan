// Package match provides CI/CD platform detection and capability parameter
// definitions without pulling in the platform adapter dependencies.
package match

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
)

// Jenkins and JFrog are absent: self-hosted URLs are unrecognizable, so they
// arrive through the explicit "platform" parameter instead.
var SupportedPlatforms = map[string]string{
	"github.com":    "github",
	"gitlab.com":    "gitlab",
	"dev.azure.com": "azuredevops",
	"bitbucket.org": "bitbucket",
	"circleci.com":  "circleci",
}

func DetectPlatform(repoURL string) (string, bool) {
	for domain, platform := range SupportedPlatforms {
		if strings.Contains(repoURL, domain) {
			return platform, true
		}
	}
	return "", false
}

func DefaultParameters() []capability.Parameter {
	return []capability.Parameter{
		capability.String("token", "Authentication token for the CI/CD platform API"),
		capability.String("platform",
			"CI/CD platform override (auto-detected from URL if omitted). "+
				"Required for self-hosted platforms: jenkins, jfrog").
			WithOptions("github", "gitlab", "azuredevops", "bitbucket", "jenkins", "jfrog", "circleci"),
		capability.String("base_url",
			"Base URL for self-hosted platforms (e.g., https://jenkins.corp.com). "+
				"Required when platform=jenkins or platform=jfrog"),
	}
}

func Repository(ctx capability.ExecutionContext, input capmodel.Repository) error {
	if input.URL == "" {
		return fmt.Errorf("repository URL is required")
	}

	// A self-hosted instance can live at any URL, so an explicit platform skips detection.
	if platform, ok := ctx.Parameters.GetString("platform"); ok && platform != "" {
		return nil
	}

	if _, detected := DetectPlatform(input.URL); !detected {
		return fmt.Errorf("unsupported CI/CD platform for URL %q; "+
			"set 'platform' parameter for self-hosted instances (jenkins, jfrog)", input.URL)
	}

	return nil
}
