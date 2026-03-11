// Package match provides lightweight CI/CD platform detection and capability
// parameter definitions for Trajan. It is safe to import without pulling in
// heavy platform adapter dependencies.
package match

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
)

// SupportedPlatforms maps URL substrings to Trajan platform identifiers.
// Jenkins and JFrog are self-hosted; they need the explicit "platform" parameter.
var SupportedPlatforms = map[string]string{
	"github.com":    "github",
	"gitlab.com":    "gitlab",
	"dev.azure.com": "azuredevops",
	"bitbucket.org": "bitbucket",
	"circleci.com":  "circleci",
}

// DetectPlatform determines the CI/CD platform from a repository URL.
func DetectPlatform(repoURL string) (string, bool) {
	for domain, platform := range SupportedPlatforms {
		if strings.Contains(repoURL, domain) {
			return platform, true
		}
	}
	return "", false
}

// DefaultParameters returns the standard capability parameters for Trajan.
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

// Repository validates that the input repository is scannable by Trajan,
// applying URL-based platform detection with optional explicit platform override.
func Repository(ctx capability.ExecutionContext, input capmodel.Repository) error {
	if input.URL == "" {
		return fmt.Errorf("repository URL is required")
	}

	// Explicit platform override accepts any URL (needed for self-hosted Jenkins/JFrog)
	if platform, ok := ctx.Parameters.GetString("platform"); ok && platform != "" {
		return nil
	}

	if _, detected := DetectPlatform(input.URL); !detected {
		return fmt.Errorf("unsupported CI/CD platform for URL %q; "+
			"set 'platform' parameter for self-hosted instances (jenkins, jfrog)", input.URL)
	}

	return nil
}
