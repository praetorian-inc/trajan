package cmdutil

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// GetToken reads the token from root persistent flags.
func GetToken(cmd *cobra.Command) string {
	if t, err := cmd.Root().PersistentFlags().GetString("token"); err == nil && t != "" {
		return t
	}
	return ""
}

// GetTokenForPlatform retrieves authentication token for the specified platform.
// Checks CLI flag first, then platform-specific environment variables.
func GetTokenForPlatform(cmd *cobra.Command, platform string) string {
	if t := GetToken(cmd); t != "" {
		return t
	}

	envVars := map[string][]string{
		"github":      {"GH_TOKEN", "GITHUB_TOKEN"},
		"gitlab":      {"GITLAB_TOKEN", "GL_TOKEN"},
		"azuredevops": {"AZURE_DEVOPS_PAT", "AZDO_PAT"},
		"jfrog":       {"JFROG_TOKEN"},
		"jenkins":     {"JENKINS_TOKEN", "JENKINS_PASSWORD"},
		"bitbucket":   {"BITBUCKET_TOKEN", "BB_TOKEN"},
	}

	if vars, ok := envVars[platform]; ok {
		for _, env := range vars {
			if t := os.Getenv(env); t != "" {
				return t
			}
		}
	}

	return ""
}

// GetVerbose reads the verbose flag from root persistent flags.
func GetVerbose(cmd *cobra.Command) bool {
	v, _ := cmd.Root().PersistentFlags().GetBool("verbose")
	return v
}

// GetOutput reads the output format flag from root persistent flags.
func GetOutput(cmd *cobra.Command) string {
	o, _ := cmd.Root().PersistentFlags().GetString("output")
	return o
}

// GetHTTPProxy reads the HTTP proxy flag from root persistent flags.
func GetHTTPProxy(cmd *cobra.Command) string {
	p, _ := cmd.Root().PersistentFlags().GetString("proxy")
	return p
}

// GetSOCKSProxy reads the SOCKS proxy flag from root persistent flags.
func GetSOCKSProxy(cmd *cobra.Command) string {
	p, _ := cmd.Root().PersistentFlags().GetString("socks-proxy")
	return p
}

// GetUsernameForPlatform retrieves username for the specified platform.
func GetUsernameForPlatform(cmd *cobra.Command, platform string) string {
	if u, err := cmd.Root().PersistentFlags().GetString("username"); err == nil && u != "" {
		return u
	}

	envVars := map[string][]string{
		"jenkins": {"JENKINS_USERNAME", "JENKINS_USER"},
	}

	if vars, ok := envVars[platform]; ok {
		for _, env := range vars {
			if u := os.Getenv(env); u != "" {
				return u
			}
		}
	}

	return ""
}

// GetEmailForPlatform retrieves email for the specified platform.
// Checks the --email flag first, then platform-specific environment variables.
func GetEmailForPlatform(cmd *cobra.Command, platform string) string {
	if e, err := cmd.Flags().GetString("email"); err == nil && e != "" {
		return e
	}

	envVars := map[string][]string{
		"bitbucket": {"BITBUCKET_EMAIL", "BB_EMAIL"},
	}

	if vars, ok := envVars[platform]; ok {
		for _, env := range vars {
			if e := os.Getenv(env); e != "" {
				return e
			}
		}
	}

	return ""
}

// ApplyProxyFlags reads proxy flags from the command and sets them on the config.
func ApplyProxyFlags(cmd *cobra.Command, config *platforms.Config) {
	config.HTTPProxy = GetHTTPProxy(cmd)
	config.SOCKSProxy = GetSOCKSProxy(cmd)
}
