package enumerate

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/pkg/azuredevops"
)

var (
	enumPlatform    string
	enumToken       string
	enumBearerToken string
	enumOrg         string
	enumURL         string // For self-hosted instances
	enumOutput      string
	enumProject     string
)

func NewEnumerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate token permissions and accessible resources",
		Long: `Trajan - Azure DevOps - Enumerate

Enumerate the permissions and accessible resources for an API token.

This command supports subcommands for different enumeration operations:
  - token: Validate PAT and enumerate accessible resources
  - projects, repos, pipelines, users, groups, etc.: List accessible resources
  - search: Search code and credentials`,
	}

	cmd.PersistentFlags().StringVar(&enumPlatform, "platform", "azuredevops", "Platform to enumerate (azuredevops, github, gitlab)")
	cmd.PersistentFlags().StringVar(&enumToken, "token", "", "API token (or use env var: AZURE_DEVOPS_PAT, GH_TOKEN, GL_TOKEN)")
	cmd.PersistentFlags().StringVar(&enumBearerToken, "azure-bearer-token", "", "Azure Entra ID bearer token (or set AZURE_BEARER_TOKEN)")
	cmd.PersistentFlags().StringVar(&enumOrg, "org", "", "Organization name (required for azuredevops)")
	cmd.PersistentFlags().StringVar(&enumURL, "url", "", "Custom instance URL (for self-hosted GitLab, etc.)")
	cmd.PersistentFlags().StringVarP(&enumOutput, "output", "o", "console", "Output format (console, json, csv)")
	cmd.PersistentFlags().StringVar(&enumProject, "project", "", "Project name/ID (optional, for scoping to single project)")

	cmd.AddCommand(newTokenCmd())
	cmd.AddCommand(newProjectsCmd())
	cmd.AddCommand(newReposCmd())
	cmd.AddCommand(newPipelinesCmd())
	cmd.AddCommand(newVariableGroupsCmd())
	cmd.AddCommand(newConnectionsCmd())
	cmd.AddCommand(newSecureFilesCmd())
	cmd.AddCommand(newAgentPoolsCmd())
	cmd.AddCommand(newUsersCmd())
	cmd.AddCommand(newGroupsCmd())
	cmd.AddCommand(newBranchPoliciesCmd())
	cmd.AddCommand(newSearchCmd())
	cmd.AddCommand(newForkSecurityCmd())
	cmd.AddCommand(newAttackPathsCmd())

	return cmd
}

func GetTokenForPlatform(platform string) string {
	if enumToken != "" {
		return enumToken
	}

	envVars := map[string][]string{
		"github":      {"GH_TOKEN", "GITHUB_TOKEN"},
		"gitlab":      {"GITLAB_TOKEN", "GL_TOKEN"},
		"bitbucket":   {"BITBUCKET_TOKEN", "BITBUCKET_APP_PASSWORD"},
		"azuredevops": {"AZURE_DEVOPS_PAT", "AZDO_PAT"},
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

func GetBearerToken() string {
	if enumBearerToken != "" {
		return enumBearerToken
	}
	return os.Getenv("AZURE_BEARER_TOKEN")
}

// A bearer token takes precedence over a PAT when both are set.
func NewEnumerateClient(orgURL, pat string) (*azuredevops.Client, error) {
	bt := GetBearerToken()
	if pat == "" && bt == "" {
		return nil, fmt.Errorf("no token provided (use --token, --azure-bearer-token, or set AZURE_DEVOPS_PAT/AZURE_BEARER_TOKEN)")
	}
	var opts []azuredevops.ClientOption
	if bt != "" {
		opts = append(opts, azuredevops.WithBearerToken(bt))
	}
	return azuredevops.NewClient(orgURL, pat, opts...), nil
}

func formatSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}
