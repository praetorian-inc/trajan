package github

import (
	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
)

var GitHubCmd = &cobra.Command{
	Use:   "github",
	Short: "Trajan - GitHub",
	Long:  `Trajan - GitHub`,
}

func init() {
	GitHubCmd.AddCommand(enumerateCmd)
	GitHubCmd.AddCommand(scanCmd)
	GitHubCmd.AddCommand(attackCmd)
	GitHubCmd.AddCommand(retrieveCmd)
	GitHubCmd.AddCommand(searchCmd)

	// GitHub-specific flags
	GitHubCmd.PersistentFlags().SortFlags = false
	GitHubCmd.PersistentFlags().String("url", "", "base URL for GitHub Enterprise Server (e.g., https://github.example.com/api/v3)")
}

func getToken(cmd *cobra.Command) string {
	return cmdutil.GetTokenForPlatform(cmd, "github")
}

// getURL returns the GitHub base URL from the --url persistent flag.
// Returns empty string when unset, in which case the default github.com URL is used.
func getURL(cmd *cobra.Command) string {
	url, _ := cmd.Flags().GetString("url")
	return url
}
