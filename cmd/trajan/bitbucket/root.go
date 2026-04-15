package bitbucket

import (
	"github.com/spf13/cobra"
)

var BitbucketCmd = &cobra.Command{
	Use:   "bitbucket",
	Short: "Trajan - Bitbucket",
	Long:  `Trajan - Bitbucket`,
}

func init() {
	// Persistent flags available to all bitbucket subcommands
	BitbucketCmd.PersistentFlags().String("email", "", "email address for API token auth (or set BITBUCKET_EMAIL/BB_EMAIL)")
	BitbucketCmd.PersistentFlags().String("workspace", "", "Bitbucket workspace slug (or set BITBUCKET_WORKSPACE)")

	BitbucketCmd.AddCommand(enumerateCmd)
}
