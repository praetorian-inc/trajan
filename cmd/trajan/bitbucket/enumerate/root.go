package enumerate

import (
	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
)

var enumerateCmd = &cobra.Command{
	Use:   "enumerate",
	Short: "Enumerate Bitbucket resources and attack surface",
	Long: `Trajan - Bitbucket - Enumerate

Enumerate and discover Bitbucket resources accessible to the authenticated token.

The enumerate command provides detailed reconnaissance capabilities including:
  - Token validation and scope analysis
  - User identity and account status`,
}

func init() {
	enumerateCmd.AddCommand(tokenCmd)
}

func NewEnumerateCmd() *cobra.Command {
	return enumerateCmd
}

func getToken(cmd *cobra.Command) string {
	return cmdutil.GetTokenForPlatform(cmd, "bitbucket")
}

func getEmail(cmd *cobra.Command) string {
	return cmdutil.GetEmailForPlatform(cmd, "bitbucket")
}
