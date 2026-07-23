package ado

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
)

var AdoCmd = &cobra.Command{
	Use:   "ado",
	Short: "Trajan - Azure DevOps",
	Long:  "Trajan - Azure DevOps",
}

func init() {
	AdoCmd.PersistentFlags().String("azure-bearer-token", "", "Azure Entra ID bearer token (or set AZURE_BEARER_TOKEN)")

	AdoCmd.AddCommand(enumerateCmd)
	AdoCmd.AddCommand(scanCmd)
	AdoCmd.AddCommand(attackCmd)
	AdoCmd.AddCommand(retrieveCmd)
	AdoCmd.AddCommand(newCollectCmd())
	AdoCmd.AddCommand(newNormalizeCmd())
}

func getToken(cmd *cobra.Command) string {
	return cmdutil.GetTokenForPlatform(cmd, "azuredevops")
}

func getBearerToken(cmd *cobra.Command) string {
	if t, err := cmd.Flags().GetString("azure-bearer-token"); err == nil && t != "" {
		return t
	}
	return os.Getenv("AZURE_BEARER_TOKEN")
}
