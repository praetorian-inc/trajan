package jenkins

import (
	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
)

var JenkinsCmd = &cobra.Command{
	Use:   "jenkins",
	Short: "Trajan - Jenkins",
	Long:  `Trajan - Jenkins`,
}

func init() {
	JenkinsCmd.PersistentFlags().SortFlags = false
	JenkinsCmd.PersistentFlags().String("username", "", "Jenkins username for Basic auth (env: JENKINS_USERNAME)")
	JenkinsCmd.PersistentFlags().String("password", "", "Jenkins password or API token for Basic auth (env: JENKINS_PASSWORD)")
	JenkinsCmd.AddCommand(enumerateCmd)
	JenkinsCmd.AddCommand(scanCmd)
}

func getToken(cmd *cobra.Command) string {
	if p, err := cmd.Flags().GetString("password"); err == nil && p != "" {
		return p
	}
	return cmdutil.GetTokenForPlatform(cmd, "jenkins")
}

func getUsername(cmd *cobra.Command) string {
	if u, err := cmd.Flags().GetString("username"); err == nil && u != "" {
		return u
	}
	return cmdutil.GetUsernameForPlatform(cmd, "jenkins")
}
