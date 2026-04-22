package local

import "github.com/spf13/cobra"

// LocalCmd is the root command for local filesystem scanning.
var LocalCmd = &cobra.Command{
	Use:   "local",
	Short: "Trajan - Local",
	Long:  "Trajan - Scan a local filesystem path for CI/CD workflow vulnerabilities",
}

func init() {
	LocalCmd.AddCommand(scanCmd)
}
