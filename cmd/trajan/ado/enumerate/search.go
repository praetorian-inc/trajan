package enumerate

import (
	"github.com/spf13/cobra"
)

func newSearchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search",
		Short: "Search code, logs, files, and credentials",
		Long: `Trajan - Azure DevOps - Enumerate

Search across code repositories, build logs, and files for patterns and credentials.

Subcommands:
  - code: Search code with custom query
  - creds: Search for credential patterns using built-in regex patterns
  - logs: Search build logs for patterns
  - files: Search for files by filename pattern`,
	}

	cmd.AddCommand(newSearchCodeCmd())
	cmd.AddCommand(newSearchCredsCmd())
	cmd.AddCommand(newSearchLogsCmd())
	cmd.AddCommand(newSearchFilesCmd())

	return cmd
}
