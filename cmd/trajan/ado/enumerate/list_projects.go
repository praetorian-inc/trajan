package enumerate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/pkg/output"
)

func newProjectsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "projects",
		Short: "List all accessible projects",
		Long: `Trajan - Azure DevOps - Enumerate

List all projects accessible to the authenticated token.
Shows project name, ID, visibility, state, and description.
Requires --org flag.`,
		RunE: runListProjects,
	}

	return cmd
}

func runListProjects(cmd *cobra.Command, args []string) error {
	switch enumPlatform {
	case "azuredevops":
		return runListProjectsAzureDevOps(cmd, args)
	case "github", "gitlab":
		return fmt.Errorf("platform %s not yet supported for this command", enumPlatform)
	default:
		return fmt.Errorf("unsupported platform: %s", enumPlatform)
	}
}

func runListProjectsAzureDevOps(cmd *cobra.Command, args []string) error {
	if enumOrg == "" {
		return fmt.Errorf("--org is required for Azure DevOps")
	}

	ctx := context.Background()
	orgURL := fmt.Sprintf("https://dev.azure.com/%s", enumOrg)
	client, err := NewEnumerateClient(orgURL, GetTokenForPlatform("azuredevops"))
	if err != nil {
		return err
	}

	projects, err := client.ListProjects(ctx)
	if err != nil {
		return err
	}

	switch enumOutput {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(projects)

	case "csv":
		headers := []string{"Name", "ID", "Visibility", "State", "Description"}
		rows := make([][]string, len(projects))
		for i, proj := range projects {
			visibility := proj.Visibility
			if visibility == "" {
				visibility = "unknown"
			}
			description := proj.Description
			if description == "" {
				description = "-"
			}
			rows[i] = []string{proj.Name, proj.ID, visibility, proj.State, description}
		}
		return output.RenderCSV(os.Stdout, headers, rows)

	default: // console
		if len(projects) == 0 {
			fmt.Println("No projects found")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tID\tVISIBILITY\tSTATE\tDESCRIPTION")
		for _, proj := range projects {
			visibility := proj.Visibility
			if visibility == "" {
				visibility = "unknown"
			}
			description := proj.Description
			if description == "" {
				description = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", proj.Name, proj.ID, visibility, proj.State, description)
		}
		w.Flush()

		fmt.Printf("\nTotal: %d projects\n", len(projects))
		return nil
	}
}
