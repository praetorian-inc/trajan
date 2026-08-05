package enumerate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/output"
)

var scanYAML bool

func newConnectionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connections",
		Short: "List service connections in a project",
		Long: `Trajan - Azure DevOps - Enumerate

List service connections configured in an Azure DevOps project. Requires --project flag.
Shows connection name, type, readiness, and sharing status.

Use --scan-yaml to discover additional service connections referenced in pipeline YAML files.
This is useful when the API returns empty results due to permission restrictions.`,
		RunE: runListConnections,
	}

	cmd.Flags().SortFlags = false
	cmd.Flags().BoolVar(&scanYAML, "scan-yaml", false, "Scan pipeline YAML files for service connection references")

	return cmd
}

func runListConnections(cmd *cobra.Command, args []string) error {
	switch enumPlatform {
	case "azuredevops":
		return runListConnectionsAzDO()
	default:
		return fmt.Errorf("not supported for platform: %s", enumPlatform)
	}
}

func runListConnectionsAzDO() error {
	if enumOrg == "" {
		return fmt.Errorf("--org is required for Azure DevOps")
	}
	if enumProject == "" {
		return fmt.Errorf("--project is required for this command")
	}
	ctx := context.Background()
	orgURL := fmt.Sprintf("https://dev.azure.com/%s", enumOrg)
	client, err := NewEnumerateClient(orgURL, GetTokenForPlatform("azuredevops"))
	if err != nil {
		return err
	}

	connections, err := client.ListServiceConnections(ctx, enumProject)
	if err != nil {
		return err
	}

	var discovered []azuredevops.DiscoveredServiceConnection
	if scanYAML || len(connections) == 0 {
		discovered, err = client.DiscoverServiceConnectionsFromYAML(ctx, enumProject)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: YAML discovery failed: %v\n", err)
		}
	}

	switch enumOutput {
	case "json":
		result := map[string]interface{}{
			"api_connections": connections,
			"yaml_discovered": discovered,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)

	case "csv":
		headers := []string{"ID", "Name", "Type", "Ready", "Shared", "Description"}
		rows := make([][]string, len(connections))
		for i, conn := range connections {
			ready := "no"
			if conn.IsReady {
				ready = "yes"
			}
			shared := "no"
			if conn.IsShared {
				shared = "yes"
			}
			desc := conn.Description
			if desc == "" {
				desc = "-"
			}
			rows[i] = []string{conn.ID, conn.Name, conn.Type, ready, shared, desc}
		}
		if err := output.RenderCSV(os.Stdout, headers, rows); err != nil {
			return err
		}

		// Add discovered connections in CSV
		if len(discovered) > 0 {
			fmt.Println() // blank line separator
			headers = []string{"Name", "UsageType", "Repository", "FilePath"}
			discoveredRows := make([][]string, len(discovered))
			for i, conn := range discovered {
				discoveredRows[i] = []string{conn.Name, conn.UsageType, conn.Repository, conn.FilePath}
			}
			return output.RenderCSV(os.Stdout, headers, discoveredRows)
		}
		return nil

	default: // console
		if len(connections) == 0 && len(discovered) == 0 {
			fmt.Println("No service connections found")
			return nil
		}

		if len(connections) > 0 {
			fmt.Println("=== API Service Connections ===")
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tTYPE\tREADY\tSHARED")
			for _, conn := range connections {
				ready := "no"
				if conn.IsReady {
					ready = "yes"
				}
				shared := "no"
				if conn.IsShared {
					shared = "yes"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", conn.Name, conn.Type, ready, shared)
			}
			w.Flush()
			fmt.Printf("\nTotal: %d service connections\n", len(connections))
		}

		if len(discovered) > 0 {
			if len(connections) > 0 {
				fmt.Println() // blank line between sections
			}
			fmt.Println("=== YAML-Discovered Service Connections ===")
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tUSAGE TYPE\tREPOSITORY\tFILE")
			for _, conn := range discovered {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", conn.Name, conn.UsageType, conn.Repository, conn.FilePath)
			}
			w.Flush()
			fmt.Printf("\nTotal: %d discovered connections\n", len(discovered))
		}
		return nil
	}
}
