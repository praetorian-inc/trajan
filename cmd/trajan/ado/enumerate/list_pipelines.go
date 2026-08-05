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

func newPipelinesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pipelines",
		Short: "List pipelines in a project",
		Long: `Trajan - Azure DevOps - Enumerate

List pipelines and build definitions in an Azure DevOps organization or project.
Shows both YAML pipelines and classic build definitions with their IDs, names, and paths.
Use --project to scope to a single project; omit to list all pipelines across all projects.`,
		RunE: runListPipelines,
	}
}

func runListPipelines(cmd *cobra.Command, args []string) error {
	switch enumPlatform {
	case "azuredevops":
		return runListPipelinesAzDO()
	default:
		return fmt.Errorf("not supported for platform: %s", enumPlatform)
	}
}

func runListPipelinesAzDO() error {
	if enumOrg == "" {
		return fmt.Errorf("--org is required for Azure DevOps")
	}
	ctx := context.Background()
	orgURL := fmt.Sprintf("https://dev.azure.com/%s", enumOrg)
	client, err := NewEnumerateClient(orgURL, GetTokenForPlatform("azuredevops"))
	if err != nil {
		return err
	}

	var pipelines []azuredevops.Pipeline
	var buildDefs []azuredevops.BuildDefinition

	if enumProject != "" {
		var err error
		pipelines, err = client.ListPipelines(ctx, enumProject)
		if err != nil {
			return err
		}
		buildDefs, err = client.ListBuildDefinitions(ctx, enumProject)
		if err != nil {
			return err
		}
	} else {
		projects, err := client.ListProjects(ctx)
		if err != nil {
			return err
		}
		for _, proj := range projects {
			p, err := client.ListPipelines(ctx, proj.Name)
			if err != nil {
				continue
			}
			pipelines = append(pipelines, p...)
			bd, err := client.ListBuildDefinitions(ctx, proj.Name)
			if err != nil {
				continue
			}
			buildDefs = append(buildDefs, bd...)
		}
	}

	switch enumOutput {
	case "json":
		result := map[string]interface{}{
			"pipelines":        pipelines,
			"buildDefinitions": buildDefs,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)

	case "csv":
		headers := []string{"Type", "ID", "Name", "Folder", "Path"}
		var rows [][]string
		for _, p := range pipelines {
			rows = append(rows, []string{"Pipeline", fmt.Sprintf("%d", p.ID), p.Name, p.Folder, "-"})
		}
		for _, bd := range buildDefs {
			rows = append(rows, []string{"BuildDef", fmt.Sprintf("%d", bd.ID), bd.Name, "-", bd.Path})
		}
		return output.RenderCSV(os.Stdout, headers, rows)

	default: // console
		fmt.Println("Pipelines:")
		if len(pipelines) == 0 {
			fmt.Println("  No pipelines found")
		} else {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "  ID\tNAME\tFOLDER")
			for _, p := range pipelines {
				fmt.Fprintf(w, "  %d\t%s\t%s\n", p.ID, p.Name, p.Folder)
			}
			w.Flush()
			fmt.Printf("  Total: %d pipelines\n", len(pipelines))
		}

		fmt.Println("\nBuild Definitions:")
		if len(buildDefs) == 0 {
			fmt.Println("  No build definitions found")
		} else {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "  ID\tNAME\tPATH\tQUEUE STATUS")
			for _, bd := range buildDefs {
				fmt.Fprintf(w, "  %d\t%s\t%s\t%s\n", bd.ID, bd.Name, bd.Path, bd.QueueStatus)
			}
			w.Flush()
			fmt.Printf("  Total: %d build definitions\n", len(buildDefs))
		}
		return nil
	}
}
