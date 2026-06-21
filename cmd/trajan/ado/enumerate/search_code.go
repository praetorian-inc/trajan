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

var searchCodeQuery string

func newSearchCodeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "code",
		Short: "Search code across repositories",
		Long: `Trajan - Azure DevOps - Enumerate

Search for code across repositories. Use --project to scope to a project, or search org-wide.
Requires --query flag.`,
		RunE: runSearchCode,
	}

	cmd.Flags().SortFlags = false
	cmd.Flags().StringVarP(&searchCodeQuery, "query", "q", "", "Search query (required)")
	_ = cmd.MarkFlagRequired("query")

	return cmd
}

func runSearchCode(cmd *cobra.Command, args []string) error {
	switch enumPlatform {
	case "azuredevops":
		return runSearchCodeAzDO()
	default:
		return fmt.Errorf("not supported for platform: %s", enumPlatform)
	}
}

func runSearchCodeAzDO() error {
	if enumOrg == "" {
		return fmt.Errorf("--org is required for Azure DevOps")
	}
	if searchCodeQuery == "" {
		return fmt.Errorf("--query is required for this command")
	}
	ctx := context.Background()
	orgURL := fmt.Sprintf("https://dev.azure.com/%s", enumOrg)
	client, err := NewEnumerateClient(orgURL, GetTokenForPlatform("azuredevops"))
	if err != nil {
		return err
	}

	req := azuredevops.CodeSearchRequest{
		SearchText:    searchCodeQuery,
		Top:           100,
		IncludeFacets: false,
	}

	var result *azuredevops.CodeSearchResult

	if enumProject != "" {
		result, err = client.SearchCode(ctx, enumProject, req)
	} else {
		result, err = client.SearchCodeOrg(ctx, req)
	}

	if err != nil {
		return fmt.Errorf("searching code: %w", err)
	}

	switch enumOutput {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)

	case "csv":
		headers := []string{"Project", "Repository", "File", "Path"}
		rows := make([][]string, len(result.Results))
		for i, r := range result.Results {
			rows[i] = []string{r.Project.Name, r.Repository.Name, r.FileName, r.Path}
		}
		return output.RenderCSV(os.Stdout, headers, rows)

	default: // console
		if result.Count == 0 {
			fmt.Println("No results found")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "PROJECT\tREPOSITORY\tFILE\tPATH")
		for _, r := range result.Results {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Project.Name, r.Repository.Name, r.FileName, r.Path)
		}
		w.Flush()

		fmt.Printf("\nTotal: %d results\n", result.Count)
		return nil
	}
}
