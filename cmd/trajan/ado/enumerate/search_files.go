package enumerate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/output"
)

var searchFilesQuery string

func newSearchFilesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "files",
		Short: "Search for files by filename pattern",
		Long: `Trajan - Azure DevOps - Enumerate

Search for files by filename pattern (case-insensitive substring match on path).
Requires --query flag. Optional --project flag to scope search to a specific project.`,
		RunE: runSearchFiles,
	}

	cmd.Flags().SortFlags = false
	cmd.Flags().StringVarP(&searchFilesQuery, "query", "q", "", "Filename pattern (required, case-insensitive substring match)")
	_ = cmd.MarkFlagRequired("query")
	cmd.Flags().StringVar(&enumProject, "project", "", "Project name (optional, search across all if not provided)")

	return cmd
}

func runSearchFiles(cmd *cobra.Command, args []string) error {
	switch enumPlatform {
	case "azuredevops":
		return runSearchFilesAzDO()
	default:
		return fmt.Errorf("not supported for platform: %s", enumPlatform)
	}
}

func runSearchFilesAzDO() error {
	if enumOrg == "" {
		return fmt.Errorf("--org is required for Azure DevOps")
	}
	if searchFilesQuery == "" {
		return fmt.Errorf("--query is required for this command")
	}
	ctx := context.Background()
	orgURL := fmt.Sprintf("https://dev.azure.com/%s", enumOrg)
	client, err := NewEnumerateClient(orgURL, GetTokenForPlatform("azuredevops"))
	if err != nil {
		return err
	}

	type fileMatch struct {
		Project    string
		Repository string
		Path       string
	}

	var matches []fileMatch

	// Get projects
	var projects []azuredevops.Project
	if enumProject != "" {
		// Single project mode
		proj, err := client.GetProject(ctx, enumProject)
		if err != nil {
			return fmt.Errorf("getting project: %w", err)
		}
		projects = []azuredevops.Project{*proj}
	} else {
		// All projects mode
		allProjects, err := client.ListProjects(ctx)
		if err != nil {
			return err
		}
		projects = allProjects
	}

	// Search each project's repositories
	for _, project := range projects {
		repos, err := client.ListRepositories(ctx, project.ID)
		if err != nil {
			continue // Skip projects we can't access
		}

		for _, repo := range repos {
			items, err := client.ListRepoItems(ctx, project.ID, repo.ID)
			if err != nil {
				continue // Skip repos we can't access
			}

			// Match each item's path against query (case-insensitive)
			for _, item := range items {
				if !item.IsFolder && strings.Contains(strings.ToLower(item.Path), strings.ToLower(searchFilesQuery)) {
					matches = append(matches, fileMatch{
						Project:    project.Name,
						Repository: repo.Name,
						Path:       item.Path,
					})
				}
			}
		}
	}

	switch enumOutput {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(matches)

	case "csv":
		headers := []string{"Project", "Repository", "Path"}
		rows := make([][]string, len(matches))
		for i, m := range matches {
			rows[i] = []string{m.Project, m.Repository, m.Path}
		}
		return output.RenderCSV(os.Stdout, headers, rows)

	default: // console
		if len(matches) == 0 {
			fmt.Printf("No files found matching pattern: %q\n", searchFilesQuery)
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "PROJECT\tREPOSITORY\tPATH")
		for _, m := range matches {
			fmt.Fprintf(w, "%s\t%s\t%s\n", m.Project, m.Repository, m.Path)
		}
		w.Flush()

		fmt.Printf("\nTotal: %d files found matching %q\n", len(matches), searchFilesQuery)
		return nil
	}
}
