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

func newReposCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "repos",
		Short: "List repositories",
		Long: `Trajan - Azure DevOps - Enumerate

List repositories in an Azure DevOps organization or project.
Shows repo metadata including size, default branch, and disabled status.
Use --project to scope to a single project; omit to list all repos across all projects.`,
		RunE: runListRepos,
	}
}

func runListRepos(cmd *cobra.Command, args []string) error {
	switch enumPlatform {
	case "azuredevops":
		return runListReposAzDO()
	default:
		return fmt.Errorf("not supported for platform: %s", enumPlatform)
	}
}

func runListReposAzDO() error {
	if enumOrg == "" {
		return fmt.Errorf("--org is required for Azure DevOps")
	}
	ctx := context.Background()
	orgURL := fmt.Sprintf("https://dev.azure.com/%s", enumOrg)
	client, err := NewEnumerateClient(orgURL, GetTokenForPlatform("azuredevops"))
	if err != nil {
		return err
	}

	var allRepos []azuredevops.Repository

	if enumProject != "" {
		repos, err := client.ListRepositories(ctx, enumProject)
		if err != nil {
			return err
		}
		allRepos = repos
	} else {
		projects, err := client.ListProjects(ctx)
		if err != nil {
			return err
		}

		for _, proj := range projects {
			repos, err := client.ListRepositories(ctx, proj.Name)
			if err != nil {
				// Skip projects we can't access
				continue
			}
			allRepos = append(allRepos, repos...)
		}
	}

	switch enumOutput {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(allRepos)

	case "csv":
		headers := []string{"Name", "ID", "Project", "Default Branch", "Size", "Disabled"}
		rows := make([][]string, len(allRepos))
		for i, repo := range allRepos {
			disabled := "no"
			if repo.IsDisabled {
				disabled = "yes"
			}
			rows[i] = []string{repo.Name, repo.ID, repo.Project.Name, repo.DefaultBranch, formatSize(repo.Size), disabled}
		}
		return output.RenderCSV(os.Stdout, headers, rows)

	default: // console
		if len(allRepos) == 0 {
			fmt.Println("No repositories found")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tPROJECT\tDEFAULT BRANCH\tSIZE\tDISABLED")
		for _, repo := range allRepos {
			disabled := "no"
			if repo.IsDisabled {
				disabled = "yes"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", repo.Name, repo.Project.Name, repo.DefaultBranch, formatSize(repo.Size), disabled)
		}
		w.Flush()

		fmt.Printf("\nTotal: %d repositories\n", len(allRepos))
		return nil
	}
}
