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

var (
	searchLogsQuery string
	searchLogsLimit int
)

func newSearchLogsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Search build logs for patterns",
		Long: `Trajan - Azure DevOps - Enumerate

Search build logs for patterns (case-insensitive substring match).

Use --project to scope to a single project, or omit to search across all projects.
Optional --query flag for pattern matching.
Optional --limit flag to control number of builds to search per project (default 25).`,
		RunE: runSearchLogs,
	}

	cmd.Flags().SortFlags = false
	cmd.Flags().StringVar(&enumProject, "project", "", "Project name (optional, iterates all projects if omitted)")
	cmd.Flags().StringVarP(&searchLogsQuery, "query", "q", "", "Search pattern (case-insensitive substring match)")
	cmd.Flags().IntVar(&searchLogsLimit, "limit", 25, "Maximum number of builds to search")

	return cmd
}

func runSearchLogs(cmd *cobra.Command, args []string) error {
	switch enumPlatform {
	case "azuredevops":
		return runSearchLogsAzDO()
	default:
		return fmt.Errorf("not supported for platform: %s", enumPlatform)
	}
}

func runSearchLogsAzDO() error {
	if enumOrg == "" {
		return fmt.Errorf("--org is required for Azure DevOps")
	}
	ctx := context.Background()
	orgURL := fmt.Sprintf("https://dev.azure.com/%s", enumOrg)
	client, err := NewEnumerateClient(orgURL, GetTokenForPlatform("azuredevops"))
	if err != nil {
		return err
	}

	// Get recent builds
	var builds []azuredevops.Build
	var searchProject string

	if enumProject != "" {
		b, err := client.ListBuilds(ctx, enumProject)
		if err != nil {
			return err
		}
		builds = b
	} else {
		projects, err := client.ListProjects(ctx)
		if err != nil {
			return err
		}
		for _, proj := range projects {
			b, err := client.ListBuilds(ctx, proj.Name)
			if err != nil {
				continue
			}
			builds = append(builds, b...)
		}
		_ = searchProject // not used in org-wide mode
	}

	// Limit builds to search
	if len(builds) > searchLogsLimit {
		builds = builds[:searchLogsLimit]
	}

	type logMatch struct {
		BuildID    int
		BuildNum   string
		Definition string
		LogID      int
		Snippet    string
	}

	var matches []logMatch

	for _, build := range builds {
		// Use the build's project for API calls (supports org-wide iteration)
		buildProject := enumProject
		if buildProject == "" && build.Project.Name != "" {
			buildProject = build.Project.Name
		}
		logs, err := client.ListBuildLogs(ctx, buildProject, build.ID)
		if err != nil {
			continue // Skip builds we can't access
		}

		for _, log := range logs {
			content, err := client.GetBuildLog(ctx, buildProject, build.ID, log.ID)
			if err != nil {
				continue // Skip logs we can't read
			}

			logStr := string(content)

			// If no query, report all logs
			if searchLogsQuery == "" {
				snippet := logStr
				if len(snippet) > 100 {
					snippet = snippet[:100] + "..."
				}
				matches = append(matches, logMatch{
					BuildID:    build.ID,
					BuildNum:   build.BuildNumber,
					Definition: build.Definition.Name,
					LogID:      log.ID,
					Snippet:    strings.ReplaceAll(snippet, "\n", " "),
				})
				continue
			}

			// Case-insensitive substring search
			if strings.Contains(strings.ToLower(logStr), strings.ToLower(searchLogsQuery)) {
				// Find matching line
				lines := strings.Split(logStr, "\n")
				for _, line := range lines {
					if strings.Contains(strings.ToLower(line), strings.ToLower(searchLogsQuery)) {
						snippet := line
						if len(snippet) > 100 {
							snippet = snippet[:100] + "..."
						}
						matches = append(matches, logMatch{
							BuildID:    build.ID,
							BuildNum:   build.BuildNumber,
							Definition: build.Definition.Name,
							LogID:      log.ID,
							Snippet:    snippet,
						})
						break // Only first match per log
					}
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
		headers := []string{"BuildID", "BuildNumber", "Definition", "LogID", "Snippet"}
		rows := make([][]string, len(matches))
		for i, m := range matches {
			rows[i] = []string{
				fmt.Sprintf("%d", m.BuildID),
				m.BuildNum,
				m.Definition,
				fmt.Sprintf("%d", m.LogID),
				m.Snippet,
			}
		}
		return output.RenderCSV(os.Stdout, headers, rows)

	default: // console
		if len(matches) == 0 {
			if searchLogsQuery == "" {
				fmt.Println("No build logs found")
			} else {
				fmt.Printf("No matches found for query: %q\n", searchLogsQuery)
			}
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "BUILD_ID\tBUILD_NUM\tDEFINITION\tLOG_ID\tSNIPPET")
		for _, m := range matches {
			fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%s\n",
				m.BuildID, m.BuildNum, m.Definition, m.LogID, m.Snippet)
		}
		w.Flush()

		if searchLogsQuery == "" {
			fmt.Printf("\nTotal: %d logs found in %d builds\n", len(matches), len(builds))
		} else {
			fmt.Printf("\nTotal: %d matches found for %q\n", len(matches), searchLogsQuery)
		}
		return nil
	}
}
