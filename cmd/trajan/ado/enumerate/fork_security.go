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

func newForkSecurityCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fork-security",
		Short: "Detect pipelines with insecure fork build configurations",
		Long: `Trajan - Azure DevOps - Enumerate

Detect pipelines with insecure fork build configurations.

Scans Azure DevOps build pipelines for security issues related to fork builds:
- Secrets exposed to fork builds (Critical)
- Fork builds without required approval (High)

Requires --org flag. Optionally accepts --project flag to scan a single project.`,
		RunE: runForkSecurity,
	}
}

func runForkSecurity(cmd *cobra.Command, args []string) error {
	switch enumPlatform {
	case "azuredevops":
		return runForkSecurityAzDO()
	default:
		return fmt.Errorf("not supported for platform: %s", enumPlatform)
	}
}

func runForkSecurityAzDO() error {
	if enumOrg == "" {
		return fmt.Errorf("--org is required for Azure DevOps")
	}

	ctx := context.Background()
	orgURL := fmt.Sprintf("https://dev.azure.com/%s", enumOrg)
	client, err := NewEnumerateClient(orgURL, GetTokenForPlatform("azuredevops"))
	if err != nil {
		return err
	}

	var projects []azuredevops.Project

	if enumProject != "" {
		proj, err := client.GetProject(ctx, enumProject)
		if err != nil {
			return fmt.Errorf("getting project: %w", err)
		}
		projects = []azuredevops.Project{*proj}
	} else {
		projects, err = client.ListProjects(ctx)
		if err != nil {
			return err
		}
	}

	var vulnerabilities []azuredevops.ForkVulnerability

	for _, project := range projects {
		definitions, err := client.ListBuildDefinitions(ctx, project.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to list build definitions for %s: %v\n", project.Name, err)
			continue
		}

		for _, def := range definitions {
			fullDef, err := client.GetBuildDefinition(ctx, project.Name, def.ID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to get definition %d: %v\n", def.ID, err)
				continue
			}

			// Fork build settings only exist for GitHub-hosted repositories.
			if fullDef.Repository.Type != "GitHub" && fullDef.Repository.Type != "GitHubEnterprise" {
				continue
			}

			for _, trigger := range fullDef.Triggers {
				if trigger.TriggerType != "pullRequest" {
					continue
				}

				if trigger.Forks == nil {
					continue
				}

				if trigger.Forks.Enabled && trigger.Forks.AllowSecrets {
					vulnerabilities = append(vulnerabilities, azuredevops.ForkVulnerability{
						PipelineID:   fullDef.ID,
						PipelineName: fullDef.Name,
						RepoType:     fullDef.Repository.Type,
						Severity:     "Critical",
						Issue:        "Secrets exposed to fork builds",
					})
				}

				if trigger.Forks.Enabled && !trigger.IsCommentRequiredForPullRequest && !trigger.RequireCommentsForNonTeamMembersOnly {
					vulnerabilities = append(vulnerabilities, azuredevops.ForkVulnerability{
						PipelineID:   fullDef.ID,
						PipelineName: fullDef.Name,
						RepoType:     fullDef.Repository.Type,
						Severity:     "High",
						Issue:        "No comment required for fork builds",
					})
				}
			}
		}
	}

	switch enumOutput {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(vulnerabilities)

	case "csv":
		headers := []string{"PIPELINE", "ID", "REPO TYPE", "SEVERITY", "ISSUE"}
		rows := make([][]string, len(vulnerabilities))
		for i, vuln := range vulnerabilities {
			rows[i] = []string{
				vuln.PipelineName,
				fmt.Sprintf("%d", vuln.PipelineID),
				vuln.RepoType,
				vuln.Severity,
				vuln.Issue,
			}
		}
		return output.RenderCSV(os.Stdout, headers, rows)

	default: // console
		if len(vulnerabilities) == 0 {
			fmt.Println("✅ No fork security vulnerabilities found")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "PIPELINE\tID\tREPO TYPE\tSEVERITY\tISSUE")
		for _, vuln := range vulnerabilities {
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\n",
				vuln.PipelineName,
				vuln.PipelineID,
				vuln.RepoType,
				vuln.Severity,
				vuln.Issue,
			)
		}
		_ = w.Flush()

		criticalCount := 0
		for _, vuln := range vulnerabilities {
			if vuln.Severity == "Critical" {
				criticalCount++
			}
		}

		fmt.Printf("\n⚠️  Found %d fork security vulnerabilities (%d critical)\n", len(vulnerabilities), criticalCount)
		return nil
	}
}
