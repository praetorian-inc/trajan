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

var branchPoliciesBuildOnly bool

func newBranchPoliciesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "branch-policies",
		Short: "List branch policies",
		Long: `Trajan - Azure DevOps - Enumerate

List branch protection policies configured across repositories and branches.
Shows policy type, scope (repository/branch), enabled/blocking status, and details.
Use --project to scope to a single project; omit to enumerate policies across all projects.
Use --build-only to show only build validation policies.`,
		RunE: runListBranchPolicies,
	}

	cmd.Flags().SortFlags = false
	cmd.Flags().BoolVar(&branchPoliciesBuildOnly, "build-only", false, "Show only build validation policies")

	return cmd
}

func runListBranchPolicies(cmd *cobra.Command, args []string) error {
	switch enumPlatform {
	case "azuredevops":
		return runListBranchPoliciesAzDO()
	default:
		return fmt.Errorf("not supported for platform: %s", enumPlatform)
	}
}

func runListBranchPoliciesAzDO() error {
	if enumOrg == "" {
		return fmt.Errorf("--org is required for Azure DevOps")
	}

	ctx := context.Background()
	orgURL := fmt.Sprintf("https://dev.azure.com/%s", enumOrg)
	client, err := NewEnumerateClient(orgURL, GetTokenForPlatform("azuredevops"))
	if err != nil {
		return err
	}

	var projects []string
	if enumProject != "" {
		// Single project specified
		projects = []string{enumProject}
	} else {
		// List all projects
		projList, err := client.ListProjects(ctx)
		if err != nil {
			return err
		}
		for _, p := range projList {
			projects = append(projects, p.Name)
		}
	}

	// Collect all policies across projects
	type policyRow struct {
		ID         int
		Type       string
		Project    string
		Repository string
		Branch     string
		Enabled    string
		Blocking   string
		Details    string
	}

	var allPolicies []azuredevops.PolicyConfiguration
	var rows []policyRow

	for _, proj := range projects {
		// Get policies for this project
		policies, err := client.ListPolicyConfigurations(ctx, proj)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to list policies for project %s: %v\n", proj, err)
			continue
		}

		// Build repository name map
		repoMap := make(map[string]string)
		repos, err := client.ListRepositories(ctx, proj)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to list repositories for project %s: %v\n", proj, err)
		} else {
			for _, repo := range repos {
				repoMap[repo.ID] = repo.Name
			}
		}

		// Get policy type name map
		typeMap := policyTypeNameMap()

		// Process policies
		for _, p := range policies {
			// Filter for build-only if requested
			if branchPoliciesBuildOnly && p.Type.ID != buildValidationPolicyTypeID {
				continue
			}

			allPolicies = append(allPolicies, p)

			// Expand scope entries into separate rows
			if len(p.Settings.Scope) == 0 {
				// No scope defined - applies to all repos
				row := policyRow{
					ID:         p.ID,
					Type:       getPolicyTypeName(p.Type.ID, typeMap),
					Project:    proj,
					Repository: "(all repos)",
					Branch:     "",
					Enabled:    formatBool(p.IsEnabled),
					Blocking:   formatBool(p.IsBlocking),
					Details:    formatPolicyDetails(p),
				}
				rows = append(rows, row)
			} else {
				// Create a row for each scope entry
				for _, scope := range p.Settings.Scope {
					row := policyRow{
						ID:         p.ID,
						Type:       getPolicyTypeName(p.Type.ID, typeMap),
						Project:    proj,
						Repository: getRepoName(scope.RepositoryID, repoMap),
						Branch:     formatBranchName(scope.RefName),
						Enabled:    formatBool(p.IsEnabled),
						Blocking:   formatBool(p.IsBlocking),
						Details:    formatPolicyDetails(p),
					}
					rows = append(rows, row)
				}
			}
		}
	}

	// Output results
	switch enumOutput {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(allPolicies)

	case "csv":
		headers := []string{"ID", "TYPE", "PROJECT", "REPOSITORY", "BRANCH", "ENABLED", "BLOCKING", "DETAILS"}
		csvRows := make([][]string, len(rows))
		for i, row := range rows {
			csvRows[i] = []string{
				fmt.Sprintf("%d", row.ID),
				row.Type,
				row.Project,
				row.Repository,
				row.Branch,
				row.Enabled,
				row.Blocking,
				row.Details,
			}
		}
		return output.RenderCSV(os.Stdout, headers, csvRows)

	default: // console
		if len(rows) == 0 {
			fmt.Println("No branch policies found")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tTYPE\tPROJECT\tREPOSITORY\tBRANCH\tENABLED\tBLOCKING\tDETAILS")
		for _, row := range rows {
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				row.ID,
				row.Type,
				row.Project,
				row.Repository,
				row.Branch,
				row.Enabled,
				row.Blocking,
				row.Details,
			)
		}
		_ = w.Flush()

		fmt.Printf("\nTotal: %d policies\n", len(allPolicies))
		return nil
	}
}

// getRepoName returns a display name for a repository ID
func getRepoName(repoID string, repoMap map[string]string) string {
	if repoID == "" || repoID == "null" {
		return "(all repos)"
	}
	if name, ok := repoMap[repoID]; ok {
		return name
	}
	// Truncate long IDs for display
	if len(repoID) > 8 {
		return repoID[:8] + "..."
	}
	return repoID
}

// formatBranchName formats a Git ref for display
func formatBranchName(refName string) string {
	if refName == "" {
		return "*"
	}
	// Strip refs/heads/ prefix if present
	if len(refName) > 11 && refName[:11] == "refs/heads/" {
		return refName[11:]
	}
	return refName
}

// getPolicyTypeName returns a friendly name for a policy type ID
func getPolicyTypeName(typeID string, typeMap map[string]string) string {
	if name, ok := typeMap[typeID]; ok {
		return name
	}
	// Truncate unknown type IDs
	if len(typeID) > 8 {
		return typeID[:8] + "..."
	}
	return typeID
}

// formatPolicyDetails returns a summary of policy-specific details
func formatPolicyDetails(p azuredevops.PolicyConfiguration) string {
	if p.Type.ID == buildValidationPolicyTypeID {
		// For build validation, try to show build definition info
		if p.Settings.BuildDefinitionID > 0 {
			return fmt.Sprintf("Pipeline ID: %d", p.Settings.BuildDefinitionID)
		}
	}
	if p.Settings.MinimumApproverCount > 0 {
		return fmt.Sprintf("%d reviewer(s)", p.Settings.MinimumApproverCount)
	}
	return "-"
}
