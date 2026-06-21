package enumerate

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/internal/registry"
	gitlabplatform "github.com/praetorian-inc/trajan/pkg/gitlab"
	"github.com/praetorian-inc/trajan/pkg/platforms"

	_ "github.com/praetorian-inc/trajan/pkg/platforms/all"
)

var (
	branchProtectionsProject      string
	branchProtectionsGroup        string
	branchProtectionsShowWeakOnly bool
	branchProtectionsOutputFile   string
)

var branchProtectionsCmd = &cobra.Command{
	Use:   "branch-protections",
	Short: "Enumerate branch protection rules",
	Long: `Trajan - GitLab CI - Enumerate

Enumerate branch protection rules for a project or all projects within a group.
Reports protected branch configurations including push/merge access levels, force push settings,
and code owner approval requirements. Use --show-weak-only to surface misconfigurations.`,
	RunE: runBranchProtectionsEnumerate,
}

func init() {
	branchProtectionsCmd.Flags().SortFlags = false
	branchProtectionsCmd.Flags().StringVar(&branchProtectionsProject, "project", "", "project to enumerate (group/project)")
	branchProtectionsCmd.Flags().StringVar(&branchProtectionsGroup, "group", "", "group to enumerate (all projects)")
	branchProtectionsCmd.Flags().BoolVar(&branchProtectionsShowWeakOnly, "show-weak-only", false, "show only weak protections")
	branchProtectionsCmd.Flags().StringVar(&branchProtectionsOutputFile, "output-file", "", "save output to file")
}

func runBranchProtectionsEnumerate(cmd *cobra.Command, args []string) error {
	token := getToken(cmd)
	if token == "" {
		return fmt.Errorf("no token provided (use --token or set GITLAB_TOKEN/GL_TOKEN env var)")
	}

	output := cmdutil.GetOutput(cmd)

	// Validate that either --project or --group is provided
	if branchProtectionsProject == "" && branchProtectionsGroup == "" {
		return fmt.Errorf("must specify --project or --group")
	}

	if branchProtectionsProject != "" && branchProtectionsGroup != "" {
		return fmt.Errorf("cannot specify both --project and --group")
	}

	ctx := context.Background()

	platform, err := registry.GetPlatform("gitlab")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	config := platforms.Config{
		Token:  token,
		GitLab: &platforms.GitLabAuth{Token: token},
	}
	if url := getGitLabURL(cmd); url != "" {
		config.BaseURL = url
	}
	cmdutil.ApplyProxyFlags(cmd, &config)

	if err := platform.Init(ctx, config); err != nil {
		return fmt.Errorf("initializing platform: %w", err)
	}

	glPlatform, ok := platform.(*gitlabplatform.Platform)
	if !ok {
		return fmt.Errorf("unexpected platform type")
	}

	var results []*gitlabplatform.BranchProtectionsEnumerateResult

	// Handle --group: enumerate all projects in group, then get protections for each
	if branchProtectionsGroup != "" {
		if output == "console" {
			fmt.Fprintf(os.Stderr, "Enumerating projects in group %s...\n", branchProtectionsGroup)
		}

		// Get all projects in the group
		groupTarget := platforms.Target{Type: platforms.TargetOrg, Value: branchProtectionsGroup}
		projectsResult, err := glPlatform.EnumerateProjects(ctx, groupTarget)
		if err != nil {
			return fmt.Errorf("enumerating projects in group: %w", err)
		}

		if len(projectsResult.Projects) == 0 {
			fmt.Println("No projects found in group")
			return nil
		}

		if output == "console" {
			fmt.Fprintf(os.Stderr, "Found %d projects, enumerating branch protections...\n", len(projectsResult.Projects))
		}

		// Enumerate branch protections for each project
		for _, proj := range projectsResult.Projects {
			projectPath := proj.Owner + "/" + proj.Name
			target := platforms.Target{Type: platforms.TargetRepo, Value: projectPath}

			result, err := glPlatform.EnumerateBranchProtections(ctx, target)
			if err != nil {
				// Collect error but continue with other projects
				result = &gitlabplatform.BranchProtectionsEnumerateResult{
					Project: projectPath,
					Errors:  []string{err.Error()},
				}
			}
			results = append(results, result)
		}
	} else {
		// Handle --project: single project
		if output == "console" {
			fmt.Fprintf(os.Stderr, "Enumerating branch protections for %s...\n", branchProtectionsProject)
		}

		target := platforms.Target{Type: platforms.TargetRepo, Value: branchProtectionsProject}
		result, err := glPlatform.EnumerateBranchProtections(ctx, target)
		if err != nil {
			return fmt.Errorf("enumerating branch protections: %w", err)
		}
		results = append(results, result)
	}

	switch output {
	case "json":
		return outputBranchProtectionsJSON(results, branchProtectionsOutputFile)
	default:
		return outputBranchProtectionsConsole(results, branchProtectionsShowWeakOnly)
	}
}
