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
	runnersProject    string
	runnersGroup      string
	runnersInstance   bool
	runnersShowTags   bool
	runnersShowGaps   bool
	runnersOutputFile string
)

var runnersCmd = &cobra.Command{
	Use:   "runners",
	Short: "Enumerate GitLab runners and analyze workflow tag coverage",
	Long: `Trajan - GitLab CI - Enumerate

Enumerate GitLab runners at the project, group, or instance level and analyze workflow tag coverage.
Use --project, --group, or --instance to control which runner types are shown.
Use --show-tags to analyze workflow tag coverage and --show-gaps to highlight missing tags.`,
	RunE: runRunnersEnumerate,
}

func init() {
	runnersCmd.Flags().SortFlags = false
	runnersCmd.Flags().StringVar(&runnersProject, "project", "", "enumerate project runners for specified project (owner/repo)")
	runnersCmd.Flags().StringVar(&runnersGroup, "group", "", "enumerate group runners for specified group")
	runnersCmd.Flags().BoolVar(&runnersInstance, "instance", false, "enumerate instance runners (requires admin token)")

	runnersCmd.Flags().BoolVar(&runnersShowTags, "show-tags", false, "analyze workflow tags and show coverage")
	runnersCmd.Flags().BoolVar(&runnersShowGaps, "show-gaps", false, "show only missing workflow tags (requires --show-tags)")
	runnersCmd.Flags().StringVar(&runnersOutputFile, "output-file", "", "save output to file")
}

func runRunnersEnumerate(cmd *cobra.Command, args []string) error {
	token := getToken(cmd)
	if token == "" {
		return fmt.Errorf("no token provided (use --token or set GITLAB_TOKEN/GL_TOKEN env var)")
	}

	output := cmdutil.GetOutput(cmd)

	// Validate that at least one scope is specified
	if runnersProject == "" && runnersGroup == "" && !runnersInstance {
		return fmt.Errorf("must specify at least one of: --project, --group, or --instance")
	}

	// Validate --show-gaps requires --show-tags
	if runnersShowGaps && !runnersShowTags {
		return fmt.Errorf("--show-gaps requires --show-tags")
	}

	// Determine which runner types to include based on flags
	includeProject := (runnersProject != "")
	includeGroup := (runnersGroup != "")
	includeInstance := runnersInstance

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

	var results []*gitlabplatform.RunnersEnumerateResult

	// Determine enumeration mode based on what's specified
	if runnersGroup != "" {
		// Group mode: enumerate all projects in the group
		if output == "console" {
			fmt.Fprintf(os.Stderr, "Enumerating projects in group %s...\n", runnersGroup)
		}

		// Get all projects in the group
		groupTarget := platforms.Target{Type: platforms.TargetOrg, Value: runnersGroup}
		projectsResult, err := glPlatform.EnumerateProjects(ctx, groupTarget)
		if err != nil {
			return fmt.Errorf("enumerating projects in group: %w", err)
		}

		if len(projectsResult.Projects) == 0 {
			fmt.Println("No projects found in group")
			return nil
		}

		if output == "console" {
			fmt.Fprintf(os.Stderr, "Found %d projects, enumerating runners...\n", len(projectsResult.Projects))
		}

		// Enumerate runners for each project
		for _, proj := range projectsResult.Projects {
			projectPath := proj.Owner + "/" + proj.Name
			result, err := enumerateRunnersForProject(ctx, glPlatform, projectPath, includeGroup, includeInstance)
			if err != nil {
				// Collect error but continue with other projects
				result = &gitlabplatform.RunnersEnumerateResult{
					Errors: []string{err.Error()},
				}
			}
			results = append(results, result)
		}
	} else if runnersProject != "" {
		// Project mode: enumerate single project
		if output == "console" {
			fmt.Fprintf(os.Stderr, "Enumerating runners for %s...\n", runnersProject)
		}

		result, err := enumerateRunnersForProject(ctx, glPlatform, runnersProject, includeGroup, includeInstance)
		if err != nil {
			return fmt.Errorf("enumerating runners: %w", err)
		}
		results = append(results, result)
	} else if runnersInstance {
		// Instance mode: enumerate instance runners only
		if output == "console" {
			fmt.Fprintf(os.Stderr, "Enumerating instance runners...\n")
		}

		result := &gitlabplatform.RunnersEnumerateResult{}
		instanceRunners, err := glPlatform.Client().ListInstanceRunners(ctx)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("listing instance runners: %v", err))
		} else {
			// Enrich with detailed information
			enriched, _ := glPlatform.Client().EnrichRunnersWithDetails(ctx, instanceRunners)
			result.InstanceRunners = enriched
		}
		result.Summary = gitlabplatform.RunnerSummary{
			Total:    len(result.InstanceRunners),
			Online:   countOnline(result.InstanceRunners),
			Offline:  len(result.InstanceRunners) - countOnline(result.InstanceRunners),
			Instance: len(result.InstanceRunners),
		}
		results = append(results, result)
	}

	// Filter results to show only the requested runner types
	// Each flag indicates which type to include in the output
	for _, result := range results {
		if !includeProject {
			result.ProjectRunners = []gitlabplatform.RunnerInfo{}
		}
		if !includeGroup {
			result.GroupRunners = []gitlabplatform.RunnerInfo{}
		}
		if !includeInstance {
			result.InstanceRunners = []gitlabplatform.RunnerInfo{}
		}
	}

	switch output {
	case "json":
		return outputRunnersJSON(results, runnersOutputFile)
	default:
		return outputRunnersConsole(results, runnersShowGaps)
	}
}

// enumerateRunnersForProject enumerates runners for a single project
func enumerateRunnersForProject(ctx context.Context, platform *gitlabplatform.Platform, projectPath string, includeGroup, includeInstance bool) (*gitlabplatform.RunnersEnumerateResult, error) {
	// Enumerate runners with specified scope flags
	result, err := platform.EnumerateRunners(ctx, projectPath, includeGroup, includeInstance)
	if err != nil {
		return nil, err
	}

	// Enrich runners with detailed information (platform, version, architecture)
	if len(result.ProjectRunners) > 0 {
		enriched, _ := platform.Client().EnrichRunnersWithDetails(ctx, result.ProjectRunners)
		result.ProjectRunners = enriched
	}
	if len(result.GroupRunners) > 0 {
		enriched, _ := platform.Client().EnrichRunnersWithDetails(ctx, result.GroupRunners)
		result.GroupRunners = enriched
	}
	if len(result.InstanceRunners) > 0 {
		enriched, _ := platform.Client().EnrichRunnersWithDetails(ctx, result.InstanceRunners)
		result.InstanceRunners = enriched
	}

	// Get project info for log analysis and workflow tags
	project, err := platform.Client().GetProject(ctx, projectPath)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to get project info: %v", err))
		return result, nil
	}

	// Always analyze pipeline logs for historical runner usage
	// SaaS filtering is handled automatically within AnalyzeProjectLogs
	logRunners, err := platform.AnalyzeProjectLogs(ctx, project.ID, 5)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Pipeline log analysis: %v", err))
	} else {
		result.HistoricalRunners = logRunners
	}

	// If --show-tags is set, analyze workflow tags
	if runnersShowTags {
		// Get .gitlab-ci.yml content from the default branch
		ciContent, err := platform.Client().GetWorkflowFile(ctx, project.ID, ".gitlab-ci.yml", project.DefaultBranch)
		if err != nil {
			// Don't fail the entire enumeration if .gitlab-ci.yml is not found
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to get .gitlab-ci.yml: %v", err))
			return result, nil
		}

		// Combine all runners for analysis
		allRunners := make([]gitlabplatform.RunnerInfo, 0)
		allRunners = append(allRunners, result.ProjectRunners...)
		allRunners = append(allRunners, result.GroupRunners...)
		allRunners = append(allRunners, result.InstanceRunners...)

		// Analyze workflow tags
		tagAnalysis, err := platform.AnalyzeWorkflowTags(ctx, ciContent, allRunners)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to analyze workflow tags: %v", err))
			return result, nil
		}

		result.WorkflowTags = *tagAnalysis
	}

	return result, nil
}

// countOnline counts how many runners are online in the provided slice
func countOnline(runners []gitlabplatform.RunnerInfo) int {
	count := 0
	for _, r := range runners {
		if r.Online {
			count++
		}
	}
	return count
}
