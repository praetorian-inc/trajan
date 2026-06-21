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
	projectsGroup      string
	projectsPermission string
	projectsVisibility string
	projectsArchived   bool
	projectsOutputFile string
)

var projectsCmd = &cobra.Command{
	Use:   "projects",
	Short: "Discover accessible projects",
	Long: `Trajan - GitLab CI - Enumerate

Discover accessible GitLab projects within a group or across the instance.
Use --group to scope to a specific group, or omit to list all accessible projects.
Use --permission, --visibility, and --archived to filter results.`,
	RunE: runProjectsEnumerate,
}

func init() {
	projectsCmd.Flags().SortFlags = false
	projectsCmd.Flags().StringVar(&projectsGroup, "group", "", "group to enumerate")
	projectsCmd.Flags().StringVar(&projectsPermission, "permission", "all", "filter by permission: read, write, admin, all")
	projectsCmd.Flags().StringVar(&projectsVisibility, "visibility", "all", "filter by visibility: public, internal, private, all")
	projectsCmd.Flags().BoolVar(&projectsArchived, "archived", false, "include archived projects")
	projectsCmd.Flags().StringVar(&projectsOutputFile, "output-file", "", "save output to file")
}

func runProjectsEnumerate(cmd *cobra.Command, args []string) error {
	token := getToken(cmd)
	if token == "" {
		return fmt.Errorf("no token provided (use --token or set GITLAB_TOKEN/GL_TOKEN env var)")
	}

	output := cmdutil.GetOutput(cmd)

	var target platforms.Target
	if projectsGroup != "" {
		target = platforms.Target{Type: platforms.TargetOrg, Value: projectsGroup}
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

	if output == "console" {
		if projectsGroup != "" {
			fmt.Fprintf(os.Stderr, "Enumerating projects for group %s...\n", projectsGroup)
		} else {
			fmt.Fprintf(os.Stderr, "Enumerating all accessible projects...\n")
		}
	}

	result, err := glPlatform.EnumerateProjects(ctx, target)
	if err != nil {
		return fmt.Errorf("enumerating projects: %w", err)
	}

	// Apply filters
	if len(result.Projects) > 0 {
		if projectsPermission != "all" {
			result.Projects = filterProjectsByPermission(result.Projects, projectsPermission)
		}
		if projectsVisibility != "all" {
			result.Projects = filterProjectsByVisibility(result.Projects, projectsVisibility)
		}
		if !projectsArchived {
			filtered := make([]gitlabplatform.ProjectWithPermissions, 0, len(result.Projects))
			for _, p := range result.Projects {
				if !p.Archived {
					filtered = append(filtered, p)
				}
			}
			result.Projects = filtered
		}
		result.Summary = rebuildProjectsSummary(result.Projects)
	}

	switch output {
	case "json":
		return outputProjectsJSON(result, projectsOutputFile)
	default:
		return outputProjectsConsole(result)
	}
}

// filterProjectsByPermission filters by access level
func filterProjectsByPermission(projects []gitlabplatform.ProjectWithPermissions, perm string) []gitlabplatform.ProjectWithPermissions {
	var filtered []gitlabplatform.ProjectWithPermissions
	for _, p := range projects {
		switch perm {
		case "admin":
			if p.AccessLevel >= 50 { // Owner
				filtered = append(filtered, p)
			}
		case "write":
			if p.AccessLevel >= 30 { // Developer+
				filtered = append(filtered, p)
			}
		case "read":
			if p.AccessLevel > 0 && p.AccessLevel < 30 { // Guest/Reporter
				filtered = append(filtered, p)
			}
		}
	}
	return filtered
}

// filterProjectsByVisibility filters by visibility
func filterProjectsByVisibility(projects []gitlabplatform.ProjectWithPermissions, vis string) []gitlabplatform.ProjectWithPermissions {
	var filtered []gitlabplatform.ProjectWithPermissions
	for _, p := range projects {
		if p.Visibility == vis {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// rebuildProjectsSummary recalculates summary after filtering
func rebuildProjectsSummary(projects []gitlabplatform.ProjectWithPermissions) gitlabplatform.ProjectsSummary {
	s := gitlabplatform.ProjectsSummary{Total: len(projects)}
	for _, p := range projects {
		switch p.Visibility {
		case "private":
			s.Private++
		case "internal":
			s.Internal++
		case "public":
			s.Public++
		}
		if p.Archived {
			s.Archived++
		}
		if p.AccessLevel >= 30 {
			s.WriteAccess++
		} else if p.AccessLevel > 0 {
			s.ReadAccess++
		}
	}
	return s
}
