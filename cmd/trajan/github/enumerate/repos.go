package enumerate

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/github"
	"github.com/praetorian-inc/trajan/pkg/platforms"

	// Import to trigger platform registration
	_ "github.com/praetorian-inc/trajan/pkg/platforms/all"
)

var (
	reposOrg        string
	reposPermission string
	reposVisibility string
	reposArchived   bool
	reposOutputFile string
)

var reposCmd = &cobra.Command{
	Use:   "repos",
	Short: "Discover accessible repositories",
	Long: `Trajan - GitHub - Enumerate

Discover accessible repositories for a user or organization.
Lists repos with metadata including visibility, permissions, and fork status.
Filter results by permission level (read, write, admin) or visibility (public, private).`,
	RunE: runReposEnumerate,
}

func init() {
	reposCmd.Flags().SortFlags = false
	reposCmd.Flags().StringVar(&reposOrg, "org", "", "organization to enumerate")
	reposCmd.Flags().StringVar(&reposPermission, "permission", "all", "filter by permission: read, write, admin, all")
	reposCmd.Flags().StringVar(&reposVisibility, "visibility", "all", "filter by visibility: public, private, all")
	reposCmd.Flags().BoolVar(&reposArchived, "archived", false, "include archived repositories")
	reposCmd.Flags().StringVar(&reposOutputFile, "output-file", "", "save output to file")
}

func runReposEnumerate(cmd *cobra.Command, args []string) error {
	token := getToken(cmd)
	if token == "" {
		return fmt.Errorf("no token provided (use --token or set GH_TOKEN/GITHUB_TOKEN env var)")
	}

	output := cmdutil.GetOutput(cmd)

	// Determine target
	var target platforms.Target
	if reposOrg != "" {
		target = platforms.Target{Type: platforms.TargetOrg, Value: reposOrg}
	} else {
		// Default: authenticated user's repos (empty value signals authenticated user)
		target = platforms.Target{Type: platforms.TargetUser, Value: ""}
	}

	ctx := context.Background()

	// Initialize GitHub platform
	platform, err := registry.GetPlatform("github")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	config := platforms.Config{
		Token: token,
	}
	if url := getURL(cmd); url != "" {
		config.BaseURL = url
	}
	cmdutil.ApplyProxyFlags(cmd, &config)

	if err := platform.Init(ctx, config); err != nil {
		return fmt.Errorf("initializing platform: %w", err)
	}

	ghPlatform, ok := platform.(*github.Platform)
	if !ok {
		return fmt.Errorf("unexpected platform type")
	}

	// Show progress to user
	verbose := cmdutil.GetVerbose(cmd)
	if verbose || output == "console" {
		switch target.Type {
		case platforms.TargetOrg:
			fmt.Fprintf(os.Stderr, "Enumerating repositories for organization %s...\n", target.Value)
		case platforms.TargetUser:
			if target.Value == "" {
				fmt.Fprintf(os.Stderr, "Enumerating all accessible repositories...\n")
			} else {
				fmt.Fprintf(os.Stderr, "Enumerating repositories for user %s...\n", target.Value)
			}
		}
	}

	// Enumerate repositories
	result, err := ghPlatform.EnumerateRepos(ctx, target)
	if err != nil {
		return fmt.Errorf("enumerating repos: %w", err)
	}

	// Apply filters if repositories were found
	if len(result.Repositories) > 0 {
		// Apply permission filter
		if reposPermission != "all" {
			result.Repositories = filterByPermission(result.Repositories, reposPermission)
		}

		// Apply visibility filter
		if reposVisibility != "all" {
			result.Repositories = filterByVisibility(result.Repositories, reposVisibility)
		}

		// Filter archived if not requested
		if !reposArchived {
			filtered := make([]github.RepositoryWithPermissions, 0, len(result.Repositories))
			for _, repo := range result.Repositories {
				if !repo.Repository.Archived {
					filtered = append(filtered, repo)
				}
			}
			result.Repositories = filtered
		}

		// Recalculate summary after ALL filtering
		result.Summary = buildReposSummary(result.Repositories)
	}

	// Output results
	switch output {
	case "json":
		return outputReposJSON(result, reposOutputFile)
	default:
		return outputReposConsole(result)
	}
}

// outputReposConsole outputs repository enumeration in console format
func outputReposConsole(result *github.ReposEnumerateResult) error {
	fmt.Printf("=== Repository Enumeration ===\n\n")

	if len(result.Repositories) == 0 {
		fmt.Println("No repositories found")
		return nil
	}

	fmt.Printf("Total: %d repositories (%d private, %d public)\n",
		result.Summary.Total,
		result.Summary.Private,
		result.Summary.Public)

	if result.Summary.Archived > 0 {
		fmt.Printf("Archived: %d repositories\n", result.Summary.Archived)
	}

	// Separate repos by permission level (Admin > Write > Read > unknown)
	var adminRepos, writeRepos, readRepos, otherRepos []github.RepositoryWithPermissions
	for _, repo := range result.Repositories {
		switch {
		case repo.Permissions.Admin:
			adminRepos = append(adminRepos, repo)
		case repo.Permissions.Push:
			writeRepos = append(writeRepos, repo)
		case repo.Permissions.Pull:
			readRepos = append(readRepos, repo)
		default:
			otherRepos = append(otherRepos, repo)
		}
	}

	// Print admin access repos
	if len(adminRepos) > 0 {
		fmt.Printf("\nAdmin Access (%d repositories):\n", len(adminRepos))
		for _, repo := range adminRepos {
			visibility := "public"
			if repo.Repository.Private {
				visibility = "private"
			}
			fmt.Printf("  • %s/%s [%s, %s]\n",
				repo.Repository.Owner, repo.Repository.Name, visibility, repo.Repository.DefaultBranch)
		}
	}

	// Print write access repos (Push but not Admin)
	if len(writeRepos) > 0 {
		fmt.Printf("\nWrite Access (%d repositories):\n", len(writeRepos))
		for _, repo := range writeRepos {
			visibility := "public"
			if repo.Repository.Private {
				visibility = "private"
			}
			fmt.Printf("  • %s/%s [%s, %s]\n",
				repo.Repository.Owner, repo.Repository.Name, visibility, repo.Repository.DefaultBranch)
		}
	}

	// Print read access repos (Pull only)
	if len(readRepos) > 0 {
		fmt.Printf("\nRead Access (%d repositories):\n", len(readRepos))
		for _, repo := range readRepos {
			visibility := "public"
			if repo.Repository.Private {
				visibility = "private"
			}
			fmt.Printf("  • %s/%s [%s, %s]\n",
				repo.Repository.Owner, repo.Repository.Name, visibility, repo.Repository.DefaultBranch)
		}
	}

	// Repos with no reported permission bits — common for GitHub App installation
	// tokens, whose list endpoint does not return reliable push/pull metadata.
	if len(otherRepos) > 0 {
		fmt.Printf("\nAccessible Repositories (%d) [permissions not reported]:\n", len(otherRepos))
		for _, repo := range otherRepos {
			visibility := "public"
			if repo.Repository.Private {
				visibility = "private"
			}
			fmt.Printf("  \u2022 %s/%s [%s, %s]\n",
				repo.Repository.Owner, repo.Repository.Name, visibility, repo.Repository.DefaultBranch)
		}
	}

	return nil
}

// filterByPermission filters repositories by permission level
func filterByPermission(repos []github.RepositoryWithPermissions, permission string) []github.RepositoryWithPermissions {
	if permission == "all" {
		return repos
	}

	var filtered []github.RepositoryWithPermissions
	for _, repo := range repos {
		switch permission {
		case "admin":
			if repo.Permissions.Admin {
				filtered = append(filtered, repo)
			}
		case "write":
			if repo.Permissions.Push || repo.Permissions.Admin {
				filtered = append(filtered, repo)
			}
		case "read":
			if repo.Permissions.Pull && !repo.Permissions.Push && !repo.Permissions.Admin {
				filtered = append(filtered, repo)
			}
		}
	}
	return filtered
}

// filterByVisibility filters repositories by visibility (public/private)
func filterByVisibility(repos []github.RepositoryWithPermissions, visibility string) []github.RepositoryWithPermissions {
	if visibility == "all" {
		return repos
	}

	var filtered []github.RepositoryWithPermissions
	for _, repo := range repos {
		switch visibility {
		case "private":
			if repo.Repository.Private {
				filtered = append(filtered, repo)
			}
		case "public":
			if !repo.Repository.Private {
				filtered = append(filtered, repo)
			}
		}
	}
	return filtered
}

// buildReposSummary generates summary statistics from repository list
func buildReposSummary(repos []github.RepositoryWithPermissions) github.ReposSummary {
	summary := github.ReposSummary{
		Total: len(repos),
	}

	for _, repo := range repos {
		if repo.Repository.Private {
			summary.Private++
		} else {
			summary.Public++
		}

		if repo.Repository.Archived {
			summary.Archived++
		}

		if repo.Permissions.Push || repo.Permissions.Admin {
			summary.WriteAccess++
		} else if repo.Permissions.Pull {
			summary.ReadAccess++
		}
	}

	return summary
}
