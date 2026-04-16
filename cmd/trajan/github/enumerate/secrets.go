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

	_ "github.com/praetorian-inc/trajan/pkg/platforms/all"
)

var (
	secretsRepo       string
	secretsOrg        string
	secretsOutputFile string
)

var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Enumerate repository and organization secrets",
	Long: `Trajan - GitHub - Enumerate

Enumerate secrets accessible at repository and organization level.

This command enumerates:
  - Actions secrets (repo-level and org-level)
  - Environment secrets (deployment-specific)
  - Organization secrets accessible to repositories
  - Workflow-referenced secrets (parsed from YAML)

Note: Secret values cannot be retrieved via API (only names and metadata).`,
	RunE: runSecretsEnumerate,
}

func init() {
	secretsCmd.Flags().SortFlags = false
	secretsCmd.Flags().StringVar(&secretsRepo, "repo", "", "repository to enumerate (owner/repo)")
	secretsCmd.Flags().StringVar(&secretsOrg, "org", "", "organization to enumerate")
	secretsCmd.Flags().StringVar(&secretsOutputFile, "output-file", "", "save output to file")
}

func runSecretsEnumerate(cmd *cobra.Command, args []string) error {
	token := getToken(cmd)
	if token == "" {
		return fmt.Errorf("no token provided (use --token or set GH_TOKEN/GITHUB_TOKEN env var)")
	}

	output := cmdutil.GetOutput(cmd)

	// Determine target
	var target platforms.Target
	switch {
	case secretsRepo != "":
		target = platforms.Target{Type: platforms.TargetRepo, Value: secretsRepo}
	case secretsOrg != "":
		target = platforms.Target{Type: platforms.TargetOrg, Value: secretsOrg}
	default:
		return fmt.Errorf("must specify --repo or --org")
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
		case platforms.TargetRepo:
			fmt.Fprintf(os.Stderr, "Enumerating secrets for repository %s...\n", target.Value)
		case platforms.TargetOrg:
			fmt.Fprintf(os.Stderr, "Enumerating secrets for organization %s...\n", target.Value)
		}
	}

	// Enumerate secrets (reuses existing ScanSecrets implementation)
	result, err := ghPlatform.ScanSecrets(ctx, target)
	if err != nil {
		return fmt.Errorf("enumerating secrets: %w", err)
	}

	// Output results
	switch output {
	case "json":
		return outputSecretsJSON(result, secretsOutputFile)
	default:
		return outputSecretsConsole(result)
	}
}

// outputSecretsConsole outputs secrets enumeration in console format
func outputSecretsConsole(result *github.SecretsResult) error {
	fmt.Printf("=== Secrets Enumeration ===\n\n")

	counts := countSecrets(result)

	if counts.Total == 0 {
		fmt.Println("No secrets found")
		if len(result.PermissionErrors) > 0 {
			fmt.Printf("\nPermission Errors (%d):\n", len(result.PermissionErrors))
			for _, errMsg := range result.PermissionErrors {
				fmt.Printf("  %s\n", errMsg)
			}
		}
		return nil
	}

	fmt.Printf("Total: %d secrets\n", counts.Total)

	// Actions secrets
	if counts.Actions > 0 {
		fmt.Printf("\nActions Secrets (%d):\n", counts.Actions)
		for scope, secrets := range result.ActionsSecrets {
			if len(secrets) > 0 {
				fmt.Printf("  %s:\n", scope)
				for _, secret := range secrets {
					created := ""
					if !secret.CreatedAt.IsZero() {
						created = fmt.Sprintf(" (created: %s)", secret.CreatedAt.Format("2006-01-02"))
					}
					fmt.Printf("    • %s%s\n", secret.Name, created)
				}
			}
		}
	} else if counts.Workflow > 0 {
		// If we have workflow secrets but no Actions secrets, mention permission requirements
		fmt.Printf("\nActions Secrets (0):\n")
		fmt.Printf("  Note: Org-level Actions secrets require admin:org scope\n")
		fmt.Printf("  Showing workflow-referenced secrets below\n")
	}

	// Dependabot secrets
	if counts.Dependabot > 0 {
		fmt.Printf("\nDependabot Secrets (%d):\n", counts.Dependabot)
		for scope, secrets := range result.DependabotSecrets {
			if len(secrets) > 0 {
				fmt.Printf("  %s:\n", scope)
				for _, secret := range secrets {
					created := ""
					if !secret.CreatedAt.IsZero() {
						created = fmt.Sprintf(" (created: %s)", secret.CreatedAt.Format("2006-01-02"))
					}
					fmt.Printf("    • %s%s\n", secret.Name, created)
				}
			}
		}
	}

	// Codespaces secrets
	if counts.Codespaces > 0 {
		fmt.Printf("\nCodespaces Secrets (%d):\n", counts.Codespaces)
		for scope, secrets := range result.CodespacesSecrets {
			if len(secrets) > 0 {
				fmt.Printf("  %s:\n", scope)
				for _, secret := range secrets {
					created := ""
					if !secret.CreatedAt.IsZero() {
						created = fmt.Sprintf(" (created: %s)", secret.CreatedAt.Format("2006-01-02"))
					}
					fmt.Printf("    • %s%s\n", secret.Name, created)
				}
			}
		}
	}

	// Workflow secrets
	if counts.Workflow > 0 {
		fmt.Printf("\nWorkflow Secrets (%d):\n", counts.Workflow)
		for scope, secrets := range result.WorkflowSecrets {
			if len(secrets) > 0 {
				fmt.Printf("  %s:\n", scope)
				for _, secret := range secrets {
					fmt.Printf("    • %s\n", secret.Name)
				}
			}
		}
	}

	// Permission errors
	if len(result.PermissionErrors) > 0 {
		fmt.Printf("\nPermission Errors (%d):\n", len(result.PermissionErrors))
		for _, errMsg := range result.PermissionErrors {
			fmt.Printf("  %s\n", errMsg)
		}
	}

	// General errors
	if len(result.Errors) > 0 {
		fmt.Printf("\nErrors (%d):\n", len(result.Errors))
		for _, err := range result.Errors {
			fmt.Printf("  %s\n", err.Error())
		}
	}

	fmt.Printf("\nNote: Secret values are not retrievable via API\n")

	return nil
}

// SecretCounts holds counts for each secret type
type SecretCounts struct {
	Actions    int
	Dependabot int
	Codespaces int
	Workflow   int
	Total      int
}

// countSecrets counts secrets across all types
func countSecrets(result *github.SecretsResult) SecretCounts {
	counts := SecretCounts{}

	for _, secrets := range result.ActionsSecrets {
		counts.Actions += len(secrets)
	}
	for _, secrets := range result.DependabotSecrets {
		counts.Dependabot += len(secrets)
	}
	for _, secrets := range result.CodespacesSecrets {
		counts.Codespaces += len(secrets)
	}
	for _, secrets := range result.WorkflowSecrets {
		counts.Workflow += len(secrets)
	}

	counts.Total = counts.Actions + counts.Dependabot + counts.Codespaces + counts.Workflow

	return counts
}
