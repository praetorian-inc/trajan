package enumerate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/bitbucket"
	"github.com/praetorian-inc/trajan/pkg/platforms"

	_ "github.com/praetorian-inc/trajan/pkg/platforms/all"
)

var tokenOutputFile string

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Validate and analyze Bitbucket token capabilities",
	Long: `Trajan - Bitbucket - Enumerate Token

Validate the Bitbucket token and analyze its capabilities.

This command checks:
  - Token validity and type (workspace/project/repo access token or API token)
  - OAuth scopes and permissions
  - User identity (for API tokens)
  - Rate limit status`,
	RunE: runTokenEnumerate,
}

func init() {
	tokenCmd.Flags().SortFlags = false
	tokenCmd.Flags().StringVar(&tokenOutputFile, "output-file", "", "save output to file")
}

func runTokenEnumerate(cmd *cobra.Command, args []string) error {
	token := getToken(cmd)
	if token == "" {
		return fmt.Errorf("no token provided (use --token or set BITBUCKET_TOKEN/BB_TOKEN env var)")
	}

	email := getEmail(cmd)

	// Validate: ATATT3x token without email
	if strings.HasPrefix(token, "ATATT3x") && email == "" {
		return fmt.Errorf("--email is required for API token auth (use --email or set BITBUCKET_EMAIL/BB_EMAIL env var)")
	}

	// Warn: access token with email provided
	if strings.HasPrefix(token, "ATCTT3x") && email != "" {
		fmt.Fprintf(os.Stderr, "Warning: email ignored for access tokens (Bearer auth used)\n")
	}

	output := cmdutil.GetOutput(cmd)
	ctx := context.Background()

	// Initialize platform
	platform, err := registry.GetPlatform("bitbucket")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	config := platforms.Config{
		Token: token,
		Bitbucket: &platforms.BitbucketAuth{
			Token: token,
			Email: email,
		},
	}
	cmdutil.ApplyProxyFlags(cmd, &config)

	if err := platform.Init(ctx, config); err != nil {
		return fmt.Errorf("initializing platform: %w", err)
	}

	bbPlatform, ok := platform.(*bitbucket.Platform)
	if !ok {
		return fmt.Errorf("unexpected platform type")
	}

	if output == "console" {
		fmt.Fprintf(os.Stderr, "Validating token...\n\n")
	}

	result, err := bbPlatform.EnumerateToken(ctx)
	if err != nil {
		return fmt.Errorf("enumerating token: %w", err)
	}

	switch output {
	case "json":
		return outputTokenJSON(result, tokenOutputFile)
	default:
		return outputTokenConsole(result)
	}
}

func outputTokenJSON(result *bitbucket.TokenEnumerateResult, outputFile string) error {
	enc := json.NewEncoder(os.Stdout)
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		enc = json.NewEncoder(f)
	}

	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func outputTokenConsole(result *bitbucket.TokenEnumerateResult) error {
	fmt.Printf("=== Bitbucket Token Information ===\n\n")

	if result.TokenInfo == nil {
		fmt.Println("No token information available")
		if len(result.Errors) > 0 {
			fmt.Printf("\nErrors:\n")
			for _, e := range result.Errors {
				fmt.Printf("  • %s\n", e)
			}
		}
		return nil
	}

	info := result.TokenInfo

	// User info (API tokens only)
	if result.User != nil {
		fmt.Printf("User: %s", result.User.Username)
		if result.User.DisplayName != "" {
			fmt.Printf(" (%s)", result.User.DisplayName)
		}
		fmt.Println()
		if result.User.AccountID != "" {
			fmt.Printf("Account: %s\n", result.User.AccountID)
		}
		if result.User.AccountStatus != "" {
			fmt.Printf("Status: %s\n", result.User.AccountStatus)
		}
		fmt.Println()
	}

	// Token type
	fmt.Printf("Type: %s\n", formatTokenType(info.Type))

	// Scopes
	if info.Scopes != nil && len(info.RawScopes) > 0 {
		fmt.Printf("\nScopes (%d):\n", len(info.RawScopes))
		if info.Scopes.Format() == bitbucket.ScopeFormatFineGrained {
			// Grouped display for fine-grained (API token) scopes
			outputFineGrainedScopes(info.Scopes)
		} else {
			// Bullet list with implication annotations for legacy (access token) scopes
			for _, scope := range info.RawScopes {
				annotation := legacyScopeAnnotations[scope]
				if annotation != "" {
					fmt.Printf("  • %s (%s)\n", scope, annotation)
				} else {
					fmt.Printf("  • %s\n", scope)
				}
			}
		}
	}

	// Note for API tokens
	if info.Type == bitbucket.TokenTypeAPIToken {
		fmt.Printf("\nNote: Scopes show maximum token permissions.\n")
		fmt.Printf("Actual access depends on user's workspace and repository roles.\n")
	}

	// Rate limit
	if result.RateLimit != nil && result.RateLimit.Limit > 0 {
		nearLimit := "no"
		if result.RateLimit.NearLimit {
			nearLimit = "yes"
		}
		fmt.Printf("\nRate Limit: %d (near limit: %s)\n", result.RateLimit.Limit, nearLimit)
	}

	// Errors
	if len(result.Errors) > 0 {
		fmt.Printf("\nErrors:\n")
		for _, e := range result.Errors {
			fmt.Printf("  • %s\n", e)
		}
	}

	return nil
}

// legacyScopeAnnotations maps scopes to their human-readable annotation text.
// Bare scope names (e.g., "project") mean read-level access, so we annotate them.
var legacyScopeAnnotations = map[string]string{
	"account":           "read",
	"project":           "read; implies repository:read",
	"project:admin":     "",
	"repository":        "read",
	"repository:write":  "implies repository:read",
	"repository:admin":  "",
	"repository:delete": "",
	"pullrequest":       "read; implies repository:read",
	"pullrequest:write": "implies pullrequest:read, repository:write, repository:read",
	"webhook":           "read+write",
	"pipeline":          "read",
	"pipeline:write":    "implies pipeline:read",
	"pipeline:variable": "implies pipeline:write, pipeline:read",
	"runner":            "read",
	"runner:write":      "implies runner:read",
	"test":              "read",
	"test:write":        "implies test:read",
}

// categoryDisplayNames maps scope categories to human-readable display names.
var categoryDisplayNames = map[string]string{
	"repository":  "Repositories",
	"pullrequest": "Pull Requests",
	"project":     "Projects",
	"workspace":   "Workspaces",
	"pipeline":    "Pipelines",
	"runner":      "Runners",
	"test":        "Tests",
	"issue":       "Issues",
	"webhook":     "Webhooks",
	"snippet":     "Snippets",
	"wiki":        "Wikis",
	"ssh-key":     "SSH Keys",
	"gpg-key":     "GPG Keys",
	"permission":  "Permissions",
	"user":        "Users",
	"package":     "Packages",
}

func outputFineGrainedScopes(scopes *bitbucket.Scopes) {
	for _, category := range scopes.Categories() {
		levels := scopes.Levels(category)
		levelStrs := make([]string, len(levels))
		for i, l := range levels {
			levelStrs[i] = string(l)
		}
		displayName := categoryDisplayNames[category]
		if displayName == "" {
			displayName = category
		}
		fmt.Printf("  %-15s %s\n", displayName+":", strings.Join(levelStrs, ", "))
	}
}

func formatTokenType(t bitbucket.TokenType) string {
	switch t {
	case bitbucket.TokenTypeWorkspace:
		return "Workspace Access Token"
	case bitbucket.TokenTypeProject:
		return "Project Access Token"
	case bitbucket.TokenTypeRepo:
		return "Repository Access Token"
	case bitbucket.TokenTypeAPIToken:
		return "Personal API Token"
	default:
		return "Unknown"
	}
}
