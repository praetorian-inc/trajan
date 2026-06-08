package enumerate

import (
	"context"
	"encoding/json"
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
	tokenOutputFile string
)

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Validate and analyze GitHub token capabilities",
	Long: `Trajan - GitHub - Enumerate

Validate the GitHub token and analyze its capabilities.

This command checks:
  - Token validity and authenticated user
  - Token type (classic PAT, fine-grained PAT, or GITHUB_TOKEN)
  - OAuth scopes (for classic PATs)
  - Token expiration date
  - Accessible organizations
  - Current rate limit status`,
	RunE: runTokenEnumerate,
}

func init() {
	tokenCmd.Flags().SortFlags = false
	tokenCmd.Flags().StringVar(&tokenOutputFile, "output-file", "",
		"save output to file")
}

func runTokenEnumerate(cmd *cobra.Command, args []string) error {
	token := getToken(cmd)
	if token == "" {
		return fmt.Errorf("no token provided (use --token or set GH_TOKEN/GITHUB_TOKEN env var)")
	}

	output := cmdutil.GetOutput(cmd)

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
	if output == "console" {
		fmt.Fprintf(os.Stderr, "Validating token and enumerating organizations...\n")
	}

	// Get token info
	result, err := ghPlatform.EnumerateToken(ctx)
	if err != nil {
		return fmt.Errorf("enumerating token: %w", err)
	}

	// Output results
	switch output {
	case "json":
		return outputTokenJSON(result, tokenOutputFile)
	default:
		return outputTokenConsole(result)
	}
}

func outputTokenJSON(result *github.TokenEnumerateResult, outputFile string) error {
	out := struct {
		TokenInfo   *github.TokenInfo         `json:"token_info,omitempty"`
		Permissions map[string]string         `json:"permissions,omitempty"`
		Orgs        []github.OrganizationInfo `json:"organizations,omitempty"`
		RateLimit   *github.RateLimitInfo     `json:"rate_limit,omitempty"`
		Errors      []string                  `json:"errors,omitempty"`
	}{
		TokenInfo:   result.TokenInfo,
		Permissions: result.Permissions,
		Orgs:        result.Organizations,
		RateLimit:   result.RateLimit,
	}

	for _, err := range result.Errors {
		out.Errors = append(out.Errors, err.Error())
	}

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
	return enc.Encode(out)
}

func outputTokenConsole(result *github.TokenEnumerateResult) error {
	fmt.Printf("=== GitHub Token Information ===\n\n")

	if result.TokenInfo == nil {
		fmt.Println("No token information available")
		if len(result.Errors) > 0 {
			fmt.Printf("\nErrors:\n")
			for _, err := range result.Errors {
				fmt.Printf("  ✗ %s\n", err.Error())
			}
		}
		return nil
	}

	info := result.TokenInfo

	// User information
	if info.User != "" {
		fmt.Printf("User: %s", info.User)
		if info.Name != "" {
			fmt.Printf(" (%s)", info.Name)
		}
		fmt.Println()
	}

	// Token type
	fmt.Printf("Type: %s\n", formatTokenType(info.Type))

	// GitHub App installation tokens have no user identity; show installation scope.
	if info.Type == github.TokenTypeGitHubApp {
		if result.RepositorySelection != "" {
			fmt.Printf("Repository selection: %s\n", result.RepositorySelection)
		}
		fmt.Printf("Accessible repositories: %d\n", result.AccessibleRepos)
	}

	// Scopes (for classic PATs)
	if len(info.Scopes) > 0 {
		fmt.Printf("\nScopes (%d):\n", len(info.Scopes))
		for _, scope := range info.Scopes {
			fmt.Printf("  • %s\n", scope)
		}
	}

	// Expiration
	if info.Expiration != nil {
		fmt.Printf("\nExpiration: %s\n", info.Expiration.Format("2006-01-02 15:04:05 MST"))
	} else if info.Type == github.TokenTypeClassic {
		fmt.Printf("\nExpiration: none (classic PAT - never expires unless revoked)\n")
	}

	// Organizations
	if len(result.Organizations) > 0 {
		fmt.Printf("\nOrganizations (%d):\n", len(result.Organizations))
		for _, org := range result.Organizations {
			roleInfo := ""
			if org.Role != "" {
				roleInfo = fmt.Sprintf(" [%s]", org.Role)
			}
			fmt.Printf("  • %s%s\n", org.Name, roleInfo)
		}
	}

	// Rate limit
	if result.RateLimit != nil {
		fmt.Printf("\nRate Limit: %d/%d remaining\n",
			result.RateLimit.Remaining, result.RateLimit.Limit)
		if !result.RateLimit.Reset.IsZero() {
			fmt.Printf("Resets: %s\n", result.RateLimit.Reset.Format("2006-01-02 15:04:05 MST"))
		}
	}

	// Errors
	if len(result.Errors) > 0 {
		fmt.Printf("\nErrors:\n")
		for _, err := range result.Errors {
			fmt.Printf("  %s\n", err.Error())
		}
	}

	return nil
}

func formatTokenType(tokenType github.TokenType) string {
	switch tokenType {
	case github.TokenTypeClassic:
		return "classic personal access token"
	case github.TokenTypeFineGrained:
		return "fine-grained personal access token"
	case github.TokenTypeGitHubApp:
		return "GitHub App installation token"
	default:
		return "unknown"
	}
}
