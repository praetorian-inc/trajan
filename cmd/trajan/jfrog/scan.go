package jfrog

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/jfrog"
	jfProbe "github.com/praetorian-inc/trajan/pkg/jfrog/tokenprobe"
	"github.com/praetorian-inc/trajan/pkg/platforms"

	// Blank imports: platform and detection init registration.
	_ "github.com/praetorian-inc/trajan/pkg/platforms/all"

	_ "github.com/praetorian-inc/trajan/pkg/detections/all"
)

var (
	scanSecrets   bool
	scanTokenInfo bool
	jfrogUsername string
	jfrogPassword string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan JFrog Artifactory for secrets and token information",
	Long: `Trajan - JFrog - Scan

Scan JFrog Artifactory instances for secrets and enumerate token capabilities.

JFrog does not support vulnerability scanning of CI/CD pipelines.
Available operations:
  --secrets     Enumerate secrets from artifacts, builds, remote repos, and ML
  --token-info  Display token capabilities and accessible resources

Authentication:
  Tokens can be provided via --token flag or environment variable:
    JFROG_TOKEN
  Or use username/password with -u and -p flags.`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().SortFlags = false
	scanCmd.Flags().BoolVar(&scanSecrets, "secrets", false, "enumerate secrets from artifacts, builds, remote repos, and ML")
	scanCmd.Flags().BoolVar(&scanTokenInfo, "token-info", false, "display token capabilities and accessible resources")
	scanCmd.Flags().StringVarP(&jfrogUsername, "username", "u", "", "username for basic auth")
	scanCmd.Flags().StringVarP(&jfrogPassword, "password", "p", "", "password for basic auth")
}

func runScan(cmd *cobra.Command, args []string) error {
	jfrogURL, _ := cmd.Root().PersistentFlags().GetString("url")
	if jfrogURL == "" {
		// --url may be bound on JFrogCmd rather than on the root.
		jfrogURL, _ = cmd.Parent().PersistentFlags().GetString("url")
	}

	if jfrogURL == "" {
		return fmt.Errorf("--url is required for JFrog operations (e.g., https://acme.jfrog.io)")
	}

	if !scanSecrets && !scanTokenInfo {
		return fmt.Errorf("must specify --secrets or --token-info")
	}

	t := getToken(cmd)

	// JFrog allows username/password authentication without a token
	if t == "" {
		if jfrogUsername != "" && jfrogPassword != "" {
			t = ""
		} else {
			return fmt.Errorf("no authentication provided (use --token/JFROG_TOKEN or --username/-u and --password/-p)")
		}
	}

	verbose := cmdutil.GetVerbose(cmd)
	output := cmdutil.GetOutput(cmd)

	ctx := context.Background()

	platform, err := registry.GetPlatform("jfrog")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	config := platforms.Config{
		Token: t,
		JFrog: &platforms.JFrogAuth{
			Token:    t,
			Username: jfrogUsername,
			Password: jfrogPassword,
		},
		BaseURL: jfrogURL,
	}
	cmdutil.ApplyProxyFlags(cmd, &config)

	if err := platform.Init(ctx, config); err != nil {
		return fmt.Errorf("initializing platform: %w", err)
	}

	return handleJFrogSpecificFeatures(ctx, platform, jfrogURL, verbose, output)
}

func handleJFrogSpecificFeatures(ctx context.Context, platform platforms.Platform, jfrogURL string, verbose bool, output string) error {
	jfPlatform, ok := platform.(*jfrog.Platform)
	if !ok {
		return fmt.Errorf("unexpected platform type")
	}

	if scanTokenInfo {
		return runJFrogTokenInfo(ctx, jfPlatform, jfrogURL, verbose)
	}

	if scanSecrets {
		return runJFrogSecrets(ctx, jfPlatform, jfrogURL, verbose, output)
	}

	return nil
}

func runJFrogTokenInfo(ctx context.Context, platform *jfrog.Platform, jfrogURL string, verbose bool) error {
	if verbose {
		fmt.Fprintf(os.Stderr, "Retrieving JFrog token information...\n")
	}

	client := platform.Client()
	if client == nil {
		return fmt.Errorf("platform client not initialized")
	}

	if err := client.EnsureToken(ctx); err != nil {
		return fmt.Errorf("ensuring access token: %w", err)
	}

	prober := jfProbe.NewProber(client, platform)
	result, err := prober.Probe(ctx)
	if err != nil {
		return fmt.Errorf("probing token: %w", err)
	}

	if !result.Valid {
		fmt.Println("[!] Token is invalid or has no permissions")
		return nil
	}

	fmt.Printf("=== JFrog Token Information ===\n")
	if jfrogURL != "" {
		fmt.Printf("Instance: %s\n\n", jfrogURL)
	}

	if result.User != nil {
		fmt.Printf("User: %s\n", result.User.Name)
		if result.User.Email != "" {
			fmt.Printf("Email: %s\n", result.User.Email)
		}
		if result.IsAdmin {
			fmt.Println("[!] User is an administrator")
		}
		if len(result.User.Groups) > 0 {
			fmt.Printf("Groups: %s\n", strings.Join(result.User.Groups, ", "))
		}
	}

	if result.Version != "" {
		fmt.Printf("\nVersion: %s\n", result.Version)
	}
	if result.License != "" {
		fmt.Printf("License: %s\n", result.License)
	}

	fmt.Println("\nDetected Capabilities:")
	if len(result.Capabilities) == 0 {
		fmt.Println("  (none detected)")
	} else {
		for _, cap := range result.Capabilities {
			fmt.Printf("  - %s\n", cap)
		}
	}

	fmt.Println("\nAccessible Resources:")
	fmt.Printf("  Repositories: %d\n", result.RepositoryCount)
	fmt.Printf("  Builds:       %d\n", result.BuildCount)
	fmt.Printf("  Groups:       %d\n", len(result.Groups))
	fmt.Printf("  Permissions:  %d\n", len(result.Permissions))

	if result.HasHighValueAccess() {
		fmt.Println("\n[!] High-value access detected:")
		if result.IsAdmin {
			fmt.Println("    - Administrator privileges")
		}
		if result.HasRemoteCredentials {
			fmt.Println("    - Remote repository credentials")
		}
		if result.HasBuildSecrets {
			fmt.Println("    - Build secrets detected")
		}
	}

	return nil
}

func runJFrogSecrets(ctx context.Context, platform *jfrog.Platform, jfrogURL string, verbose bool, output string) error {
	if verbose {
		fmt.Fprintf(os.Stderr, "Enumerating JFrog secrets...\n")
	}

	result := &JFrogSecretsResult{
		Instance: jfrogURL,
	}

	artifactSecrets, err := platform.ScanArtifactsForSecrets(ctx, "", "selective")
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "Warning: failed to scan artifact secrets: %v\n", err)
		}
	} else {
		result.ArtifactSecrets = artifactSecrets
		result.TotalSecrets += len(artifactSecrets)
	}

	buildSecrets, err := platform.ScanBuildsForSecrets(ctx, 10)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "Warning: failed to scan build secrets: %v\n", err)
		}
	} else {
		result.BuildSecrets = buildSecrets
		result.TotalSecrets += len(buildSecrets)
	}

	remoteCreds, err := platform.ExtractRemoteRepoCredentials(ctx)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "Warning: failed to extract remote repo credentials: %v\n", err)
		}
	} else {
		result.RemoteRepoCredentials = remoteCreds
		for _, cred := range remoteCreds {
			if cred.HasCreds {
				result.TotalSecrets++
			}
		}
	}

	mlSecrets, err := platform.GetMLSecrets(ctx)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "Warning: failed to get ML secrets: %v\n", err)
		}
	} else {
		result.MLSecrets = mlSecrets
		for _, secret := range mlSecrets {
			if secret.Value != "" {
				result.TotalSecrets++
			}
		}
	}

	switch output {
	case "json":
		return outputJFrogSecretsJSON(result)
	default:
		return outputJFrogSecretsConsole(result)
	}
}

func outputJFrogSecretsJSON(result *JFrogSecretsResult) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func outputJFrogSecretsConsole(result *JFrogSecretsResult) error {
	fmt.Printf("=== JFrog Secrets Enumeration ===\n")
	if result.Instance != "" {
		fmt.Printf("Instance: %s\n\n", result.Instance)
	}

	if len(result.ArtifactSecrets) > 0 {
		fmt.Printf("Artifact Secrets (%d found in artifacts):\n", len(result.ArtifactSecrets))
		for _, secret := range result.ArtifactSecrets {
			fmt.Printf("  - Artifact: %s\n", secret.Artifact)
			if secret.Repo != "" {
				fmt.Printf("    Repo: %s\n", secret.Repo)
			}
			if secret.Path != "" {
				fmt.Printf("    Path: %s\n", secret.Path)
			}
			if len(secret.SecretTypes) > 0 {
				fmt.Printf("    Types: %s\n", strings.Join(secret.SecretTypes, ", "))
			}
			if secret.Value != "" {
				fmt.Printf("    Value: %s\n", secret.Value)
			}
		}
		fmt.Println()
	} else {
		fmt.Printf("Artifact secrets: 0 found\n")
	}

	if len(result.BuildSecrets) > 0 {
		fmt.Printf("Build Secrets (%d found in recent builds):\n", len(result.BuildSecrets))
		for _, secret := range result.BuildSecrets {
			fmt.Printf("  - Build: %s #%s\n", secret.BuildName, secret.BuildNumber)
			fmt.Printf("    EnvVar: %s\n", secret.EnvVar)
			if secret.Value != "" {
				fmt.Printf("    Value: %s\n", secret.Value)
			}
			if len(secret.SecretTypes) > 0 {
				fmt.Printf("    Types: %s\n", strings.Join(secret.SecretTypes, ", "))
			}
		}
		fmt.Println()
	} else {
		fmt.Printf("Build secrets: 0 found\n")
	}

	if len(result.RemoteRepoCredentials) > 0 {
		fmt.Printf("Remote Repository Credentials (%d repositories):\n", len(result.RemoteRepoCredentials))
		for _, cred := range result.RemoteRepoCredentials {
			fmt.Printf("  - Repository: %s\n", cred.Key)
			if cred.URL != "" {
				fmt.Printf("    URL: %s\n", cred.URL)
			}
			if cred.HasCreds {
				fmt.Printf("    [!] Has credentials configured\n")
				if cred.Username != "" {
					fmt.Printf("    Username: %s\n", cred.Username)
				}
			}
		}
		fmt.Println()
	} else {
		fmt.Printf("Remote repository credentials: 0 found\n")
	}

	if len(result.MLSecrets) > 0 {
		fmt.Printf("ML Secrets (%d secrets):\n", len(result.MLSecrets))
		for _, secret := range result.MLSecrets {
			fmt.Printf("  - Name: %s\n", secret.Name)
			if secret.EnvironmentID != "" {
				fmt.Printf("    Environment: %s\n", secret.EnvironmentID)
			}
			if secret.Value != "" {
				fmt.Printf("    Value: %s\n", secret.Value)
			} else if secret.Error != "" {
				fmt.Printf("    Error: %s\n", secret.Error)
			}
		}
		fmt.Println()
	} else {
		fmt.Printf("ML secrets: 0 found\n")
	}

	fmt.Printf("\nTotal secrets found: %d\n", result.TotalSecrets)

	return nil
}

type JFrogSecretsResult struct {
	Instance              string                        `json:"instance"`
	ArtifactSecrets       []jfrog.ArtifactSecret        `json:"artifactSecrets"`
	BuildSecrets          []jfrog.BuildSecret           `json:"buildSecrets"`
	RemoteRepoCredentials []jfrog.RemoteRepoCredentials `json:"remoteRepoCredentials"`
	MLSecrets             []jfrog.JFrogMLSecret         `json:"mlSecrets,omitempty"`
	TotalSecrets          int                           `json:"totalSecrets"`
}
