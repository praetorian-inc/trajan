package enumerate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/jenkins"
	"github.com/praetorian-inc/trajan/pkg/platforms"

	_ "github.com/praetorian-inc/trajan/pkg/platforms/all"
)

var accessURL string

var accessCmd = &cobra.Command{
	Use:   "access",
	Short: "Probe access level and server info",
	Long: `Trajan - Jenkins - Enumerate

Check authenticated user identity, group memberships, server version,
security configuration, and script console accessibility.`,
	RunE: runAccessEnumerate,
}

func init() {
	accessCmd.Flags().SortFlags = false
	accessCmd.Flags().StringVar(&accessURL, "url", "", "Jenkins instance URL")
}

func runAccessEnumerate(cmd *cobra.Command, args []string) error {
	token := getToken(cmd)
	username := getUsername(cmd)
	output := cmdutil.GetOutput(cmd)

	if accessURL == "" {
		return fmt.Errorf("must specify --url")
	}

	ctx := context.Background()

	platform, err := registry.GetPlatform("jenkins")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	config := platforms.Config{
		Token:   token,
		BaseURL: accessURL,
		Jenkins: &platforms.JenkinsAuth{Username: username},
	}
	cmdutil.ApplyProxyFlags(cmd, &config)

	if err := platform.Init(ctx, config); err != nil {
		return fmt.Errorf("initializing platform: %w", err)
	}

	jPlatform, ok := platform.(*jenkins.Platform)
	if !ok {
		return fmt.Errorf("unexpected platform type %T", platform)
	}
	client := jPlatform.Client()

	if output == "console" || output == "" {
		fmt.Fprintf(os.Stderr, "Probing Jenkins at %s...\n", accessURL)
	}

	serverInfo, serverErr := client.GetServerInfo(ctx)
	whoAmI, whoErr := client.GetWhoAmI(ctx)
	scriptAccess, scriptStatus, scriptErr := client.CheckScriptConsole(ctx)

	switch output {
	case "json":
		return outputAccessJSON(serverInfo, whoAmI, scriptAccess, scriptStatus, serverErr, whoErr, scriptErr)
	default:
		return outputAccessConsole(serverInfo, whoAmI, scriptAccess, scriptStatus, serverErr, whoErr, scriptErr)
	}
}

func outputAccessConsole(serverInfo *jenkins.ServerInfo, whoAmI *jenkins.WhoAmI, scriptAccess bool, scriptStatus int, serverErr, whoErr, scriptErr error) error {
	fmt.Printf("=== Jenkins Access Enumeration ===\n\n")

	if serverErr != nil {
		fmt.Printf("Server Info: ERROR - %v\n", serverErr)
	} else {
		fmt.Printf("Version: %s\n", serverInfo.Version)
		fmt.Printf("Mode: %s\n", serverInfo.Mode)
		fmt.Printf("Security Enabled: %v\n", serverInfo.UseSecurity)
		fmt.Printf("CSRF Protection: %v\n", serverInfo.UseCrumbs)
	}
	fmt.Println()

	if whoErr != nil {
		fmt.Printf("User Info: ERROR - %v\n", whoErr)
	} else {
		if whoAmI.Anonymous {
			fmt.Printf("User: anonymous\n")
		} else {
			fmt.Printf("User: %s\n", whoAmI.Name)
		}
		if len(whoAmI.Authorities) > 0 {
			fmt.Printf("Groups/Authorities:\n")
			for _, auth := range whoAmI.Authorities {
				fmt.Printf("  - %s\n", auth)
			}
		}
	}
	fmt.Println()

	if scriptErr != nil {
		fmt.Printf("Script Console: ERROR - %v\n", scriptErr)
	} else if scriptAccess {
		fmt.Printf("Script Console: ACCESSIBLE (status %d)\n", scriptStatus)
	} else {
		fmt.Printf("Script Console: NOT ACCESSIBLE (status %d)\n", scriptStatus)
	}

	return nil
}

func outputAccessJSON(serverInfo *jenkins.ServerInfo, whoAmI *jenkins.WhoAmI, scriptAccess bool, scriptStatus int, serverErr, whoErr, scriptErr error) error {
	out := map[string]interface{}{
		"script_console": map[string]interface{}{
			"accessible":  scriptAccess,
			"status_code": scriptStatus,
		},
	}
	if serverInfo != nil {
		out["server"] = serverInfo
	}
	if whoAmI != nil {
		out["user"] = whoAmI
	}

	var errors []string
	if serverErr != nil {
		errors = append(errors, "server: "+serverErr.Error())
	}
	if whoErr != nil {
		errors = append(errors, "whoami: "+whoErr.Error())
	}
	if scriptErr != nil {
		errors = append(errors, "script: "+scriptErr.Error())
	}
	if len(errors) > 0 {
		out["errors"] = errors
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
