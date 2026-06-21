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
	"github.com/praetorian-inc/trajan/pkg/jenkins"
	"github.com/praetorian-inc/trajan/pkg/platforms"

	_ "github.com/praetorian-inc/trajan/pkg/platforms/all"
)

var pluginsURL string

var pluginsCmd = &cobra.Command{
	Use:   "plugins",
	Short: "List installed plugins and versions",
	Long: `Trajan - Jenkins - Enumerate

List all installed Jenkins plugins with their version and active/disabled status.
Highlights plugins with available updates.`,
	RunE: runPluginsEnumerate,
}

func init() {
	pluginsCmd.Flags().SortFlags = false
	pluginsCmd.Flags().StringVar(&pluginsURL, "url", "", "Jenkins instance URL")
}

func runPluginsEnumerate(cmd *cobra.Command, args []string) error {
	token := getToken(cmd)
	username := getUsername(cmd)
	output := cmdutil.GetOutput(cmd)

	if pluginsURL == "" {
		return fmt.Errorf("must specify --url")
	}

	ctx := context.Background()

	platform, err := registry.GetPlatform("jenkins")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	config := platforms.Config{
		Token:   token,
		BaseURL: pluginsURL,
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
		fmt.Fprintf(os.Stderr, "Enumerating plugins at %s...\n", pluginsURL)
	}

	plugins, err := client.ListPlugins(ctx)
	if err != nil {
		return fmt.Errorf("listing plugins: %w", err)
	}

	switch output {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(plugins)
	default:
		return outputPluginsConsole(plugins)
	}
}

func outputPluginsConsole(plugins []jenkins.PluginInfo) error {
	fmt.Printf("=== Jenkins Plugins (%d) ===\n\n", len(plugins))

	// Calculate column widths from data
	nameWidth := len("NAME")
	verWidth := len("VERSION")
	for _, p := range plugins {
		name := p.ShortName
		if p.LongName != "" {
			name = p.LongName
		}
		if len(name) > nameWidth {
			nameWidth = len(name)
		}
		if len(p.Version) > verWidth {
			verWidth = len(p.Version)
		}
	}
	// Add padding
	nameWidth += 2
	verWidth += 2

	fmt.Printf("  %-*s %-*s %s\n", nameWidth, "NAME", verWidth, "VERSION", "STATUS")
	fmt.Printf("  %-*s %-*s %s\n", nameWidth, strings.Repeat("-", nameWidth), verWidth, strings.Repeat("-", verWidth), strings.Repeat("-", 10))

	for _, p := range plugins {
		status := "active"
		if !p.Active {
			status = "inactive"
		}
		if !p.Enabled {
			status = "disabled"
		}
		update := ""
		if p.HasUpdate {
			update = " [UPDATE]"
		}

		name := p.ShortName
		if p.LongName != "" {
			name = p.LongName
		}

		fmt.Printf("  %-*s %-*s %s%s\n", nameWidth, name, verWidth, p.Version, status, update)
	}

	return nil
}
