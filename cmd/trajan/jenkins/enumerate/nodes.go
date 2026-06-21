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

var nodesURL string

var nodesCmd = &cobra.Command{
	Use:   "nodes",
	Short: "List build agents/nodes",
	Long: `Trajan - Jenkins - Enumerate

List all Jenkins build agents and nodes.

Shows node name, online/offline status, labels, and executor count.`,
	RunE: runNodesEnumerate,
}

func init() {
	nodesCmd.Flags().SortFlags = false
	nodesCmd.Flags().StringVar(&nodesURL, "url", "", "Jenkins instance URL")
}

func runNodesEnumerate(cmd *cobra.Command, args []string) error {
	token := getToken(cmd)
	username := getUsername(cmd)
	output := cmdutil.GetOutput(cmd)

	if nodesURL == "" {
		return fmt.Errorf("must specify --url")
	}

	ctx := context.Background()

	platform, err := registry.GetPlatform("jenkins")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	config := platforms.Config{
		Token:   token,
		BaseURL: nodesURL,
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
		fmt.Fprintf(os.Stderr, "Enumerating nodes at %s...\n", nodesURL)
	}

	nodes, err := client.ListNodes(ctx)
	if err != nil {
		return fmt.Errorf("listing nodes: %w", err)
	}

	switch output {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(nodes)
	default:
		return outputNodesConsole(nodes)
	}
}

func outputNodesConsole(nodes []jenkins.Node) error {
	fmt.Printf("=== Jenkins Nodes (%d) ===\n\n", len(nodes))

	for _, n := range nodes {
		status := "ONLINE"
		if n.Offline {
			status = "OFFLINE"
		}
		if n.TemporarilyOffline {
			status = "TEMP OFFLINE"
		}

		var labels []string
		for _, l := range n.AssignedLabels {
			labels = append(labels, l.Name)
		}
		labelStr := ""
		if len(labels) > 0 {
			labelStr = fmt.Sprintf(" labels=[%s]", strings.Join(labels, ", "))
		}

		fmt.Printf("  %-30s %-12s executors=%d%s\n", n.DisplayName, status, n.NumExecutors, labelStr)
	}

	return nil
}
