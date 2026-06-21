package enumerate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/output"
)

var listAgentPoolsShowAgents bool

func newAgentPoolsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent-pools",
		Short: "List agent pools",
		Long: `Trajan - Azure DevOps - Enumerate

List all agent pools in the organization. Includes both Microsoft-hosted and self-hosted pools.
Shows pool ID, name, type, size, and auto-provisioning status.
Includes a security analysis flagging self-hosted pools and auto-provisioned pools.

Use --show-agents to enumerate individual agents within each self-hosted pool,
including their status, OS, and version information.`,
		RunE: runListAgentPools,
	}

	cmd.Flags().SortFlags = false
	cmd.Flags().BoolVar(&listAgentPoolsShowAgents, "show-agents", false,
		"enumerate individual agents within self-hosted pools")

	return cmd
}

func runListAgentPools(cmd *cobra.Command, args []string) error {
	switch enumPlatform {
	case "azuredevops":
		return runListAgentPoolsAzDO()
	default:
		return fmt.Errorf("not supported for platform: %s", enumPlatform)
	}
}

// agentPoolWithAgents wraps an AgentPool with its agents for JSON output
type agentPoolWithAgents struct {
	azuredevops.AgentPool
	Agents []azuredevops.Agent `json:"agents,omitempty"`
}

func runListAgentPoolsAzDO() error {
	if enumOrg == "" {
		return fmt.Errorf("--org is required for Azure DevOps")
	}
	ctx := context.Background()
	orgURL := fmt.Sprintf("https://dev.azure.com/%s", enumOrg)
	client, err := NewEnumerateClient(orgURL, GetTokenForPlatform("azuredevops"))
	if err != nil {
		return err
	}

	pools, err := client.ListAgentPools(ctx)
	if err != nil {
		return err
	}

	// Enumerate agents within self-hosted pools if --agents flag is set
	var agentsByPool map[int][]azuredevops.Agent
	if listAgentPoolsShowAgents {
		agentsByPool = make(map[int][]azuredevops.Agent)
		for _, pool := range pools {
			if pool.IsHosted {
				continue
			}
			agents, err := client.ListAgents(ctx, pool.ID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to list agents for pool '%s' (ID %d): %v\n", pool.Name, pool.ID, err)
				continue
			}
			agentsByPool[pool.ID] = agents
		}
	}

	switch enumOutput {
	case "json":
		return renderAgentPoolsJSON(pools, agentsByPool)
	case "csv":
		return renderAgentPoolsCSV(pools, agentsByPool)
	default:
		return renderAgentPoolsConsole(pools, agentsByPool)
	}
}

func renderAgentPoolsJSON(pools []azuredevops.AgentPool, agentsByPool map[int][]azuredevops.Agent) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	if agentsByPool == nil {
		return enc.Encode(pools)
	}

	// Wrap pools with their agents
	wrapped := make([]agentPoolWithAgents, len(pools))
	for i, pool := range pools {
		wrapped[i] = agentPoolWithAgents{
			AgentPool: pool,
			Agents:    agentsByPool[pool.ID],
		}
	}
	return enc.Encode(wrapped)
}

func renderAgentPoolsCSV(pools []azuredevops.AgentPool, agentsByPool map[int][]azuredevops.Agent) error {
	if agentsByPool == nil {
		// Original CSV format
		headers := []string{"ID", "Name", "Hosted", "Pool Type", "Size", "Auto Provision"}
		rows := make([][]string, len(pools))
		for i, pool := range pools {
			hosted := "no"
			if pool.IsHosted {
				hosted = "yes"
			}
			autoProv := "no"
			if pool.AutoProvision {
				autoProv = "yes"
			}
			rows[i] = []string{fmt.Sprintf("%d", pool.ID), pool.Name, hosted, pool.PoolType, fmt.Sprintf("%d", pool.Size), autoProv}
		}
		return output.RenderCSV(os.Stdout, headers, rows)
	}

	// Extended CSV with agent details
	headers := []string{"Pool ID", "Pool Name", "Hosted", "Pool Type", "Size", "Auto Provision", "Agent Name", "Agent Status", "Agent OS", "Agent Version"}
	var rows [][]string
	for _, pool := range pools {
		hosted := "no"
		if pool.IsHosted {
			hosted = "yes"
		}
		autoProv := "no"
		if pool.AutoProvision {
			autoProv = "yes"
		}
		agents := agentsByPool[pool.ID]
		if len(agents) == 0 {
			// Pool row with no agents
			rows = append(rows, []string{
				fmt.Sprintf("%d", pool.ID), pool.Name, hosted, pool.PoolType, fmt.Sprintf("%d", pool.Size), autoProv,
				"", "", "", "",
			})
			continue
		}
		for _, agent := range agents {
			rows = append(rows, []string{
				fmt.Sprintf("%d", pool.ID), pool.Name, hosted, pool.PoolType, fmt.Sprintf("%d", pool.Size), autoProv,
				agent.Name, agent.Status, agent.OSDescription, agent.Version,
			})
		}
	}
	return output.RenderCSV(os.Stdout, headers, rows)
}

func renderAgentPoolsConsole(pools []azuredevops.AgentPool, agentsByPool map[int][]azuredevops.Agent) error {
	if len(pools) == 0 {
		fmt.Println("No agent pools found")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tHOSTED\tPOOL TYPE\tSIZE\tAUTO PROVISION")
	for _, pool := range pools {
		hosted := "no"
		if pool.IsHosted {
			hosted = "yes"
		}
		autoProv := "no"
		if pool.AutoProvision {
			autoProv = "yes"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%s\n", pool.ID, pool.Name, hosted, pool.PoolType, pool.Size, autoProv)
	}
	_ = w.Flush()

	// Print agent details under self-hosted pools
	if agentsByPool != nil {
		for _, pool := range pools {
			if pool.IsHosted {
				continue
			}
			agents := agentsByPool[pool.ID]
			fmt.Printf("\n  Agents in '%s' (%d):\n", pool.Name, len(agents))
			if len(agents) == 0 {
				fmt.Println("    (none)")
				continue
			}
			for _, agent := range agents {
				suffix := ""
				if !agent.Enabled {
					suffix = " [disabled]"
				}
				fmt.Printf("    * %s [%s] %s - %s%s\n", agent.Name, agent.Status, agent.OSDescription, agent.Version, suffix)
			}
		}
	}

	fmt.Printf("\nTotal: %d agent pools\n", len(pools))

	// Security analysis
	analysis := analyzeAgentPoolsSecurity(pools, agentsByPool)
	if analysis != "" {
		fmt.Printf("\n%s\n", analysis)
	}

	return nil
}

// analyzeAgentPoolsSecurity analyzes agent pools for security risks
func analyzeAgentPoolsSecurity(pools []azuredevops.AgentPool, agentsByPool map[int][]azuredevops.Agent) string {
	if len(pools) == 0 {
		return ""
	}

	var warnings []string
	selfHostedCount := 0

	for _, pool := range pools {
		// Count self-hosted pools
		if !pool.IsHosted {
			selfHostedCount++
		}

		// Check for auto-provisioned pools
		if pool.AutoProvision {
			warnings = append(warnings, fmt.Sprintf("⚠️  Pool '%s' is auto-provisioned to all projects - cross-project contamination risk", pool.Name))
		}
	}

	var result string
	result += "\nSecurity Analysis:\n"
	result += "==================\n"

	// Report on self-hosted pools
	if selfHostedCount > 0 {
		result += fmt.Sprintf("⚠️  %d self-hosted agent pool(s) detected - potential lateral movement targets\n", selfHostedCount)
	} else {
		result += "✓ All pools are Microsoft-hosted (lower risk)\n"
	}

	// Add auto-provision warnings
	for _, warning := range warnings {
		result += warning + "\n"
	}

	// Add agent-level analysis if available
	if agentsByPool != nil {
		agentAnalysis := analyzeAgentDetails(agentsByPool)
		if agentAnalysis != "" {
			result += agentAnalysis
		}
	}

	return result
}

// analyzeAgentDetails reports on agent-level security observations
func analyzeAgentDetails(agentsByPool map[int][]azuredevops.Agent) string {
	var lines []string

	totalAgents := 0
	linuxCount := 0
	windowsCount := 0
	offlineCount := 0
	versions := make(map[string]int)

	for _, agents := range agentsByPool {
		for _, agent := range agents {
			totalAgents++

			// OS breakdown
			osLower := strings.ToLower(agent.OSDescription)
			switch {
			case strings.Contains(osLower, "linux"),
				strings.Contains(osLower, "ubuntu"),
				strings.Contains(osLower, "debian"),
				strings.Contains(osLower, "centos"),
				strings.Contains(osLower, "rhel"),
				strings.Contains(osLower, "fedora"),
				strings.Contains(osLower, "alpine"):
				linuxCount++
			case strings.Contains(osLower, "windows"):
				windowsCount++
			}

			// Offline agents
			if agent.Status == "offline" {
				offlineCount++
			}

			// Version tracking
			if agent.Version != "" {
				versions[agent.Version]++
			}
		}
	}

	if totalAgents == 0 {
		return ""
	}

	lines = append(lines, "\nAgent Details:")

	// OS breakdown
	otherCount := totalAgents - linuxCount - windowsCount
	var osParts []string
	if linuxCount > 0 {
		osParts = append(osParts, fmt.Sprintf("%d Linux", linuxCount))
	}
	if windowsCount > 0 {
		osParts = append(osParts, fmt.Sprintf("%d Windows", windowsCount))
	}
	if otherCount > 0 {
		osParts = append(osParts, fmt.Sprintf("%d other", otherCount))
	}
	lines = append(lines, fmt.Sprintf("  Agent OS breakdown: %s (%d total across self-hosted pools)", strings.Join(osParts, ", "), totalAgents))

	// Offline agents
	if offlineCount > 0 {
		lines = append(lines, fmt.Sprintf("  ⚠️  %d agent(s) offline - potential stale/abandoned agents", offlineCount))
	}

	// Version spread
	if len(versions) > 1 {
		var versionList []string
		for v, count := range versions {
			versionList = append(versionList, fmt.Sprintf("%s (%d)", v, count))
		}
		lines = append(lines, fmt.Sprintf("  ⚠️  Multiple agent versions detected: %s - inconsistent patching", strings.Join(versionList, ", ")))
	}

	return strings.Join(lines, "\n") + "\n"
}
