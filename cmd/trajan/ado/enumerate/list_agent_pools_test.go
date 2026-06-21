package enumerate

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/azuredevops"
)

// Test security analysis helper functions

func TestAnalyzeAgentPoolsSecurity_AllMicrosoftHosted(t *testing.T) {
	pools := []azuredevops.AgentPool{
		{ID: 1, Name: "Azure Pipelines", IsHosted: true, AutoProvision: false},
		{ID: 2, Name: "Hosted Ubuntu", IsHosted: true, AutoProvision: false},
	}

	result := analyzeAgentPoolsSecurity(pools, nil)

	assert.Contains(t, result, "All pools are Microsoft-hosted (lower risk)")
	assert.NotContains(t, result, "self-hosted agent pool(s) detected")
}

func TestAnalyzeAgentPoolsSecurity_SelfHosted(t *testing.T) {
	pools := []azuredevops.AgentPool{
		{ID: 1, Name: "Azure Pipelines", IsHosted: true, AutoProvision: false},
		{ID: 2, Name: "My Self-Hosted Pool", IsHosted: false, AutoProvision: false},
		{ID: 3, Name: "Another Self-Hosted", IsHosted: false, AutoProvision: false},
	}

	result := analyzeAgentPoolsSecurity(pools, nil)

	assert.Contains(t, result, "2 self-hosted agent pool(s) detected - potential lateral movement targets")
	assert.NotContains(t, result, "All pools are Microsoft-hosted")
}

func TestAnalyzeAgentPoolsSecurity_AutoProvision(t *testing.T) {
	pools := []azuredevops.AgentPool{
		{ID: 1, Name: "Auto Pool", IsHosted: false, AutoProvision: true},
		{ID: 2, Name: "Normal Pool", IsHosted: false, AutoProvision: false},
	}

	result := analyzeAgentPoolsSecurity(pools, nil)

	assert.Contains(t, result, "Pool 'Auto Pool' is auto-provisioned to all projects - cross-project contamination risk")
}

func TestAnalyzeAgentPoolsSecurity_Empty(t *testing.T) {
	pools := []azuredevops.AgentPool{}

	result := analyzeAgentPoolsSecurity(pools, nil)

	assert.Equal(t, "", result)
}

func TestAnalyzeAgentDetails_WithAgents(t *testing.T) {
	agentsByPool := map[int][]azuredevops.Agent{
		1: {
			{ID: 1, Name: "linux-01", Version: "4.260.0", Status: "online", Enabled: true, OSDescription: "Linux 5.15.0-1234-azure"},
			{ID: 2, Name: "win-01", Version: "4.260.0", Status: "offline", Enabled: true, OSDescription: "Windows 10.0.20348"},
		},
		2: {
			{ID: 3, Name: "linux-02", Version: "4.259.0", Status: "online", Enabled: true, OSDescription: "Linux 5.4.0-100-generic"},
			{ID: 4, Name: "ubuntu-01", Version: "4.260.0", Status: "online", Enabled: true, OSDescription: "Ubuntu 24.04.4 LTS"},
		},
	}

	result := analyzeAgentDetails(agentsByPool)

	assert.Contains(t, result, "Agent OS breakdown:")
	assert.Contains(t, result, "3 Linux")
	assert.Contains(t, result, "1 Windows")
	assert.Contains(t, result, "4 total across self-hosted pools")
	assert.Contains(t, result, "1 agent(s) offline - potential stale/abandoned agents")
	assert.Contains(t, result, "Multiple agent versions detected")
	assert.Contains(t, result, "inconsistent patching")
}

func TestAnalyzeAgentDetails_Empty(t *testing.T) {
	agentsByPool := map[int][]azuredevops.Agent{}

	result := analyzeAgentDetails(agentsByPool)

	assert.Equal(t, "", result)
}

func TestAnalyzeAgentPoolsSecurity_WithAgentData(t *testing.T) {
	pools := []azuredevops.AgentPool{
		{ID: 1, Name: "Self-Hosted Pool", IsHosted: false, AutoProvision: false},
	}
	agentsByPool := map[int][]azuredevops.Agent{
		1: {
			{ID: 1, Name: "agent-01", Version: "4.260.0", Status: "online", Enabled: true, OSDescription: "Linux 5.15.0"},
		},
	}

	result := analyzeAgentPoolsSecurity(pools, agentsByPool)

	assert.Contains(t, result, "Security Analysis:")
	assert.Contains(t, result, "1 self-hosted agent pool(s) detected")
	assert.Contains(t, result, "Agent Details:")
	assert.Contains(t, result, "1 Linux")
}
