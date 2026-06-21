package enumerate

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/azuredevops"
)

func TestAttackPathsCommandExists(t *testing.T) {
	cmd := NewEnumerateCmd()
	found, _, err := cmd.Find([]string{"attack-paths"})
	assert.NoError(t, err)
	assert.Equal(t, "attack-paths", found.Use)
}

func TestIdentifyAttackPaths_DirectExecution(t *testing.T) {
	perms := permissionAnalysis{
		CanQueueBuilds: true,
	}
	triggers := triggerAnalysis{}
	policies := policyAnalysis{}

	paths := identifyAttackPaths(perms, triggers, policies)

	assert.Len(t, paths, 1)
	assert.Equal(t, "High", paths[0].Risk)
	assert.Equal(t, "Direct Pipeline Execution", paths[0].Name)
}

func TestIdentifyAttackPaths_CriticalCIHijack(t *testing.T) {
	perms := permissionAnalysis{
		CanContribute: true,
	}
	triggers := triggerAnalysis{
		ExploitableCITriggers: []azuredevops.TriggerSummary{
			{PipelineID: 1, IsExploitable: true},
			{PipelineID: 2, IsExploitable: true},
		},
	}
	policies := policyAnalysis{}

	paths := identifyAttackPaths(perms, triggers, policies)

	// Should have CI Trigger Hijack (Critical)
	found := false
	for _, path := range paths {
		if path.Name == "CI Trigger Hijack" {
			found = true
			assert.Equal(t, "Critical", path.Risk)
			assert.Contains(t, path.Details, "2 exploitable")
		}
	}
	assert.True(t, found, "Should have CI Trigger Hijack attack path")
}

func TestIdentifyAttackPaths_PRAttack(t *testing.T) {
	perms := permissionAnalysis{
		CanCreatePR: true,
	}
	triggers := triggerAnalysis{
		PRTriggers: []azuredevops.TriggerSummary{
			{PipelineID: 1, TriggerType: "pullRequest"},
		},
	}
	policies := policyAnalysis{
		BuildValidationPolicies: []buildValidationPolicy{
			{PipelineID: 2},
		},
	}

	paths := identifyAttackPaths(perms, triggers, policies)

	// Should have PR Trigger Attack
	found := false
	for _, path := range paths {
		if path.Name == "PR Trigger Attack" {
			found = true
			assert.Equal(t, "Medium", path.Risk) // Medium because no exploitable PR triggers
			assert.Contains(t, path.Details, "1 PR triggers")
			assert.Contains(t, path.Details, "1 build validation policies")
		}
	}
	assert.True(t, found, "Should have PR Trigger Attack path")
}

func TestIdentifyAttackPaths_PolicyBypass(t *testing.T) {
	perms := permissionAnalysis{
		CanBypassPolicies: true,
	}
	triggers := triggerAnalysis{}
	policies := policyAnalysis{}

	paths := identifyAttackPaths(perms, triggers, policies)

	assert.Len(t, paths, 1)
	assert.Equal(t, "High", paths[0].Risk)
	assert.Equal(t, "Policy Bypass", paths[0].Name)
}

func TestIdentifyAttackPaths_ScheduledPoisoning(t *testing.T) {
	perms := permissionAnalysis{
		CanContribute: true,
	}
	triggers := triggerAnalysis{
		ScheduledTriggers: []azuredevops.TriggerSummary{
			{PipelineID: 1, TriggerType: "schedule"},
		},
	}
	policies := policyAnalysis{}

	paths := identifyAttackPaths(perms, triggers, policies)

	assert.Len(t, paths, 1)
	assert.Equal(t, "Medium", paths[0].Risk)
	assert.Equal(t, "Scheduled Trigger Poisoning", paths[0].Name)
}

func TestIdentifyAttackPaths_MultipleRisks(t *testing.T) {
	perms := permissionAnalysis{
		CanQueueBuilds:    true,
		CanContribute:     true,
		CanBypassPolicies: true,
	}
	triggers := triggerAnalysis{
		ExploitableCITriggers: []azuredevops.TriggerSummary{{PipelineID: 1}},
		CITriggers:            []azuredevops.TriggerSummary{{PipelineID: 1}},
		ScheduledTriggers:     []azuredevops.TriggerSummary{{PipelineID: 2}},
	}
	policies := policyAnalysis{}

	paths := identifyAttackPaths(perms, triggers, policies)

	// Should have multiple paths sorted by risk
	assert.Greater(t, len(paths), 3)

	// First should be Critical
	assert.Equal(t, "Critical", paths[0].Risk)

	// Check that we have expected paths
	pathNames := make(map[string]bool)
	for _, path := range paths {
		pathNames[path.Name] = true
	}
	assert.True(t, pathNames["CI Trigger Hijack"])
	assert.True(t, pathNames["Direct Pipeline Execution"])
	assert.True(t, pathNames["Policy Bypass"])
}

func TestIdentifyAttackPaths_NoPermissions(t *testing.T) {
	perms := permissionAnalysis{}
	triggers := triggerAnalysis{
		CITriggers: []azuredevops.TriggerSummary{{PipelineID: 1}},
	}
	policies := policyAnalysis{}

	paths := identifyAttackPaths(perms, triggers, policies)

	// No permissions, so no attack paths
	assert.Len(t, paths, 0)
}
