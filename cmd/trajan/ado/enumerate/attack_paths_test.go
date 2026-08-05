package enumerate

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/azuredevops"
)

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

	assert.Greater(t, len(paths), 3)

	assert.Equal(t, "Critical", paths[0].Risk)

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

	assert.Len(t, paths, 0)
}
