package common

import (
	"fmt"
	"sort"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/azuredevops"
)

// GenerateVariableGroupsYAML generates the YAML variables section for variable groups
func GenerateVariableGroupsYAML(groups []azuredevops.VariableGroup) string {
	if len(groups) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("variables:\n")
	for _, group := range groups {
		fmt.Fprintf(&sb, "  - group: %s\n", group.Name)
	}
	sb.WriteString("\n")

	return sb.String()
}

// GenerateSecretEnvYAML generates the env: mapping YAML for secret variables
func GenerateSecretEnvYAML(groups []azuredevops.VariableGroup) string {
	// Collect all secret variable names
	secretVarNames := make(map[string]bool)
	for _, group := range groups {
		for varName, varVal := range group.Variables {
			if varVal.IsSecret {
				secretVarNames[varName] = true
			}
		}
	}

	if len(secretVarNames) == 0 {
		return ""
	}

	// Sort for deterministic output
	sortedNames := make([]string, 0, len(secretVarNames))
	for name := range secretVarNames {
		sortedNames = append(sortedNames, name)
	}
	sort.Strings(sortedNames)

	var sb strings.Builder
	sb.WriteString("    env:\n")
	for _, name := range sortedNames {
		fmt.Fprintf(&sb, "      %s: $(%s)\n", name, name)
	}

	return sb.String()
}
