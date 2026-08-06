package common

import (
	"strings"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

// InjectableContexts are user-controllable Azure DevOps pipeline variables.
var InjectableContexts = []string{
	"Build.SourceVersionMessage",
	"Build.SourceBranchName", // short name, unlike Build.SourceBranch
	"Build.SourceBranch",     // full ref, e.g. refs/heads/feature/foo
	"Build.RequestedFor",
	"Build.RequestedForEmail",
	"System.PullRequest.SourceBranch",
	"System.PullRequest.TargetBranch",
}

var DangerousTokenVariables = []string{
	"SYSTEM_ACCESSTOKEN",
	"System.AccessToken",
	"AZURE_DEVOPS_EXT_PAT",
}

// Uses exact match to avoid false positives (e.g. "sprint" matching "pr").
var DangerousTriggers = map[string]bool{
	"pr":          true,
	"pullrequest": true,
}

// Matches raw name (covers all syntaxes: $(Var), ${{ variables.Var }}, $[variables.Var]).
func ContainsInjectableContext(s string) bool {
	for _, ctx := range InjectableContexts {
		if strings.Contains(s, ctx) {
			return true
		}
	}
	return false
}

func ContainsDangerousToken(s string) bool {
	upper := strings.ToUpper(s)
	for _, token := range DangerousTokenVariables {
		if strings.Contains(upper, strings.ToUpper(token)) {
			return true
		}
	}
	return false
}

func HasDangerousTrigger(triggers []string) bool {
	for _, t := range triggers {
		if DangerousTriggers[strings.ToLower(t)] {
			return true
		}
	}
	return false
}

func LineForKey(lines map[string]int, key string, fallback int) int {
	if line, ok := lines[key]; ok && line > 0 {
		return line
	}
	return fallback
}

// A block scalar's content starts at step.Line+1; an inline script sits on step.Line.
func ScriptLineForPattern(step *graph.StepNode, pattern string, caseInsensitive bool) int {
	if step.Run == "" {
		return step.Line
	}
	lines := strings.Split(step.Run, "\n")
	patternMatch := pattern
	if caseInsensitive {
		patternMatch = strings.ToLower(pattern)
	}
	for i, line := range lines {
		lineMatch := line
		if caseInsensitive {
			lineMatch = strings.ToLower(line)
		}
		if strings.Contains(lineMatch, patternMatch) {
			if len(lines) == 1 {
				return step.Line
			}
			return step.Line + 1 + i
		}
	}
	return step.Line
}

// Dot-notation, as the variables appear in $(…) macro expressions.
var SafeSystemVariablesMacro = map[string]bool{
	"Build.BuildId":           true,
	"Build.BuildNumber":       true,
	"Build.SourceVersion":     true,
	"Build.Repository.Name":   true,
	"Build.Repository.Uri":    true,
	"Build.DefinitionName":    true,
	"Build.Reason":            true,
	"System.TeamProject":      true,
	"System.CollectionUri":    true,
	"System.DefinitionId":     true,
	"System.TeamProjectId":    true,
	"System.CollectionId":     true,
	"System.HostType":         true,
	"System.JobId":            true,
	"System.PlanId":           true,
	"System.StageId":          true,
	"System.PhaseId":          true,
	"System.TimelineId":       true,
	"System.TaskInstanceId":   true,
	"System.JobDisplayName":   true,
	"System.StageDisplayName": true,
	"Agent.BuildDirectory":    true,
	"Agent.Id":                true,
	"Agent.MachineName":       true,
	"Agent.Name":              true,
	"Agent.OS":                true,
	"Agent.OSArchitecture":    true,
	"Agent.TempDirectory":     true,
	"Agent.ToolsDirectory":    true,
	"Agent.WorkFolder":        true,
	"Agent.JobName":           true,
	"Pipeline.Workspace":      true,
}

// Underscore-notation, as the variables appear in ${{ variables.… }} template expressions.
var SafeSystemVariablesTemplateExpr = map[string]bool{
	"Build_BuildId":           true,
	"Build_BuildNumber":       true,
	"Build_Repository_Name":   true,
	"Build_Repository_Uri":    true,
	"Build_SourceVersion":     true,
	"Build_DefinitionName":    true,
	"System_TeamProject":      true,
	"System_CollectionUri":    true,
	"System_DefinitionId":     true,
	"System_TeamProjectId":    true,
	"System_CollectionId":     true,
	"System_HostType":         true,
	"System_JobId":            true,
	"System_PlanId":           true,
	"System_StageId":          true,
	"System_PhaseId":          true,
	"System_TimelineId":       true,
	"System_TaskInstanceId":   true,
	"System_JobDisplayName":   true,
	"System_StageDisplayName": true,
	"Agent_BuildDirectory":    true,
	"Agent_Id":                true,
	"Agent_MachineName":       true,
	"Agent_Name":              true,
	"Agent_OS":                true,
	"Agent_OSArchitecture":    true,
	"Agent_TempDirectory":     true,
	"Agent_ToolsDirectory":    true,
	"Agent_WorkFolder":        true,
	"Agent_JobName":           true,
	"Pipeline_Workspace":      true,
}
