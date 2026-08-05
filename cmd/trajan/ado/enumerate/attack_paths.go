package enumerate

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/pkg/azuredevops"
)

type permissionAnalysis struct {
	CanQueueBuilds     bool
	CanContribute      bool
	CanCreatePR        bool
	CanForcePush       bool
	CanBypassPolicies  bool
	CanViewBuilds      bool
	CanViewDefinitions bool
	BuildPerms         []permissionDetail
	GitPerms           []permissionDetail
}

type permissionDetail struct {
	Name    string
	Bit     int
	Allowed bool
}

type triggerAnalysis struct {
	CITriggers            []azuredevops.TriggerSummary
	PRTriggers            []azuredevops.TriggerSummary
	ScheduledTriggers     []azuredevops.TriggerSummary
	ManualOnly            []azuredevops.TriggerSummary
	ExploitableCITriggers []azuredevops.TriggerSummary
	ExploitablePRTriggers []azuredevops.TriggerSummary
	TotalPipelines        int
}

type policyAnalysis struct {
	BuildValidationPolicies []buildValidationPolicy
	TotalPolicies           int
}

type buildValidationPolicy struct {
	Repository   string
	Branch       string
	PipelineID   int
	PipelineName string
	IsEnabled    bool
	Project      string
}

type attackPath struct {
	Risk    string
	Name    string
	Details string
}

type attackPathOutput struct {
	Permissions permissionAnalysis `json:"permissions"`
	Triggers    triggerAnalysis    `json:"triggers"`
	Policies    policyAnalysis     `json:"policies"`
	AttackPaths []attackPath       `json:"attack_paths"`
	Summary     struct {
		TotalPaths int `json:"total_paths"`
		Critical   int `json:"critical"`
		High       int `json:"high"`
		Medium     int `json:"medium"`
	} `json:"summary"`
}

func newAttackPathsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attack-paths",
		Short: "Analyze permissions, triggers, and policies to identify attack paths",
		Long: `Trajan - Azure DevOps - Enumerate

Analyze permissions, triggers, and policies to identify attack paths.

This command performs a comprehensive analysis to identify potential attack paths
by examining:
  - User permissions (queue builds, contribute code, bypass policies)
  - Pipeline triggers (CI, PR, scheduled)
  - Build validation policies

Use --project to scope to a single project, or omit to analyze all projects.`,
		RunE: runAttackPaths,
	}

	return cmd
}

func runAttackPaths(cmd *cobra.Command, args []string) error {
	if enumOrg == "" {
		return fmt.Errorf("--org is required")
	}

	switch enumPlatform {
	case "azuredevops":
		return runAttackPathsAzDO(cmd.Context())
	default:
		return fmt.Errorf("platform %s not supported for attack path analysis", enumPlatform)
	}
}

func runAttackPathsAzDO(ctx context.Context) error {
	orgURL := fmt.Sprintf("https://dev.azure.com/%s", enumOrg)
	client, err := NewEnumerateClient(orgURL, GetTokenForPlatform(enumPlatform))
	if err != nil {
		return err
	}

	var projectsToAnalyze []string

	if enumProject != "" {
		projectsToAnalyze = []string{enumProject}
	} else {
		projects, err := client.ListProjects(ctx)
		if err != nil {
			return err
		}
		for _, proj := range projects {
			projectsToAnalyze = append(projectsToAnalyze, proj.Name)
		}
	}

	var allPerms permissionAnalysis
	var allTriggers triggerAnalysis
	var allPolicies policyAnalysis

	for _, proj := range projectsToAnalyze {
		perms := analyzePermissionsAzDO(ctx, client, proj)
		triggers := analyzeTriggersAzDO(ctx, client, proj)
		policies := analyzePoliciesAzDO(ctx, client, proj)

		if perms.CanQueueBuilds {
			allPerms.CanQueueBuilds = true
		}
		if perms.CanContribute {
			allPerms.CanContribute = true
		}
		if perms.CanCreatePR {
			allPerms.CanCreatePR = true
		}
		if perms.CanForcePush {
			allPerms.CanForcePush = true
		}
		if perms.CanBypassPolicies {
			allPerms.CanBypassPolicies = true
		}
		if perms.CanViewBuilds {
			allPerms.CanViewBuilds = true
		}
		if perms.CanViewDefinitions {
			allPerms.CanViewDefinitions = true
		}
		allPerms.BuildPerms = append(allPerms.BuildPerms, perms.BuildPerms...)
		allPerms.GitPerms = append(allPerms.GitPerms, perms.GitPerms...)

		allTriggers.CITriggers = append(allTriggers.CITriggers, triggers.CITriggers...)
		allTriggers.PRTriggers = append(allTriggers.PRTriggers, triggers.PRTriggers...)
		allTriggers.ScheduledTriggers = append(allTriggers.ScheduledTriggers, triggers.ScheduledTriggers...)
		allTriggers.ManualOnly = append(allTriggers.ManualOnly, triggers.ManualOnly...)
		allTriggers.ExploitableCITriggers = append(allTriggers.ExploitableCITriggers, triggers.ExploitableCITriggers...)
		allTriggers.ExploitablePRTriggers = append(allTriggers.ExploitablePRTriggers, triggers.ExploitablePRTriggers...)
		allTriggers.TotalPipelines += triggers.TotalPipelines

		allPolicies.BuildValidationPolicies = append(allPolicies.BuildValidationPolicies, policies.BuildValidationPolicies...)
		allPolicies.TotalPolicies += policies.TotalPolicies
	}

	paths := identifyAttackPaths(allPerms, allTriggers, allPolicies)

	return outputAttackPaths(allPerms, allTriggers, allPolicies, paths)
}

func analyzePermissionsAzDO(ctx context.Context, client *azuredevops.Client, project string) permissionAnalysis {
	var pa permissionAnalysis

	// Empty token = org-level check (wrong), project ID = project-level (correct)
	proj, err := client.GetProject(ctx, project)
	if err != nil {
		return pa
	}
	buildToken := proj.ID
	gitToken := "repoV2/" + proj.ID

	buildPerms := []struct {
		bit  int
		name string
	}{
		{buildPermViewBuilds, "View builds"},
		{buildPermQueueBuilds, "Queue builds"},
		{buildPermViewDefinitions, "View build definition"},
		{buildPermEditBuildDefinition, "Edit build definition"},
		{buildPermDeleteBuilds, "Delete builds"},
		{buildPermStopBuilds, "Stop builds"},
		{buildPermAdministerPermissions, "Administer build permissions"},
	}

	for _, perm := range buildPerms {
		allowed, err := client.CheckPermission(ctx, buildNamespaceID, perm.bit, buildToken)
		if err != nil {
			continue
		}
		pa.BuildPerms = append(pa.BuildPerms, permissionDetail{
			Name:    perm.name,
			Bit:     perm.bit,
			Allowed: allowed,
		})
		if allowed {
			switch perm.bit {
			case buildPermQueueBuilds:
				pa.CanQueueBuilds = true
			case buildPermViewBuilds:
				pa.CanViewBuilds = true
			case buildPermViewDefinitions:
				pa.CanViewDefinitions = true
			}
		}
	}

	gitPerms := []struct {
		bit  int
		name string
	}{
		{gitPermAdminister, "Administer"},
		{gitPermRead, "Read"},
		{gitPermContribute, "Contribute"},
		{gitPermForcePush, "Force push"},
		{gitPermCreateBranch, "Create branch"},
		{gitPermBypassPoliciesPush, "Bypass policies when pushing"},
		{gitPermContributeToPR, "Contribute to pull requests"},
		{gitPermBypassPoliciesPR, "Bypass policies when completing PR"},
	}

	for _, perm := range gitPerms {
		allowed, err := client.CheckPermission(ctx, gitNamespaceID, perm.bit, gitToken)
		if err != nil {
			continue
		}
		pa.GitPerms = append(pa.GitPerms, permissionDetail{
			Name:    perm.name,
			Bit:     perm.bit,
			Allowed: allowed,
		})
		if allowed {
			switch perm.bit {
			case gitPermContribute:
				pa.CanContribute = true
				pa.CanCreatePR = true
			case gitPermForcePush:
				pa.CanForcePush = true
			case gitPermBypassPoliciesPush, gitPermBypassPoliciesPR:
				pa.CanBypassPolicies = true
			}
		}
	}

	return pa
}

func analyzeTriggersAzDO(ctx context.Context, client *azuredevops.Client, project string) triggerAnalysis {
	var ta triggerAnalysis

	defs, err := client.ListBuildDefinitions(ctx, project)
	if err != nil {
		return ta
	}

	ta.TotalPipelines = len(defs)

	for _, defSummary := range defs {
		def, err := client.GetBuildDefinition(ctx, project, defSummary.ID)
		if err != nil {
			continue
		}

		hasCITrigger := false
		hasPRTrigger := false
		hasScheduled := false

		for _, trigger := range def.Triggers {
			summary := azuredevops.TriggerSummary{
				PipelineID:    def.ID,
				PipelineName:  def.Name,
				Project:       def.Project.Name,
				Repository:    def.Repository.Name,
				TriggerType:   trigger.TriggerType,
				BranchFilters: formatBranchFilters(trigger.BranchFilters, 3),
				RawFilters:    trigger.BranchFilters,
			}

			isExploitable, reason := analyzeBranchFilters(trigger.BranchFilters)
			summary.IsExploitable = isExploitable
			summary.ExploitReason = reason

			switch trigger.TriggerType {
			case "continuousIntegration":
				hasCITrigger = true
				ta.CITriggers = append(ta.CITriggers, summary)
				if isExploitable {
					ta.ExploitableCITriggers = append(ta.ExploitableCITriggers, summary)
				}

			case "pullRequest":
				hasPRTrigger = true
				ta.PRTriggers = append(ta.PRTriggers, summary)
				if isExploitable {
					ta.ExploitablePRTriggers = append(ta.ExploitablePRTriggers, summary)
				}

			case "schedule":
				hasScheduled = true
				ta.ScheduledTriggers = append(ta.ScheduledTriggers, summary)
			}
		}

		if !hasCITrigger && !hasPRTrigger && !hasScheduled {
			if def.Process.Type == 2 {
				// YAML pipelines have implicit CI triggers on all branches
				implicitCI := azuredevops.TriggerSummary{
					PipelineID:    def.ID,
					PipelineName:  def.Name,
					Project:       def.Project.Name,
					Repository:    def.Repository.Name,
					TriggerType:   "continuousIntegration",
					BranchFilters: "* (implicit)",
					IsExploitable: true,
					ExploitReason: "YAML implicit CI trigger on all branches",
				}
				ta.CITriggers = append(ta.CITriggers, implicitCI)
				ta.ExploitableCITriggers = append(ta.ExploitableCITriggers, implicitCI)
			} else {
				ta.ManualOnly = append(ta.ManualOnly, azuredevops.TriggerSummary{
					PipelineID:   def.ID,
					PipelineName: def.Name,
					Project:      def.Project.Name,
					Repository:   def.Repository.Name,
					TriggerType:  "manual",
				})
			}
		}
	}

	return ta
}

func analyzePoliciesAzDO(ctx context.Context, client *azuredevops.Client, project string) policyAnalysis {
	var pa policyAnalysis

	configs, err := client.ListPolicyConfigurations(ctx, project)
	if err != nil {
		return pa
	}

	pa.TotalPolicies = len(configs)

	for _, config := range configs {
		if config.Type.ID == buildValidationPolicyTypeID {
			for _, scope := range config.Settings.Scope {
				policy := buildValidationPolicy{
					PipelineID:   config.Settings.BuildDefinitionID,
					PipelineName: "", // Needs a separate lookup.
					Branch:       scope.RefName,
					IsEnabled:    config.IsEnabled,
					Project:      project,
				}

				if scope.RepositoryID != "" {
					policy.Repository = scope.RepositoryID
				}

				pa.BuildValidationPolicies = append(pa.BuildValidationPolicies, policy)
			}
		}
	}

	return pa
}

func identifyAttackPaths(perms permissionAnalysis, triggers triggerAnalysis, policies policyAnalysis) []attackPath {
	var paths []attackPath

	if perms.CanQueueBuilds {
		paths = append(paths, attackPath{
			Risk:    "High",
			Name:    "Direct Pipeline Execution",
			Details: "Queue builds permission allows direct pipeline execution",
		})
	}

	if perms.CanContribute && len(triggers.ExploitableCITriggers) > 0 {
		paths = append(paths, attackPath{
			Risk:    "Critical",
			Name:    "CI Trigger Hijack",
			Details: fmt.Sprintf("%d exploitable CI triggers with contribute access", len(triggers.ExploitableCITriggers)),
		})
	}

	if perms.CanContribute && len(triggers.CITriggers) > 0 {
		paths = append(paths, attackPath{
			Risk:    "High",
			Name:    "CI Trigger via Code Push",
			Details: fmt.Sprintf("%d CI triggers with contribute access", len(triggers.CITriggers)),
		})
	}

	if perms.CanCreatePR && (len(triggers.PRTriggers) > 0 || len(policies.BuildValidationPolicies) > 0) {
		risk := "Medium"
		if len(triggers.ExploitablePRTriggers) > 0 {
			risk = "Critical"
		}
		details := fmt.Sprintf("%d PR triggers, %d build validation policies", len(triggers.PRTriggers), len(policies.BuildValidationPolicies))
		paths = append(paths, attackPath{
			Risk:    risk,
			Name:    "PR Trigger Attack",
			Details: details,
		})
	}

	if perms.CanBypassPolicies {
		paths = append(paths, attackPath{
			Risk:    "High",
			Name:    "Policy Bypass",
			Details: "Can bypass branch policies on push or PR",
		})
	}

	if perms.CanContribute && len(triggers.ScheduledTriggers) > 0 {
		paths = append(paths, attackPath{
			Risk:    "Medium",
			Name:    "Scheduled Trigger Poisoning",
			Details: fmt.Sprintf("%d scheduled triggers with contribute access", len(triggers.ScheduledTriggers)),
		})
	}

	sort.Slice(paths, func(i, j int) bool {
		riskOrder := map[string]int{"Critical": 0, "High": 1, "Medium": 2}
		return riskOrder[paths[i].Risk] < riskOrder[paths[j].Risk]
	})

	return paths
}

func outputAttackPaths(perms permissionAnalysis, triggers triggerAnalysis, policies policyAnalysis, paths []attackPath) error {
	switch enumOutput {
	case "json":
		return outputAttackPathsJSON(perms, triggers, policies, paths)
	case "csv":
		return outputAttackPathsCSV(paths)
	default:
		return outputAttackPathsConsole(perms, triggers, policies, paths)
	}
}

func outputAttackPathsConsole(perms permissionAnalysis, triggers triggerAnalysis, policies policyAnalysis, paths []attackPath) error {
	fmt.Println("=== Permission Analysis ===")
	fmt.Printf("Queue builds:      %s\n", formatBool(perms.CanQueueBuilds))
	fmt.Printf("Contribute code:   %s\n", formatBool(perms.CanContribute))
	fmt.Printf("Create PRs:        %s\n", formatBool(perms.CanCreatePR))
	fmt.Printf("Force push:        %s\n", formatBool(perms.CanForcePush))
	fmt.Printf("Bypass policies:   %s\n", formatBool(perms.CanBypassPolicies))
	fmt.Println()

	fmt.Println("=== Trigger Analysis ===")
	exploitableCICount := len(triggers.ExploitableCITriggers)
	exploitablePRCount := len(triggers.ExploitablePRTriggers)

	fmt.Printf("CI Triggers:        %d", len(triggers.CITriggers))
	if exploitableCICount > 0 {
		fmt.Printf(" (%d exploitable)", exploitableCICount)
	}
	fmt.Println()

	fmt.Printf("PR Triggers:        %d", len(triggers.PRTriggers))
	if exploitablePRCount > 0 {
		fmt.Printf(" (%d exploitable)", exploitablePRCount)
	}
	fmt.Println()

	fmt.Printf("Scheduled:          %d\n", len(triggers.ScheduledTriggers))
	fmt.Printf("Manual only:        %d\n", len(triggers.ManualOnly))
	fmt.Printf("Total pipelines:    %d\n", triggers.TotalPipelines)
	fmt.Println()

	fmt.Println("=== Policy Analysis ===")
	fmt.Printf("Build Validation:   %d policies\n", len(policies.BuildValidationPolicies))
	fmt.Println()

	fmt.Println("=== Attack Paths ===")
	if len(paths) == 0 {
		fmt.Println("No attack paths identified")
		return nil
	}

	fmt.Printf("%-10s %-30s %s\n", "RISK", "ATTACK PATH", "DETAILS")
	fmt.Println("--------------------------------------------------------------------------------")
	for _, path := range paths {
		fmt.Printf("%-10s %-30s %s\n", path.Risk, path.Name, path.Details)
	}
	fmt.Println()

	critical, high, medium := 0, 0, 0
	for _, path := range paths {
		switch path.Risk {
		case "Critical":
			critical++
		case "High":
			high++
		case "Medium":
			medium++
		}
	}

	fmt.Printf("Found %d attack paths", len(paths))
	if critical > 0 || high > 0 || medium > 0 {
		fmt.Printf(" (%d critical, %d high, %d medium)", critical, high, medium)
	}
	fmt.Println()

	return nil
}

func outputAttackPathsJSON(perms permissionAnalysis, triggers triggerAnalysis, policies policyAnalysis, paths []attackPath) error {
	output := attackPathOutput{
		Permissions: perms,
		Triggers:    triggers,
		Policies:    policies,
		AttackPaths: paths,
	}

	output.Summary.TotalPaths = len(paths)
	for _, path := range paths {
		switch path.Risk {
		case "Critical":
			output.Summary.Critical++
		case "High":
			output.Summary.High++
		case "Medium":
			output.Summary.Medium++
		}
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func outputAttackPathsCSV(paths []attackPath) error {
	writer := csv.NewWriter(os.Stdout)
	defer writer.Flush()

	if err := writer.Write([]string{"Risk", "Attack Path", "Details"}); err != nil {
		return err
	}

	for _, path := range paths {
		if err := writer.Write([]string{path.Risk, path.Name, path.Details}); err != nil {
			return err
		}
	}

	return nil
}
