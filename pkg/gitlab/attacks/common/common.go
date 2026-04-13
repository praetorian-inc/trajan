package common

import (
	"context"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/gitlab"
)

// FindingHasType checks if any finding matches the given type
func FindingHasType(findings []detections.Finding, vulnType detections.VulnerabilityType) bool {
	for _, f := range findings {
		if f.Type == vulnType {
			return true
		}
	}
	return false
}

// GenerateBranchName creates a realistic, OpSec-friendly branch name
// Format: {prefix}/{topic}-{shortSessionID}
// Examples: feature/ci-a3f5b2, bugfix/deps-7c9e1d
func GenerateBranchName(sessionID string) string {
	prefixes := []string{
		"feature",
		"bugfix",
		"hotfix",
		"fix",
		"update",
		"patch",
	}

	topics := []string{
		"deps",
		"tests",
		"ci",
		"config",
		"build",
		"lint",
		"security",
		"docs",
	}

	// Use hash of session ID for deterministic pseudo-random selection
	h := fnv.New32a()
	h.Write([]byte(sessionID))
	hash := h.Sum32()

	prefix := prefixes[hash%uint32(len(prefixes))]
	topic := topics[(hash>>8)%uint32(len(topics))]

	// Use first 6 chars of session ID (looks like git short SHA)
	shortID := sessionID
	if len(shortID) > 6 {
		shortID = shortID[:6]
	}

	return fmt.Sprintf("%s/%s-%s", prefix, topic, shortID)
}

// WaitForPipeline polls until a pipeline completes or timeout is reached.
// Filters pipelines to only those created after commitTimestamp to avoid race conditions.
func WaitForPipeline(ctx context.Context, client *gitlab.Client, projectID int, branch string, commitTimestamp string, timeout time.Duration) (*gitlab.Pipeline, error) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Parse commit timestamp for comparison
	commitTime, err := time.Parse(time.RFC3339, commitTimestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse commit timestamp: %w", err)
	}

	var lastStatus string

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("pipeline did not complete within %v", timeout)
			}

			pipelines, err := client.ListPipelines(ctx, projectID, branch)
			if err != nil {
				continue
			}

			if len(pipelines) == 0 {
				continue
			}

			// Find first pipeline created after our commit (GitLab returns newest first)
			var pipeline *gitlab.Pipeline
			for i := range pipelines {
				pipelineTime, err := time.Parse(time.RFC3339, pipelines[i].CreatedAt)
				if err != nil {
					continue
				}

				// Only consider pipelines created at or after our commit
				if !pipelineTime.Before(commitTime) {
					pipeline = &pipelines[i]
					break
				}
			}

			if pipeline == nil {
				continue // No pipeline created after commit yet
			}

			if pipeline.Status != lastStatus {
				fmt.Printf("Pipeline status: %s\n", pipeline.Status)
				lastStatus = pipeline.Status
			}

			switch pipeline.Status {
			case "success", "failed", "canceled", "skipped":
				return pipeline, nil
			default:
				continue
			}
		}
	}
}

// DeferredCleanup holds the state needed to clean up attack artifacts in a defer block.
type DeferredCleanup struct {
	Client     *gitlab.Client
	ProjectID  int
	BranchName *string
	PipelineID *int
	JobID      *int
	Disabled   bool
}

// Run performs cleanup of attack artifacts. Intended to be called in a defer block.
// It uses a background context to ensure cleanup completes even if the original context is canceled.
func (dc *DeferredCleanup) Run() {
	if dc.Disabled {
		fmt.Printf("\nSkipping cleanup (--no-cleanup specified)\n")
		return
	}

	branchName := ""
	if dc.BranchName != nil {
		branchName = *dc.BranchName
	}
	pipelineID := 0
	if dc.PipelineID != nil {
		pipelineID = *dc.PipelineID
	}
	jobID := 0
	if dc.JobID != nil {
		jobID = *dc.JobID
	}

	if branchName == "" && pipelineID == 0 {
		return // Nothing to cleanup
	}

	// Use background context for cleanup to ensure it completes even if original context canceled
	cleanupCtx := context.Background()

	fmt.Printf("\nCleaning up artifacts...\n")

	var cleanupErrors []string

	if jobID > 0 {
		if err := dc.Client.DeleteJobLogs(cleanupCtx, dc.ProjectID, jobID); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Sprintf("job logs (job %d): %v", jobID, err))
		} else {
			fmt.Printf("Deleted job logs for job %d\n", jobID)
		}
	}

	if branchName != "" {
		if err := dc.Client.DeleteBranch(cleanupCtx, dc.ProjectID, branchName); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Sprintf("branch %s: %v", branchName, err))
		} else {
			fmt.Printf("Deleted branch %s\n", branchName)
		}
	}

	if pipelineID > 0 {
		if err := dc.Client.DeletePipeline(cleanupCtx, dc.ProjectID, pipelineID); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Sprintf("pipeline %d: %v", pipelineID, err))
		} else {
			fmt.Printf("Deleted pipeline %d\n", pipelineID)
		}
	}

	// Display prominent OpSec warning if any cleanup failed
	if len(cleanupErrors) > 0 {
		fmt.Printf("\n!!! OPSEC WARNING !!!\n")
		fmt.Printf("Failed to cleanup %d artifact(s) - traces remain in GitLab:\n", len(cleanupErrors))
		for _, errMsg := range cleanupErrors {
			fmt.Printf("  - %s\n", errMsg)
		}
		fmt.Printf("\nManual cleanup required to remove evidence.\n")
	}
}

// CleanupSessionArtifacts performs cleanup for a plugin's artifacts from a session.
// Used by the Cleanup method of attack plugins.
func CleanupSessionArtifacts(ctx context.Context, client *gitlab.Client, session *attacks.Session, pluginName string) error {
	for _, result := range session.Results {
		if result.Plugin != pluginName {
			continue
		}

		// Parse project path
		projectPath := result.Repo
		if projectPath == "" {
			projectPath = session.Target.Value
		}

		project, err := client.GetProject(ctx, projectPath)
		if err != nil {
			fmt.Printf("  Skipping cleanup for %s: %v\n", result.Plugin, err)
			continue
		}

		projectID := project.ID

		for _, action := range result.CleanupActions {
			switch action.Type {
			case attacks.ArtifactBranch:
				if err := client.DeleteBranch(ctx, projectID, action.Identifier); err != nil {
					if gitlab.IsNotFoundError(err) {
						fmt.Printf("Branch %s already deleted or doesn't exist\n", action.Identifier)
						continue
					}
					return fmt.Errorf("deleting branch %s: %w", action.Identifier, err)
				}
				fmt.Printf("Deleted branch %s\n", action.Identifier)

			case attacks.ArtifactWorkflow:
				// Parse pipeline ID from identifier "pipeline:<ID>"
				var pipelineID int
				if _, err := fmt.Sscanf(action.Identifier, "pipeline:%d", &pipelineID); err != nil {
					fmt.Printf("Warning: invalid pipeline identifier: %s\n", action.Identifier)
					continue
				}

				if err := client.DeletePipeline(ctx, projectID, pipelineID); err != nil {
					if gitlab.IsNotFoundError(err) {
						fmt.Printf("Pipeline %d already deleted or doesn't exist\n", pipelineID)
						continue
					}
					return fmt.Errorf("deleting pipeline %d: %w", pipelineID, err)
				}
				fmt.Printf("Deleted pipeline %d\n", pipelineID)
			}
		}
	}

	return nil
}
