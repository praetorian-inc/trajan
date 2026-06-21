package gitlab

import (
	"context"
	"fmt"
	"strings"
)

// AnalyzeProjectLogs analyzes recent pipeline logs to discover historical runner usage
// Automatically filters GitLab SaaS shared runners on gitlab.com instances
func (p *Platform) AnalyzeProjectLogs(ctx context.Context, projectID int, pipelineLimit int) ([]RunnerInfo, error) {
	isSaaS := strings.Contains(strings.ToLower(p.client.baseURL), "gitlab.com")
	runners := make(map[string]RunnerInfo) // Deduplicate by runner description

	// Get recent pipelines
	pipelines, err := p.client.ListRecentPipelines(ctx, projectID, pipelineLimit)
	if err != nil {
		return nil, fmt.Errorf("listing pipelines: %w", err)
	}

	for _, pipeline := range pipelines {
		// Get jobs for this pipeline
		jobs, err := p.client.ListPipelineJobs(ctx, projectID, pipeline.ID)
		if err != nil {
			// Don't fail entire analysis for one pipeline
			continue
		}

		for i := range jobs {
			job := &jobs[i]
			var runner RunnerInfo
			needsTraceEnrichment := true

			// Try to extract from job metadata first (fast path)
			if job.Runner != nil {
				if desc, ok := job.Runner["description"].(string); ok && desc != "" {
					if baseRunner := p.createRunnerFromMetadata(*job, desc); baseRunner != nil {
						runner = *baseRunner
						// Check if metadata has enough details
						if runner.Version != "" && runner.Executor != "" {
							needsTraceEnrichment = false
						}
					}
				}
			}

			// Parse trace if we need more details or had no metadata
			if needsTraceEnrichment {
				trace, err := p.client.GetJobTrace(ctx, projectID, job.ID)
				if err != nil {
					// 410 Gone means logs expired, stop analyzing older pipelines
					if IsGoneError(err) {
						break
					}
					// Other errors (403, etc.) - skip this job, but keep metadata if we have it
					if runner.Description != "" {
						runners[runner.Description] = runner
					}
					continue
				}

				// Parse trace for runner info
				logInfo, err := ParseJobTrace(trace)
				if err != nil {
					// Keep metadata-based info if we have it
					if runner.Description != "" {
						runners[runner.Description] = runner
					}
					continue
				}

				// Enrich with trace details
				traceRunner := p.logInfoToRunnerInfo(logInfo, *job)
				if runner.Description == "" {
					runner = traceRunner
				} else {
					// Merge: keep metadata fields, enrich with trace details
					if traceRunner.Version != "" {
						runner.Version = traceRunner.Version
					}
					if traceRunner.Executor != "" {
						runner.Executor = traceRunner.Executor
					}
					if traceRunner.Platform != "" {
						runner.Platform = traceRunner.Platform
					}
				}
			}

			if runner.Description != "" {
				runners[runner.Description] = runner
			}
		}
	}

	// Convert map to slice
	result := make([]RunnerInfo, 0, len(runners))
	for _, runner := range runners {
		result = append(result, runner)
	}

	// Filter SaaS shared runners if on gitlab.com
	if isSaaS {
		result = filterSelfHostedRunners(result)
	}

	return result, nil
}

// createRunnerFromMetadata creates RunnerInfo from job metadata
func (p *Platform) createRunnerFromMetadata(job Job, description string) *RunnerInfo {
	runner := &RunnerInfo{
		Description: description,
		Source:      "logs",
		Online:      false, // Unknown from logs
		Active:      true,  // Assume active if used recently
	}

	// Extract additional metadata if available
	if job.Runner != nil {
		if isShared, ok := job.Runner["is_shared"].(bool); ok {
			runner.IsShared = isShared
		}
		if tags, ok := job.Runner["tag_list"].([]interface{}); ok {
			runner.Tags = make([]string, 0, len(tags))
			for _, tag := range tags {
				if tagStr, ok := tag.(string); ok {
					runner.Tags = append(runner.Tags, tagStr)
				}
			}
		}
	}

	// Set last seen timestamp from job
	if job.FinishedAt != "" {
		runner.LastSeenAt = job.FinishedAt
	}

	return runner
}

// logInfoToRunnerInfo converts parsed log info to RunnerInfo
func (p *Platform) logInfoToRunnerInfo(logInfo *RunnerLogInfo, job Job) RunnerInfo {
	return RunnerInfo{
		Description: logInfo.RunnerName,
		Version:     logInfo.Version,
		Platform:    logInfo.Platform,
		Executor:    logInfo.Executor,
		Tags:        logInfo.Tags,
		Source:      "logs",
		Online:      false, // Unknown from logs
		Active:      true,  // Assume active if used recently
		IsShared:    !logInfo.IsSelfHosted,
		LastSeenAt:  job.FinishedAt,
	}
}
