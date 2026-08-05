package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/praetorian-inc/trajan/pkg/analysis"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

type DetectionExecutor struct {
	plugins          []detections.Detection
	concurrency      int64
	cache            *ScanResultCache
	metadata         map[string]interface{} // flows into every per-workflow graph
	instanceMetadata map[string]interface{} // instance-level detections only, never a workflow graph
	mu               sync.Mutex             // guards discoveredWorkflows writes
}

type ExecutionResult struct {
	Findings []detections.Finding
	Errors   []error
}

func NewDetectionExecutor(plugins []detections.Detection, concurrency int) *DetectionExecutor {
	if concurrency <= 0 {
		concurrency = 10
	}
	return &DetectionExecutor{
		plugins:     plugins,
		concurrency: int64(concurrency),
		metadata:    make(map[string]interface{}),
	}
}

func (e *DetectionExecutor) SetMetadata(key string, value interface{}) {
	if e.metadata == nil {
		e.metadata = make(map[string]interface{})
	}
	e.metadata[key] = value
}

// Unlike SetMetadata, these values never reach a per-workflow graph.
func (e *DetectionExecutor) SetInstanceMetadata(key string, value interface{}) {
	if e.instanceMetadata == nil {
		e.instanceMetadata = make(map[string]interface{})
	}
	e.instanceMetadata[key] = value
}

func (e *DetectionExecutor) Execute(ctx context.Context, workflows map[string][]platforms.Workflow) (*ExecutionResult, error) {
	g, gCtx := errgroup.WithContext(ctx)
	sem := semaphore.NewWeighted(e.concurrency)

	var mu sync.Mutex
	result := &ExecutionResult{
		Findings: make([]detections.Finding, 0),
		Errors:   make([]error, 0),
	}

	// A separate map: goroutines must never write the workflows map that the
	// range loop below is iterating.
	discoveredWorkflows := make(map[string][]platforms.Workflow)

	for repoSlug, wfs := range workflows {
		repoSlug := repoSlug
		wfs := wfs

		for _, wf := range wfs {
			wf := wf

			if err := sem.Acquire(gCtx, 1); err != nil {
				return result, err
			}

			g.Go(func() error {
				defer sem.Release(1)
				defer func() {
					if r := recover(); r != nil {
						panicErr := fmt.Errorf("panic in workflow execution for %s: %v", repoSlug, r)
						mu.Lock()
						result.Errors = append(result.Errors, panicErr)
						mu.Unlock()
						slog.Error("workflow execution panic",
							"repo", repoSlug,
							"panic", r)
					}
				}()

				if e.cache != nil {
					if cached, ok := e.cache.Get(repoSlug, wf.Path, string(wf.Content)); ok {
						mu.Lock()
						result.Findings = append(result.Findings, cached...)
						mu.Unlock()
						return nil
					}
				}

				findings, errs := e.executeOnWorkflow(gCtx, repoSlug, wf, discoveredWorkflows)

				if e.cache != nil {
					e.cache.Set(repoSlug, wf.Path, string(wf.Content), findings)
				}

				mu.Lock()
				result.Findings = append(result.Findings, findings...)
				result.Errors = append(result.Errors, errs...)
				mu.Unlock()

				for _, err := range errs {
					slog.Warn("workflow execution error", "error", err)
				}

				return nil
			})
		}
	}

	if err := g.Wait(); err != nil {
		return result, err
	}

	// After g.Wait(): the range loop above iterated this same map, so nothing
	// may mutate it while the goroutines are live.
	for slug, wfs := range discoveredWorkflows {
		workflows[slug] = append(workflows[slug], wfs...)
	}

	// Instance-level detections need only platform metadata, not parsed workflows.
	if len(e.instanceMetadata) > 0 {
		instanceGraph := graph.NewGraph()
		for k, v := range e.instanceMetadata {
			instanceGraph.SetMetadata(k, v)
		}
		for _, plugin := range e.plugins {
			pFindings, err := plugin.Detect(ctx, instanceGraph)
			if err != nil {
				slog.Warn("instance-level detection error", "plugin", plugin.Name(), "error", err)
				continue
			}
			result.Findings = append(result.Findings, pFindings...)
		}
	}

	return result, nil
}

// Include-directive discoveries go into discoveredWorkflows under e.mu, never
// the caller's map, which Execute's range loop is still iterating.
func (e *DetectionExecutor) executeOnWorkflow(ctx context.Context, repoSlug string, wf platforms.Workflow, discoveredWorkflows map[string][]platforms.Workflow) ([]detections.Finding, []error) {
	var findings []detections.Finding
	var errs []error

	// Workflow metadata (e.g. gitlab_client) overrides executor metadata.
	mergedMetadata := make(map[string]interface{})
	for k, v := range e.metadata {
		mergedMetadata[k] = v
	}
	if wf.Metadata != nil {
		for k, v := range wf.Metadata {
			mergedMetadata[k] = v
		}
	}

	gr, err := analysis.BuildGraph(repoSlug, wf.Path, wf.Content, mergedMetadata)
	if err != nil {
		return nil, []error{fmt.Errorf("building graph for %s/%s: %w", repoSlug, wf.Path, err)}
	}

	includedWorkflows := gr.GetIncludedWorkflows(repoSlug)
	if len(includedWorkflows) > 0 {
		e.mu.Lock()
		for _, incWf := range includedWorkflows {
			discoveredWorkflows[incWf.RepoSlug] = append(discoveredWorkflows[incWf.RepoSlug], incWf)
		}
		e.mu.Unlock()
	}

	for _, plugin := range e.plugins {
		func() {
			defer func() {
				if r := recover(); r != nil {
					// One panicking plugin must not sink the scan.
					errs = append(errs, fmt.Errorf("plugin %s on %s/%s: panic: %v", plugin.Name(), repoSlug, wf.Path, r))
					slog.Warn("plugin panic recovered",
						"plugin", plugin.Name(),
						"repo", repoSlug,
						"workflow", wf.Path,
						"panic", r)
				}
			}()

			pFindings, err := plugin.Detect(ctx, gr)
			if err != nil {
				errs = append(errs, fmt.Errorf("plugin %s on %s/%s: %w", plugin.Name(), repoSlug, wf.Path, err))
				return
			}
			findings = append(findings, pFindings...)
		}()
	}

	return findings, errs
}
