// pkg/analysis/parser/workflow.go
// This file provides backward-compatible type aliases for the original GitHub-only API.
// New code should use the WorkflowParser interface from parser.go for multi-platform support.
package parser

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Backward-compatible type aliases for existing code
// These map to the GitHub-specific types in github.go

// Workflow is a backward-compatible alias for GitHubWorkflow
//
// Deprecated: Use WorkflowParser.Parse() for new code
type Workflow = GitHubWorkflow

// Job is a backward-compatible alias for GitHubJob
//
// Deprecated: Use the generic Job type from parser.go for new code
type Job = GitHubJob

// Step is a backward-compatible alias for GitHubStep
//
// Deprecated: Use the generic Step type from parser.go for new code
type Step = GitHubStep

// Defaults is a backward-compatible alias for GitHubDefaults
type Defaults = GitHubDefaults

// RunDefaults is a backward-compatible alias for GitHubRunDefaults
type RunDefaults = GitHubRunDefaults

// Strategy is a backward-compatible alias for GitHubStrategy
type Strategy = GitHubStrategy

// Service is a backward-compatible alias for GitHubService
// Note: This shadows the generic Service type from parser.go when using this alias
type Service = GitHubService

// ParseWorkflow parses a GitHub Actions workflow YAML
//
// Deprecated: Use WorkflowParser.Parse() for new code that needs multi-platform support
func ParseWorkflow(data []byte) (*Workflow, error) {
	var wf Workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("parsing workflow: %w", err)
	}
	return &wf, nil
}
