package parser

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Deprecated: Use WorkflowParser.Parse() for new code
type Workflow = GitHubWorkflow

// Deprecated: Use the generic Job type from parser.go for new code
type Job = GitHubJob

// Deprecated: Use the generic Step type from parser.go for new code
type Step = GitHubStep

type Defaults = GitHubDefaults

type RunDefaults = GitHubRunDefaults

type Strategy = GitHubStrategy

type Service = GitHubService

// Deprecated: Use WorkflowParser.Parse() for new code that needs multi-platform support
func ParseWorkflow(data []byte) (*Workflow, error) {
	var wf Workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("parsing workflow: %w", err)
	}
	return &wf, nil
}
