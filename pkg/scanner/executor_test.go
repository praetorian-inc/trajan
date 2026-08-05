package scanner

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

type mockPlugin struct {
	name     string
	findings []detections.Finding
	err      error
}

func (m *mockPlugin) Name() string {
	return m.name
}

func (m *mockPlugin) Platform() string {
	return "github"
}

func (m *mockPlugin) Severity() detections.Severity {
	return detections.SeverityHigh
}

func (m *mockPlugin) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.findings, nil
}

var validWorkflowYAML = []byte(`
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: echo "test"
`)

func TestDetectionExecutor_Execute_ErrorHandling(t *testing.T) {
	errorPlugin := &mockPlugin{
		name: "error-plugin",
		err:  assert.AnError,
	}
	goodPlugin := &mockPlugin{
		name: "good-plugin",
		findings: []detections.Finding{
			{Type: detections.VulnActionsInjection, Severity: detections.SeverityHigh},
		},
	}

	executor := NewDetectionExecutor([]detections.Detection{errorPlugin, goodPlugin}, 10)

	workflows := map[string][]platforms.Workflow{
		"owner/repo": {
			{Name: "ci.yml", Path: ".github/workflows/ci.yml", Content: validWorkflowYAML},
		},
	}

	result, err := executor.Execute(context.Background(), workflows)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, detections.VulnActionsInjection, result.Findings[0].Type)
	require.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0].Error(), "error-plugin")
}

func TestDetectionExecutor_Execute_InvalidWorkflow(t *testing.T) {
	mockPlugin := &mockPlugin{
		name: "test-plugin",
		findings: []detections.Finding{
			{Type: detections.VulnActionsInjection, Severity: detections.SeverityHigh},
		},
	}

	executor := NewDetectionExecutor([]detections.Detection{mockPlugin}, 10)

	invalidYAML := []byte(`this is not valid YAML: {{{`)

	workflows := map[string][]platforms.Workflow{
		"owner/repo": {
			{Name: "invalid.yml", Path: ".github/workflows/invalid.yml", Content: invalidYAML},
			{Name: "valid.yml", Path: ".github/workflows/valid.yml", Content: validWorkflowYAML},
		},
	}

	result, err := executor.Execute(context.Background(), workflows)
	require.NoError(t, err)
	assert.Len(t, result.Findings, 1)
	require.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0].Error(), "building graph")
}

type panicPlugin struct {
	name string
}

func (p *panicPlugin) Name() string {
	return p.name
}

func (p *panicPlugin) Platform() string {
	return "github"
}

func (p *panicPlugin) Severity() detections.Severity {
	return detections.SeverityHigh
}

func (p *panicPlugin) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	panic(fmt.Sprintf("plugin %s panicked!", p.name))
}

func TestDetectionExecutor_Execute_PanicRecovery(t *testing.T) {
	panicPlug := &panicPlugin{name: "panic-plugin"}
	goodPlugin := &mockPlugin{
		name: "good-plugin",
		findings: []detections.Finding{
			{Type: detections.VulnActionsInjection, Severity: detections.SeverityHigh},
		},
	}

	executor := NewDetectionExecutor([]detections.Detection{panicPlug, goodPlugin}, 10)

	workflows := map[string][]platforms.Workflow{
		"owner/repo": {
			{Name: "ci.yml", Path: ".github/workflows/ci.yml", Content: validWorkflowYAML},
		},
	}

	result, err := executor.Execute(context.Background(), workflows)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, detections.VulnActionsInjection, result.Findings[0].Type)
	require.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0].Error(), "panic-plugin")
	assert.Contains(t, result.Errors[0].Error(), "panic")
}

func TestDetectionExecutor_Execute_MultiplePanicRecovery(t *testing.T) {
	panicPlug := &panicPlugin{name: "panic-plugin"}

	executor := NewDetectionExecutor([]detections.Detection{panicPlug}, 10)

	workflows := map[string][]platforms.Workflow{
		"owner/repo1": {
			{Name: "ci.yml", Path: ".github/workflows/ci.yml", Content: validWorkflowYAML},
		},
		"owner/repo2": {
			{Name: "test.yml", Path: ".github/workflows/test.yml", Content: validWorkflowYAML},
		},
		"owner/repo3": {
			{Name: "release.yml", Path: ".github/workflows/release.yml", Content: validWorkflowYAML},
		},
	}

	result, err := executor.Execute(context.Background(), workflows)
	require.NoError(t, err)
	assert.Empty(t, result.Findings)
	// One recovered panic per workflow.
	require.Len(t, result.Errors, 3)
	for _, e := range result.Errors {
		assert.Contains(t, e.Error(), "panic-plugin")
		assert.Contains(t, e.Error(), "panic")
	}
}

func TestDetectionExecutor_Execute_PopulatesIncludedWorkflows(t *testing.T) {
	mockPlugin := &mockPlugin{
		name: "test-plugin",
		findings: []detections.Finding{
			{Type: detections.VulnActionsInjection, Severity: detections.SeverityHigh},
		},
	}

	executor := NewDetectionExecutor([]detections.Detection{mockPlugin}, 10)

	gitlabWorkflowWithInclude := []byte(`
include:
  - project: 'shared/templates'
    file: '/templates/security.yml'

test:
  script:
    - echo "test"
`)

	workflows := map[string][]platforms.Workflow{
		"group/project": {
			{
				Name:     ".gitlab-ci.yml",
				Path:     ".gitlab-ci.yml",
				Content:  gitlabWorkflowWithInclude,
				RepoSlug: "group/project",
				Metadata: map[string]interface{}{
					"included_workflow:shared/templates//templates/security.yml": platforms.Workflow{
						Name:     "security.yml",
						Path:     "/templates/security.yml",
						Content:  []byte("security: {script: ['security-scan']}"),
						RepoSlug: "shared/templates",
					},
				},
			},
		},
	}

	result, err := executor.Execute(context.Background(), workflows)
	require.NoError(t, err)
	assert.Len(t, result.Findings, 1)
	assert.Empty(t, result.Errors)

	assert.Contains(t, workflows, "shared/templates")
	require.Len(t, workflows["shared/templates"], 1)
	assert.Equal(t, "security.yml", workflows["shared/templates"][0].Name)
	assert.Equal(t, "/templates/security.yml", workflows["shared/templates"][0].Path)
}

func TestDetectionExecutor_Execute_MultipleIncludedWorkflows(t *testing.T) {
	mockPlugin := &mockPlugin{
		name: "test-plugin",
		findings: []detections.Finding{
			{Type: detections.VulnActionsInjection, Severity: detections.SeverityHigh},
		},
	}

	executor := NewDetectionExecutor([]detections.Detection{mockPlugin}, 10)

	gitlabWorkflow := []byte(`
include:
  - project: 'shared/templates'
    file: '/templates/security.yml'
  - project: 'shared/templates'
    file: '/templates/build.yml'
  - project: 'other/repo'
    file: '/ci/deploy.yml'

test:
  script:
    - echo "test"
`)

	workflows := map[string][]platforms.Workflow{
		"group/project": {
			{
				Name:     ".gitlab-ci.yml",
				Path:     ".gitlab-ci.yml",
				Content:  gitlabWorkflow,
				RepoSlug: "group/project",
				Metadata: map[string]interface{}{
					"included_workflow:shared/templates//templates/security.yml": platforms.Workflow{
						Name:     "security.yml",
						Path:     "/templates/security.yml",
						Content:  []byte("security: {script: ['scan']}"),
						RepoSlug: "shared/templates",
					},
					"included_workflow:shared/templates//templates/build.yml": platforms.Workflow{
						Name:     "build.yml",
						Path:     "/templates/build.yml",
						Content:  []byte("build: {script: ['make']}"),
						RepoSlug: "shared/templates",
					},
					"included_workflow:other/repo//ci/deploy.yml": platforms.Workflow{
						Name:     "deploy.yml",
						Path:     "/ci/deploy.yml",
						Content:  []byte("deploy: {script: ['deploy']}"),
						RepoSlug: "other/repo",
					},
				},
			},
		},
	}

	result, err := executor.Execute(context.Background(), workflows)
	require.NoError(t, err)
	assert.Len(t, result.Findings, 1)
	assert.Empty(t, result.Errors)

	assert.Contains(t, workflows, "shared/templates")
	assert.Len(t, workflows["shared/templates"], 2)

	assert.Contains(t, workflows, "other/repo")
	require.Len(t, workflows["other/repo"], 1)
	assert.Equal(t, "deploy.yml", workflows["other/repo"][0].Name)
}

type instanceDetectionPlugin struct {
	name string
}

func (p *instanceDetectionPlugin) Name() string                  { return p.name }
func (p *instanceDetectionPlugin) Platform() string              { return "jenkins" }
func (p *instanceDetectionPlugin) Severity() detections.Severity { return detections.SeverityHigh }

func (p *instanceDetectionPlugin) Detect(_ context.Context, g *graph.Graph) ([]detections.Finding, error) {
	if _, ok := g.GetMetadata("jenkins_client"); ok {
		return []detections.Finding{
			{
				Type:     detections.VulnJenkinsCSRFDisabled,
				Severity: detections.SeverityMedium,
				Evidence: "instance-level finding",
			},
		}, nil
	}
	return nil, nil
}

type callCountPlugin struct {
	name      string
	callCount int
	onDetect  func(g *graph.Graph)
}

func (p *callCountPlugin) Name() string                  { return p.name }
func (p *callCountPlugin) Platform() string              { return "github" }
func (p *callCountPlugin) Severity() detections.Severity { return detections.SeverityLow }

func (p *callCountPlugin) Detect(_ context.Context, g *graph.Graph) ([]detections.Finding, error) {
	p.callCount++
	if p.onDetect != nil {
		p.onDetect(g)
	}
	return nil, nil
}

func TestDetectionExecutor_Execute_InstanceLevelDetections(t *testing.T) {
	plugin := &instanceDetectionPlugin{name: "instance-detector"}
	executor := NewDetectionExecutor([]detections.Detection{plugin}, 10)

	executor.SetInstanceMetadata("jenkins_client", "mock-client")

	// nil workflows: an instance-level detection needs none.
	result, err := executor.Execute(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "should return exactly 1 instance-level finding")
	assert.Equal(t, detections.VulnJenkinsCSRFDisabled, result.Findings[0].Type)
	assert.Equal(t, "instance-level finding", result.Findings[0].Evidence)
}

func TestDetectionExecutor_Execute_NoInstanceDetectionsWithoutInstanceMetadata(t *testing.T) {
	counter := &callCountPlugin{name: "counter"}
	executor := NewDetectionExecutor([]detections.Detection{counter}, 10)

	// SetMetadata, not SetInstanceMetadata: the instance-level pass must not fire.
	executor.SetMetadata("runners", "linux")

	workflows := map[string][]platforms.Workflow{
		"owner/repo": {
			{Name: "ci.yml", Path: ".github/workflows/ci.yml", Content: validWorkflowYAML},
		},
	}

	_, err := executor.Execute(context.Background(), workflows)
	require.NoError(t, err)

	assert.Equal(t, 1, counter.callCount,
		"plugin should be called once for the workflow, not again for instance-level")
}
