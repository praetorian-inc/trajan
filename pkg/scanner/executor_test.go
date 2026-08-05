// pkg/scanner/executor_test.go
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

// mockPlugin is a test plugin that returns predefined findings
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

// validWorkflowYAML is a minimal valid GitHub Actions workflow
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
	// Plugin that returns an error should not stop execution
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
	// Should not fail even though one plugin errored
	require.NoError(t, err)
	// Should still get finding from good plugin
	require.Len(t, result.Findings, 1)
	assert.Equal(t, detections.VulnActionsInjection, result.Findings[0].Type)
	// Should have captured the error from error-plugin
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
	// Should not fail entire execution
	require.NoError(t, err)
	// Should still get findings from valid workflow
	assert.Len(t, result.Findings, 1)
	// Should have captured the error from invalid workflow
	require.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0].Error(), "building graph")
}

// panicPlugin is a test plugin that panics during Detect
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
	// Plugin that panics should be recovered and not crash the scan
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
	// Should not crash even though one plugin panicked
	require.NoError(t, err)
	// Should still get finding from good plugin
	require.Len(t, result.Findings, 1)
	assert.Equal(t, detections.VulnActionsInjection, result.Findings[0].Type)
	// Should have captured the panic as an error
	require.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0].Error(), "panic-plugin")
	assert.Contains(t, result.Errors[0].Error(), "panic")
}

func TestDetectionExecutor_Execute_MultiplePanicRecovery(t *testing.T) {
	// Multiple workflows with panicking plugin should all be recovered
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
	// Should not crash
	require.NoError(t, err)
	// No findings since plugin panicked
	assert.Empty(t, result.Findings)
	// Should have captured 3 panics (one per workflow)
	require.Len(t, result.Errors, 3)
	for _, e := range result.Errors {
		assert.Contains(t, e.Error(), "panic-plugin")
		assert.Contains(t, e.Error(), "panic")
	}
}

func TestDetectionExecutor_Execute_PopulatesIncludedWorkflows(t *testing.T) {
	// Test that executor extracts included workflows from graph and adds them to workflows map
	mockPlugin := &mockPlugin{
		name: "test-plugin",
		findings: []detections.Finding{
			{Type: detections.VulnActionsInjection, Severity: detections.SeverityHigh},
		},
	}

	executor := NewDetectionExecutor([]detections.Detection{mockPlugin}, 10)

	// GitLab workflow with include
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
					// Mock GitLab client would be here in real scenario
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

	// Verify included workflow was added to workflows map
	assert.Contains(t, workflows, "shared/templates")
	require.Len(t, workflows["shared/templates"], 1)
	assert.Equal(t, "security.yml", workflows["shared/templates"][0].Name)
	assert.Equal(t, "/templates/security.yml", workflows["shared/templates"][0].Path)
}

func TestDetectionExecutor_Execute_MultipleIncludedWorkflows(t *testing.T) {
	// Test that multiple included workflows from same and different repos are handled correctly
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

	// Verify included workflows from shared/templates
	assert.Contains(t, workflows, "shared/templates")
	assert.Len(t, workflows["shared/templates"], 2)

	// Verify included workflow from other/repo
	assert.Contains(t, workflows, "other/repo")
	require.Len(t, workflows["other/repo"], 1)
	assert.Equal(t, "deploy.yml", workflows["other/repo"][0].Name)
}

// instanceDetectionPlugin returns a finding when the graph contains
// "jenkins_client" metadata, simulating a Jenkins instance-level detection.
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

// callCountPlugin counts how many times Detect is called. An optional
// onDetect callback runs on each invocation.
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

	// Pass nil workflows -- instance-level detections do not require workflows.
	result, err := executor.Execute(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "should return exactly 1 instance-level finding")
	assert.Equal(t, detections.VulnJenkinsCSRFDisabled, result.Findings[0].Type)
	assert.Equal(t, "instance-level finding", result.Findings[0].Evidence)
}

func TestDetectionExecutor_Execute_NoInstanceDetectionsWithoutInstanceMetadata(t *testing.T) {
	counter := &callCountPlugin{name: "counter"}
	executor := NewDetectionExecutor([]detections.Detection{counter}, 10)

	// Only set workflow-level metadata, NOT instance metadata.
	executor.SetMetadata("runners", "linux")

	workflows := map[string][]platforms.Workflow{
		"owner/repo": {
			{Name: "ci.yml", Path: ".github/workflows/ci.yml", Content: validWorkflowYAML},
		},
	}

	_, err := executor.Execute(context.Background(), workflows)
	require.NoError(t, err)

	// Plugin should be called exactly 1 time (for the single workflow).
	// Without instance metadata the instance-level loop should NOT fire.
	assert.Equal(t, 1, counter.callCount,
		"plugin should be called once for the workflow, not again for instance-level")
}
