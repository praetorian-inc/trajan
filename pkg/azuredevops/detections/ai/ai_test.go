package ai

import (
	"context"
	"testing"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func findingsByType(findings []detections.Finding, t detections.VulnerabilityType) []detections.Finding {
	var result []detections.Finding
	for _, f := range findings {
		if f.Type == t {
			result = append(result, f)
		}
	}
	return result
}

func TestAIRisk_Properties(t *testing.T) {
	d := New()
	assert.Equal(t, "ai-risk", d.Name())
	assert.Equal(t, platforms.PlatformAzureDevOps, d.Platform())
	assert.Equal(t, detections.SeverityMedium, d.Severity())
}

// ---------------------------------------------------------------------------
// Token Exfiltration
// ---------------------------------------------------------------------------

func TestTokenExfiltration_AITaskWithToken(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "org/project", []string{"pr"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "ai-review", "ubuntu-latest")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "AI Review", 10)
	step.Uses = "copilot-ai/review-task@v1"
	step.Env = map[string]string{
		"SYSTEM_ACCESSTOKEN": "$(System.AccessToken)",
		"INPUT":              "$(Build.SourceVersionMessage)",
	}
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	tokenFindings := findingsByType(findings, detections.VulnAITokenExfiltration)
	require.Len(t, tokenFindings, 1)
	assert.Equal(t, detections.SeverityMedium, tokenFindings[0].Severity)
	assert.Equal(t, detections.ConfidenceHigh, tokenFindings[0].Confidence)
	assert.Equal(t, platforms.PlatformAzureDevOps, tokenFindings[0].Platform)
}

func TestTokenExfiltration_NoToken(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "org/project", []string{"pr"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "ai-review", "ubuntu-latest")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "AI Review", 10)
	step.Uses = "copilot-ai/review-task@v1"
	step.Env = map[string]string{
		"INPUT": "$(Build.SourceVersionMessage)",
	}
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	tokenFindings := findingsByType(findings, detections.VulnAITokenExfiltration)
	assert.Empty(t, tokenFindings)
}

// ---------------------------------------------------------------------------
// Code Injection
// ---------------------------------------------------------------------------

func TestCodeInjection_AITaskWithUntrustedInput(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "org/project", []string{"pr"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "ai-review", "ubuntu-latest")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "AI Review", 10)
	step.Uses = "claude-ai/review-task@v1"
	step.Run = "echo $(Build.SourceVersionMessage)"
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	codeFindings := findingsByType(findings, detections.VulnAICodeInjection)
	require.Len(t, codeFindings, 1)
	assert.Equal(t, detections.SeverityMedium, codeFindings[0].Severity)
}

func TestCodeInjection_AITaskNoUntrustedInput(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "org/project", []string{"pr"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "ai-review", "ubuntu-latest")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "AI Review", 10)
	step.Uses = "claude-ai/review-task@v1"
	step.Run = "echo reviewing code"
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	codeFindings := findingsByType(findings, detections.VulnAICodeInjection)
	assert.Empty(t, codeFindings)
}

// ---------------------------------------------------------------------------
// MCP Abuse
// ---------------------------------------------------------------------------

func TestMCPAbuse_AITaskWithMCPAndToken(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "org/project", []string{"pr"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "ai-review", "ubuntu-latest")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "AI Review", 10)
	step.Uses = "claude-ai/review-task@v1"
	step.Env = map[string]string{
		"MCP_ENABLED":        "true",
		"SYSTEM_ACCESSTOKEN": "$(System.AccessToken)",
	}
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	mcpFindings := findingsByType(findings, detections.VulnAIMCPAbuse)
	require.Len(t, mcpFindings, 1)
	assert.Equal(t, detections.SeverityLow, mcpFindings[0].Severity)
}

// Finding 19: MCP + untrusted input only (no token) -> MEDIUM severity
func TestMCPAbuse_AITaskWithMCPAndUntrustedOnly(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "org/project", []string{"pr"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "ai-review", "ubuntu-latest")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "AI Review", 10)
	step.Uses = "claude-ai/review-task@v1"
	step.Run = "echo $(Build.SourceVersionMessage)"
	step.Env = map[string]string{
		"MCP_ENABLED": "true",
	}
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	mcpFindings := findingsByType(findings, detections.VulnAIMCPAbuse)
	require.Len(t, mcpFindings, 1)
	assert.Equal(t, detections.SeverityLow, mcpFindings[0].Severity,
		"MCP + untrusted input only (no token) should be LOW severity")
	assert.Equal(t, detections.ConfidenceMedium, mcpFindings[0].Confidence)
}

// ---------------------------------------------------------------------------
// Edge Cases
// ---------------------------------------------------------------------------

func TestNonAITask_NoFindings(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "org/project", []string{"pr"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "ubuntu-latest")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "Build", 10)
	step.Uses = "DotNetCoreCLI@2"
	step.Env = map[string]string{
		"SYSTEM_ACCESSTOKEN": "$(System.AccessToken)",
		"INPUT":              "$(Build.SourceVersionMessage)",
	}
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)
	assert.Empty(t, findings)
}
