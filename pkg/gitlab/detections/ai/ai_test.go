package ai

import (
	"context"
	"testing"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
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
	assert.Equal(t, "gitlab", d.Platform())
	assert.Equal(t, detections.SeverityMedium, d.Severity())
}

// ---------------------------------------------------------------------------
// Token Exfiltration
// ---------------------------------------------------------------------------

func TestTokenExfiltration_AIScriptWithToken(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", ".gitlab-ci.yml", ".gitlab-ci.yml", "group/repo", []string{"merge_request"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "ai-review", "")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "AI Review", 10)
	step.Run = "npx claude-code review $CI_MERGE_REQUEST_TITLE"
	step.Env = map[string]string{
		"TOKEN": "$CI_JOB_TOKEN",
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
	assert.Equal(t, "gitlab", tokenFindings[0].Platform)
}

func TestTokenExfiltration_NoToken(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", ".gitlab-ci.yml", ".gitlab-ci.yml", "group/repo", []string{"merge_request"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "ai-review", "")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "AI Review", 10)
	step.Run = "npx claude-code review $CI_MERGE_REQUEST_TITLE"
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

func TestCodeInjection_AIScriptWithUntrustedInput(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", ".gitlab-ci.yml", ".gitlab-ci.yml", "group/repo", []string{"merge_request"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "ai-review", "")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "AI Review", 10)
	step.Run = "npx coderabbit review --title $CI_MERGE_REQUEST_TITLE"
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	codeFindings := findingsByType(findings, detections.VulnAICodeInjection)
	require.Len(t, codeFindings, 1)
	assert.Equal(t, detections.SeverityMedium, codeFindings[0].Severity)
	assert.Equal(t, detections.ConfidenceHigh, codeFindings[0].Confidence)
}

func TestCodeInjection_AIScriptNoUntrustedInput(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", ".gitlab-ci.yml", ".gitlab-ci.yml", "group/repo", []string{"merge_request"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "ai-review", "")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "AI Review", 10)
	step.Run = "npx coderabbit review --all"
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

func TestMCPAbuse_AIScriptWithMCPAndToken(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", ".gitlab-ci.yml", ".gitlab-ci.yml", "group/repo", []string{"merge_request"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "ai-review", "")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "AI Review", 10)
	step.Run = "npx claude-code review"
	step.Env = map[string]string{
		"MCP_ENABLED": "true",
		"TOKEN":       "$CI_JOB_TOKEN",
	}
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	mcpFindings := findingsByType(findings, detections.VulnAIMCPAbuse)
	require.Len(t, mcpFindings, 1)
	assert.Equal(t, detections.SeverityLow, mcpFindings[0].Severity)
	assert.Equal(t, detections.ConfidenceHigh, mcpFindings[0].Confidence)
}

func TestMCPAbuse_AIScriptWithMCPAndUntrusted(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", ".gitlab-ci.yml", ".gitlab-ci.yml", "group/repo", []string{"merge_request"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "ai-review", "")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "AI Review", 10)
	step.Run = "npx claude-code review $CI_MERGE_REQUEST_TITLE"
	step.Env = map[string]string{
		"MCP_SERVER_URL": "https://mcp.example.com",
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
func TestMCPAbuse_AIScriptWithMCPAndUntrustedOnly(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", ".gitlab-ci.yml", ".gitlab-ci.yml", "group/repo", []string{"merge_request"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "ai-review", "")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "AI Review", 10)
	step.Run = "npx claude-code review $CI_MERGE_REQUEST_TITLE"
	step.Env = map[string]string{
		"MCP_SERVER_URL": "https://mcp.example.com",
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

func TestNonAIScript_NoFindings(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", ".gitlab-ci.yml", ".gitlab-ci.yml", "group/repo", []string{"merge_request"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "Build", 10)
	step.Run = "npm ci && npm test $CI_MERGE_REQUEST_TITLE"
	step.Env = map[string]string{
		"TOKEN": "$CI_JOB_TOKEN",
	}
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)
	assert.Empty(t, findings)
}
