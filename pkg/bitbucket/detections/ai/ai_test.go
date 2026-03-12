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
	assert.Equal(t, "bitbucket", d.Platform())
	assert.Equal(t, detections.SeverityMedium, d.Severity())
}

// ---------------------------------------------------------------------------
// Token Exfiltration
// ---------------------------------------------------------------------------

func TestTokenExfiltration_AIPipeWithToken(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "bitbucket-pipelines.yml", "bitbucket-pipelines.yml", "owner/repo", []string{"pull_request"})
	wf.AddTag(graph.TagPullRequest)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "ai-review", "default")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "AI Review", 10)
	step.Uses = "coderabbit/ai-review-pipe:1.0.0"
	step.With = map[string]string{
		"TITLE": "$BITBUCKET_BRANCH",
		"TOKEN": "$BITBUCKET_ACCESS_TOKEN",
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
	assert.Equal(t, "bitbucket", tokenFindings[0].Platform)
}

func TestTokenExfiltration_NoToken(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "bitbucket-pipelines.yml", "bitbucket-pipelines.yml", "owner/repo", []string{"pull_request"})
	wf.AddTag(graph.TagPullRequest)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "ai-review", "default")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "AI Review", 10)
	step.Uses = "coderabbit/ai-review-pipe:1.0.0"
	step.With = map[string]string{
		"TITLE": "$BITBUCKET_BRANCH",
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

func TestCodeInjection_AIPipeWithUntrustedInput(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "bitbucket-pipelines.yml", "bitbucket-pipelines.yml", "owner/repo", []string{"pull_request"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "ai-review", "default")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "AI Review", 10)
	step.Uses = "coderabbit/ai-review-pipe:1.0.0"
	step.With = map[string]string{
		"TITLE": "$BITBUCKET_BRANCH",
	}
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	codeFindings := findingsByType(findings, detections.VulnAICodeInjection)
	require.Len(t, codeFindings, 1)
	assert.Equal(t, detections.SeverityMedium, codeFindings[0].Severity)
}

func TestCodeInjection_AIPipeNoUntrustedInput(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "bitbucket-pipelines.yml", "bitbucket-pipelines.yml", "owner/repo", []string{"pull_request"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "ai-review", "default")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "AI Review", 10)
	step.Uses = "coderabbit/ai-review-pipe:1.0.0"
	step.With = map[string]string{
		"MODE": "full",
	}
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

func TestMCPAbuse_AIPipeWithMCPAndToken(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "bitbucket-pipelines.yml", "bitbucket-pipelines.yml", "owner/repo", []string{"pull_request"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "ai-review", "default")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "AI Review", 10)
	step.Uses = "claude-ai/review-pipe:1.0.0"
	step.Env = map[string]string{
		"MCP_ENABLED": "true",
		"TOKEN":       "$BITBUCKET_ACCESS_TOKEN",
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

// Finding 19: MCP + untrusted input only (no token) -> LOW severity
func TestMCPAbuse_AIPipeWithMCPAndUntrustedOnly(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "bitbucket-pipelines.yml", "bitbucket-pipelines.yml", "owner/repo", []string{"pull_request"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "ai-review", "default")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "AI Review", 10)
	step.Uses = "coderabbit/ai-review-pipe:1.0.0"
	step.With = map[string]string{
		"TITLE": "$BITBUCKET_BRANCH",
	}
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

func TestNonAIPipe_NoFindings(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "bitbucket-pipelines.yml", "bitbucket-pipelines.yml", "owner/repo", []string{"pull_request"})
	wf.AddTag(graph.TagPullRequest)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "default")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "Deploy", 10)
	step.Uses = "atlassian/aws-s3-deploy:1.0.0"
	step.With = map[string]string{
		"TITLE": "$BITBUCKET_BRANCH",
		"TOKEN": "$BITBUCKET_ACCESS_TOKEN",
	}
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)
	assert.Empty(t, findings)
}
