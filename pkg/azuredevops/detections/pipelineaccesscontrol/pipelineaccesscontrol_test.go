package pipelineaccesscontrol

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestPipelineAccessControlDetection_Detect_EnvironmentInWith(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "deploy", 10)
	step.With = map[string]string{
		"environment": "production",
		"action":      "deploy",
	}
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find environment reference")

	finding := findings[0]
	assert.Equal(t, detections.VulnEnvironmentBypass, finding.Type)
	assert.Equal(t, detections.ClassPrivilegeEscalation, finding.Class)
	assert.Equal(t, platforms.PlatformAzureDevOps, finding.Platform)
}

func TestPipelineAccessControlDetection_Detect_EnvironmentNameInWith(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "deploy", 20)
	step.With = map[string]string{
		"environmentName": "staging",
	}
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find environmentName reference")
}

func TestPipelineAccessControlDetection_Detect_EnvironmentInRun(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "deploy-script", 30)
	step.Run = "environment: production\ndeploy.sh"
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find environment YAML pattern in Run")
}

func TestPipelineAccessControlDetection_Detect_NoEnvironmentReference(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "build", 40)
	step.Run = "npm run build"
	step.With = map[string]string{
		"action": "build",
	}
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings without environment reference")
}

func TestPipelineAccessControlDetection_Detect_CaseInsensitiveMatch(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "deploy", 50)
	step.With = map[string]string{
		"ENVIRONMENT": "production",
	}
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find ENVIRONMENT (uppercase) reference")
}

func TestPipelineAccessControlDetection_Detect_ExcessiveBuildAdminPermissions(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "ubuntu-latest")
	job.Permissions = map[string]string{
		"build": "admin",
	}
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)

	found := false
	for _, f := range findings {
		if f.Type == detections.VulnExcessiveJobPermissions {
			found = true
			assert.Equal(t, detections.SeverityLow, f.Severity)
			assert.Equal(t, detections.ClassPrivilegeEscalation, f.Class)
		}
	}
	assert.True(t, found, "Expected VulnExcessiveJobPermissions finding for build:admin")
}

func TestPipelineAccessControlDetection_Detect_SafeReadOnlyPermissions(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "read-only", "ubuntu-latest")
	job.Permissions = map[string]string{
		"build": "read",
	}
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)

	for _, f := range findings {
		assert.NotEqual(t, detections.VulnExcessiveJobPermissions, f.Type,
			"Expected no VulnExcessiveJobPermissions for read-only build permission")
	}
}

func TestPipelineAccessControlDetection_Detect_VariableGroupInEnv(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "use-vargroup", 10)
	step.Run = "deploy.sh"
	step.Env = map[string]string{
		"MY_VAR": "variablegroups/my-group",
	}
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)

	found := false
	for _, f := range findings {
		if f.Type == detections.VulnSecretScopeRisk {
			found = true
			assert.Equal(t, detections.SeverityLow, f.Severity)
		}
	}
	assert.True(t, found, "Expected VulnSecretScopeRisk finding for variablegroups in env")
}

func TestPipelineAccessControlDetection_FindingLine_VariableGroupPointsToEnvKey(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	// Step starts at 21; the vulnerable env key GROUP_API_KEY is at 24.
	step := graph.NewStepNode("step1", "use-vargroup", 21)
	step.Run = "deploy.sh"
	step.Env = map[string]string{
		"GROUP_API_KEY": "$(variablegroups.my-group.api-key)",
	}
	step.EnvLines = map[string]int{
		"GROUP_API_KEY": 24,
	}
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)

	var scopeFinding *detections.Finding
	for i := range findings {
		if findings[i].Type == detections.VulnSecretScopeRisk {
			scopeFinding = &findings[i]
			break
		}
	}
	require.NotNil(t, scopeFinding, "Expected VulnSecretScopeRisk finding")
	assert.Equal(t, 24, scopeFinding.Line,
		"Finding Line should point to the GROUP_API_KEY env key (24), not the step start (21)")
}

func TestPipelineAccessControlDetection_FindingLine_VariableGroupFallsBackToStepLine(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	// Step at line 50, with no EnvLines.
	step := graph.NewStepNode("step1", "use-vargroup-no-lines", 50)
	step.Run = "deploy.sh"
	step.Env = map[string]string{
		"GROUP_API_KEY": "$(variablegroups.my-group.api-key)",
	}
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)

	var scopeFinding *detections.Finding
	for i := range findings {
		if findings[i].Type == detections.VulnSecretScopeRisk {
			scopeFinding = &findings[i]
			break
		}
	}
	require.NotNil(t, scopeFinding, "Expected VulnSecretScopeRisk finding")
	assert.Equal(t, 50, scopeFinding.Line,
		"Finding Line should fall back to step start (50) when EnvLines is nil")
}

func TestPipelineAccessControlDetection_Detect_NoVariableGroupReference(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "normal-step", 10)
	step.Run = "build.sh"
	step.Env = map[string]string{
		"APP_ENV":   "production",
		"LOG_LEVEL": "info",
	}
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)

	for _, f := range findings {
		assert.NotEqual(t, detections.VulnSecretScopeRisk, f.Type,
			"Expected no VulnSecretScopeRisk for normal env variables")
	}
}
