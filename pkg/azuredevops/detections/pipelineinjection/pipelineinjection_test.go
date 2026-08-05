package pipelineinjection

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestPipelineInjectionDetection_Detect_ParametersInScript(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step with parameter interpolation in script
	step := graph.NewStepNode("step1", "deploy", 10)
	step.Run = "echo ${{ parameters.deployTarget }}"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.Len(t, findings, 1, "Expected to find template injection")

	finding := findings[0]
	assert.Equal(t, detections.VulnScriptInjection, finding.Type)
	assert.Equal(t, platforms.PlatformAzureDevOps, finding.Platform, "Finding platform should be 'azuredevops'")
	assert.Equal(t, detections.SeverityHigh, finding.Severity)
}

func TestPipelineInjectionDetection_Detect_VariablesInScript(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step with variable interpolation in script
	step := graph.NewStepNode("step1", "build", 15)
	step.Run = "npm run ${{ variables.buildScript }}"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find template injection")

	finding := findings[0]
	assert.Equal(t, detections.VulnScriptInjection, finding.Type)
	assert.Equal(t, detections.SeverityHigh, finding.Severity)
	// Medium, unlike the parameters branch's High: a variable may or may not carry
	// PR-controlled content, and that difference is the point of this branch.
	assert.Equal(t, detections.ConfidenceMedium, finding.Confidence)
	assert.Equal(t, "${{ variables.buildScript }}", finding.Evidence)
}

func TestPipelineInjectionDetection_Detect_SafeStaticScript(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step with safe static script
	step := graph.NewStepNode("step1", "test", 20)
	step.Run = "npm test"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for safe script")
}

func TestPipelineInjectionDetection_Detect_SafeSystemVariables(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "info", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step with safe system variables (runtime macro syntax, not template expression)
	step := graph.NewStepNode("step1", "info", 25)
	step.Run = "echo $(Build.BuildId)"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for runtime macro system variables")
}

func TestPipelineInjectionDetection_Detect_MacroInjection_InjectableVariable(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Macro syntax with injectable variable should be flagged
	step := graph.NewStepNode("step1", "build", 50)
	step.Run = "echo $(Build.SourceBranch)"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected finding for injectable macro variable $(Build.SourceBranch)")

	finding := findings[0]
	assert.Equal(t, detections.SeverityHigh, finding.Severity)
	assert.Contains(t, finding.Evidence, "Build.SourceBranch")
}

func TestPipelineInjectionDetection_Detect_DynamicTemplateReference(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step with template reference using parameters
	step := graph.NewStepNode("step1", "deploy-step", 30)
	step.Uses = "template:${{ parameters.templatePath }}"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find dynamic template reference")

	finding := findings[0]
	assert.Equal(t, detections.SeverityCritical, finding.Severity, "Dynamic template reference should be Critical severity")
	assert.Equal(t, detections.VulnDynamicTemplateInjection, finding.Type, "Dynamic template reference should be VulnDynamicTemplateInjection")
}

func TestPipelineInjectionDetection_Detect_MultipleInjections(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create multiple steps with different injection patterns
	step1 := graph.NewStepNode("step1", "step1", 10)
	step1.Run = "echo ${{ parameters.userInput }}"
	step1.SetParent(job.ID())
	g.AddNode(step1)
	g.AddEdge(job.ID(), step1.ID(), graph.EdgeContains)

	step2 := graph.NewStepNode("step2", "step2", 15)
	step2.Run = "curl ${{ variables.apiUrl }}"
	step2.SetParent(job.ID())
	g.AddNode(step2)
	g.AddEdge(job.ID(), step2.ID(), graph.EdgeContains)

	step3 := graph.NewStepNode("step3", "step3", 20)
	step3.Uses = "template:${{ parameters.templateName }}"
	step3.SetParent(job.ID())
	g.AddNode(step3)
	g.AddEdge(job.ID(), step3.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Len(t, findings, 3, "Expected 3 findings for multiple injections")
}

func TestPipelineInjectionDetection_Detect_NoRunOrUses(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "checkout", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step with neither run nor uses (e.g., checkout step)
	step := graph.NewStepNode("step1", "checkout", 5)
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for step without run/uses")
}

// TestPipelineInjectionDetection_Detect_SafeBuildIdVariable tests that safe system variables
// using underscore notation (e.g., Build_BuildId) are NOT flagged
func TestPipelineInjectionDetection_Detect_SafeBuildIdVariable(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "info", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step using safe system variable with underscore notation
	step := graph.NewStepNode("step1", "info", 25)
	step.Run = "echo Build ID: ${{ variables.Build_BuildId }}"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for safe Build_BuildId system variable")
}

func TestPipelineInjectionDetection_Detect_SafeSystemVariables_MultipleSafe(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "info", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Test multiple safe system variables using underscore notation
	safeVariables := []string{
		"Build_BuildNumber",
		"Build_Repository_Name",
		"System_TeamProject",
		"System_CollectionUri",
		"Agent_BuildDirectory",
	}

	for i, safeVar := range safeVariables {
		step := graph.NewStepNode("step"+string(rune('a'+i)), "info-step", 30+i)
		step.Run = "echo " + safeVar + ": ${{ variables." + safeVar + " }}"
		step.SetParent(job.ID())
		g.AddNode(step)
		g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)
	}

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for safe system variables")
}

func TestPipelineInjectionDetection_Detect_UnsafeUserDefinedVariable(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// User-defined variables (not system variables) should still be flagged
	step := graph.NewStepNode("step1", "build", 35)
	step.Run = "npm run ${{ variables.userDefinedScript }}"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find unsafe user-defined variable")

	finding := findings[0]
	assert.Equal(t, detections.SeverityHigh, finding.Severity, "User-defined variable should be High severity")
}

// TestPipelineInjectionDetection_Detect_RuntimeExpressionWithParameter tests detection of
// $[ ] runtime expression syntax with parameters
func TestPipelineInjectionDetection_Detect_RuntimeExpressionWithParameter(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Runtime expressions use $[ ] syntax and are evaluated at runtime
	step := graph.NewStepNode("step1", "deploy", 40)
	step.Run = "echo Deploying to $[ parameters.environment ]"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find runtime expression injection")

	finding := findings[0]
	assert.Equal(t, detections.SeverityHigh, finding.Severity, "Runtime expression should be High severity")
}

func TestPipelineInjectionDetection_Detect_RuntimeExpressionInTemplateReference(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Runtime expression in template reference is CRITICAL
	step := graph.NewStepNode("step1", "deploy-with-template", 50)
	step.Uses = "template:$[ parameters.templatePath ]"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find runtime expression in template reference")

	finding := findings[0]
	assert.Equal(t, detections.SeverityCritical, finding.Severity, "Runtime expression in template reference should be Critical")
	assert.Equal(t, detections.VulnDynamicTemplateInjection, finding.Type, "Runtime expression in template reference should be VulnDynamicTemplateInjection")
}

// Trigger exploitation tests

func TestPipelineInjectionDetection_Detect_WildcardTrigger(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{"refs/heads/*"})
	g.AddNode(wf)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find wildcard trigger exploitation")

	found := false
	for _, f := range findings {
		if f.Type == detections.VulnTriggerExploitation {
			found = true
			assert.Equal(t, detections.SeverityHigh, f.Severity, "Wildcard trigger should be High severity")
		}
	}
	assert.True(t, found, "Expected at least one VulnTriggerExploitation finding")
}

func TestPipelineInjectionDetection_Detect_NoTrigger(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "build", 10)
	step.Run = "npm run build"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	// No trigger patterns to flag, no injection patterns — should be empty
	triggerFindings := 0
	for _, f := range findings {
		if f.Type == detections.VulnTriggerExploitation {
			triggerFindings++
		}
	}
	assert.Equal(t, 0, triggerFindings, "Expected no trigger exploitation findings for workflow with no triggers")
}
