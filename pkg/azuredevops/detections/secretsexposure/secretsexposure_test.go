package secretsexposure

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestSecretsExposureDetection_Detect_EchoWithVariableExpansion(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "echo-secret", 10)
	step.Run = "echo $(SECRET_VAR)"
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find echo with variable expansion")

	finding := findings[0]
	assert.Equal(t, detections.VulnUnredactedSecrets, finding.Type)
	assert.Equal(t, detections.ClassSecretsExposure, finding.Class)
	assert.Equal(t, platforms.PlatformAzureDevOps, finding.Platform)
}

func TestSecretsExposureDetection_Detect_CurlWithSecret(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "curl-with-secret", 20)
	step.Run = "curl https://example.com?token=$(API_TOKEN)"
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find curl with secret")
}

func TestSecretsExposureDetection_Detect_PrintenvCommand(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "printenv", 30)
	step.Run = "printenv"
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find printenv command")
}

func TestSecretsExposureDetection_Detect_EnvPipeCommand(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "env-pipe", 40)
	step.Run = "env | grep SECRET"
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find env pipe command")
}

func TestSecretsExposureDetection_Detect_SafeEchoWithoutExpansion(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "safe-echo", 50)
	step.Run = "echo 'Building application'"
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for safe echo")
}

func TestSecretsExposureDetection_Detect_NoRunCommand(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "task-step", 60)
	step.Uses = "task:SomeTask@1"
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for step without Run command")
}

func TestSecretsExposureDetection_Detect_SafeSystemVariable(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "echo-buildid", 10)
	step.Run = "echo $(Build.BuildId)"
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for safe system variable Build.BuildId")
}

func TestSecretsExposureDetection_Detect_MixedSafeAndUnsafeVariables(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "echo-mixed", 10)
	step.Run = "echo $(Build.BuildId) $(MY_SECRET)"
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.NotEmpty(t, findings, "Expected finding when mix of safe and unsafe variables")
}

func TestSecretsExposureDetection_Detect_SafeSystemVarInCurl(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "curl-safe", 10)
	step.Run = "curl https://example.com/build/$(Build.BuildId)"
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for curl with safe system variable")
}

func TestExtractVariableRefs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "single ref",
			input:    "echo $(Build.BuildId)",
			expected: []string{"Build.BuildId"},
		},
		{
			name:     "multiple refs",
			input:    "echo $(Build.BuildId) $(System.TeamProject)",
			expected: []string{"Build.BuildId", "System.TeamProject"},
		},
		{
			name:     "no refs",
			input:    "echo hello world",
			expected: []string{},
		},
		{
			name:     "bash style not matched",
			input:    "echo ${SECRET}",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractVariableRefs(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestAllRefsSafe(t *testing.T) {
	tests := []struct {
		name     string
		refs     []string
		expected bool
	}{
		{
			name:     "all safe",
			refs:     []string{"Build.BuildId", "System.TeamProject"},
			expected: true,
		},
		{
			name:     "one unsafe",
			refs:     []string{"Build.BuildId", "MY_SECRET"},
			expected: false,
		},
		{
			name:     "empty refs",
			refs:     []string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := allRefsSafe(tt.refs)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestSecretsExposureDetection_Detect_TaskInputWithSecretRef(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "task-with-secret", 10)
	step.Uses = "SomeTask@1"
	step.With = map[string]string{
		"apiToken": "$(MY_SECRET_TOKEN)",
	}
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.NotEmpty(t, findings, "Expected finding for task input referencing secret-like variable")
}

func TestSecretsExposureDetection_Detect_TaskInputWithSafeRef(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "task-safe-input", 10)
	step.Uses = "SomeTask@1"
	step.With = map[string]string{
		"buildId": "$(Build.BuildId)",
	}
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for task input referencing safe system variable")
}

func TestSecretsExposureDetection_Detect_TaskScriptInputWithEcho(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "task-script-echo", 10)
	step.Uses = "Bash@3"
	step.With = map[string]string{
		"script": "echo $(SECRET_VAR)",
	}
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.NotEmpty(t, findings, "Expected finding for task script input echoing secret")
}

func TestSecretsExposureDetection_Detect_TaskScriptInputSafe(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "task-script-safe", 10)
	step.Uses = "Bash@3"
	step.With = map[string]string{
		"script": "echo $(Build.BuildId)",
	}
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for task script input echoing safe variable")
}

func TestSecretsExposureDetection_Detect_TaskInlineInputWithPrintenv(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "task-inline-printenv", 10)
	step.Uses = "PowerShell@2"
	step.With = map[string]string{
		"inline": "printenv",
	}
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.NotEmpty(t, findings, "Expected finding for task inline input with printenv")
}

func TestSecretsExposureDetection_Detect_TaskInputNonSecretVariable(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "task-normal-var", 10)
	step.Uses = "SomeTask@1"
	step.With = map[string]string{
		"version": "$(myAppVersion)",
	}
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for task input referencing non-secret variable")
}

// A safe echo must not mask printenv detection in the same script block.
func TestSecretsExposureDetection_Detect_SafeEchoPlusPrintenv(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "safe-echo-and-printenv", 10)
	step.Run = "echo \"Building in Khazad-Dum...\"\necho \"Trigger: $(Build.Reason)\"\nprintenv"
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.Len(t, findings, 1, "Expected 1 finding for printenv even though echo refs are safe")
	assert.Contains(t, findings[0].Evidence, "printenv dumps all environment variables")
}

// Same invariant on the task-script-input path.
func TestSecretsExposureDetection_Detect_TaskScriptSafeEchoPlusPrintenv(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "task-safe-echo-printenv", 10)
	step.Uses = "Bash@3"
	step.With = map[string]string{
		"targetType": "inline",
		"script":     "echo \"Trigger: $(Build.Reason)\"\nprintenv",
	}
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.Len(t, findings, 1, "Expected 1 finding for printenv in task script even though echo refs are safe")
	assert.Contains(t, findings[0].Evidence, "Task input script dumps environment variables")
}

func TestSecretsExposureDetection_Detect_ForkSecretExposureOnPRTrigger(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", []string{"pr"})
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "build-with-secret-env", 10)
	step.Run = "build.sh"
	step.Env = map[string]string{
		"MY_SECRET_TOKEN": "$(MY_SECRET)",
	}
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)

	found := false
	for _, f := range findings {
		if f.Type == detections.VulnPullRequestSecretsExposure {
			found = true
		}
	}
	assert.True(t, found, "Expected VulnPullRequestSecretsExposure for PR trigger with secret env key")
}

func TestSecretsExposureDetection_Detect_ForkNoExposureWithoutPRTrigger(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	// No PR trigger
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", []string{"ci"})
	g.AddNode(wf)

	step := graph.NewStepNode("step1", "build-with-secret-env", 10)
	step.Run = "build.sh"
	step.Env = map[string]string{
		"MY_SECRET_TOKEN": "$(MY_SECRET)",
	}
	step.SetParent(wf.ID())
	g.AddNode(step)
	g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)

	for _, f := range findings {
		assert.NotEqual(t, detections.VulnPullRequestSecretsExposure, f.Type,
			"Expected no VulnPullRequestSecretsExposure without PR trigger")
	}
}
