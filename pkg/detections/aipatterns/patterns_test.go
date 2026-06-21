package aipatterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

func TestIsAIAction_KnownProviders(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"coderabbit-ai/pr-review@v1", true},
		{"anthropics/claude-code-action@v1", true},
		{"github/copilot-review@v1", true},
		{"openai/codex@v1", true},
		{"npx claude-code review", true},
		{"actions/checkout@v4", false},
		{"npm test", false},
		{"echo hello", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, IsAIAction(tt.input))
		})
	}
}

func TestIsAIAction_CaseInsensitive(t *testing.T) {
	assert.True(t, IsAIAction("CLAUDE-AI/review@v1"))
	assert.True(t, IsAIAction("OpenAI/action@v1"))
	assert.True(t, IsAIAction("CodeRabbit/review@v1"))
}

func TestIsAIAction_MCPPatterns(t *testing.T) {
	assert.True(t, IsAIAction("some-mcp-server"))
	assert.True(t, IsAIAction("model-context-protocol-tool"))
}

func TestIsAIStep(t *testing.T) {
	tests := []struct {
		name string
		uses string
		run  string
		want bool
	}{
		{"AI uses", "coderabbit-ai/review@v1", "", true},
		{"AI run", "", "npx claude-code review", true},
		{"non-AI uses", "actions/checkout@v4", "", false},
		{"non-AI run", "", "npm test", false},
		{"both AI", "copilot@v1", "npx claude-code review", true},
		{"empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			step := graph.NewStepNode("s1", "step", 1)
			step.Uses = tt.uses
			step.Run = tt.run
			assert.Equal(t, tt.want, IsAIStep(step))
		})
	}
}

func TestIsAIAction_OllamaPattern(t *testing.T) {
	assert.True(t, IsAIAction("ollama/code-review@v1"))
	assert.True(t, IsAIAction("some-org/ollama-action@v1"))
	assert.True(t, IsAIAction("run: ollama run llama2"))
}

func TestHasAIEnvVars(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"OPENAI_API_KEY", map[string]string{"OPENAI_API_KEY": "sk-..."}, true},
		{"ANTHROPIC_API_KEY", map[string]string{"ANTHROPIC_API_KEY": "sk-ant-..."}, true},
		{"OLLAMA_HOST", map[string]string{"OLLAMA_HOST": "http://localhost:11434"}, true},
		{"HF_TOKEN", map[string]string{"HF_TOKEN": "hf_..."}, true},
		{"GROQ_API_KEY", map[string]string{"GROQ_API_KEY": "gsk_..."}, true},
		{"case insensitive", map[string]string{"openai_api_key": "sk-..."}, true},
		{"non-AI env", map[string]string{"GITHUB_TOKEN": "ghp_...", "NODE_ENV": "prod"}, false},
		{"empty env", map[string]string{}, false},
		{"nil env", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			step := graph.NewStepNode("s1", "step", 1)
			step.Env = tt.env
			assert.Equal(t, tt.want, HasAIEnvVars(step))
		})
	}
}

func TestIsAIStep_WithEnvVars(t *testing.T) {
	// Step with no AI action/run but AI env var should still be detected
	step := graph.NewStepNode("s1", "step", 1)
	step.Uses = "actions/checkout@v4"
	step.Env = map[string]string{"OPENAI_API_KEY": "sk-..."}
	assert.True(t, IsAIStep(step))

	// Step with no AI signals at all
	step2 := graph.NewStepNode("s2", "step", 2)
	step2.Uses = "actions/checkout@v4"
	step2.Env = map[string]string{"GITHUB_TOKEN": "ghp_..."}
	assert.False(t, IsAIStep(step2))
}

func TestCheckMCPIndicators(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		with map[string]string
		want bool
	}{
		{
			name: "MCP in env key",
			env:  map[string]string{"MCP_ENABLED": "true"},
			want: true,
		},
		{
			name: "MCP in env value",
			env:  map[string]string{"CONFIG": "use-mcp-server"},
			want: true,
		},
		{
			name: "MCP in with key",
			with: map[string]string{"enable-mcp": "true"},
			want: true,
		},
		{
			name: "MCP in with value",
			with: map[string]string{"server": "mcp.example.com"},
			want: true,
		},
		{
			name: "no MCP indicators",
			env:  map[string]string{"TOKEN": "abc"},
			with: map[string]string{"mode": "full"},
			want: false,
		},
		{
			name: "empty step",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			step := graph.NewStepNode("s1", "step", 1)
			step.Env = tt.env
			step.With = tt.with
			assert.Equal(t, tt.want, CheckMCPIndicators(step))
		})
	}
}

func TestGetTriggerString(t *testing.T) {
	tests := []struct {
		name     string
		triggers []string
		want     string
	}{
		{"single trigger", []string{"push"}, "push"},
		{"multiple triggers", []string{"push", "pull_request"}, "push, pull_request"},
		{"no triggers", []string{}, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wf := graph.NewWorkflowNode("wf1", "ci.yml", "ci.yml", "owner/repo", tt.triggers)
			assert.Equal(t, tt.want, GetTriggerString(wf))
		})
	}
}
