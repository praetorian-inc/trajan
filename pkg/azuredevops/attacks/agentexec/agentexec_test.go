package agentexec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestNew(t *testing.T) {
	plugin := New()
	assert.NotNil(t, plugin)
	assert.Equal(t, "ado-agent-exec", plugin.Name())
	assert.Equal(t, "azuredevops", plugin.Platform())
	assert.Equal(t, attacks.CategoryRunners, plugin.Category())
	assert.Contains(t, plugin.Description(), "self-hosted")
}

func TestCanAttack(t *testing.T) {
	plugin := New()

	tests := []struct {
		name     string
		findings []detections.Finding
		want     bool
	}{
		{
			name: "self-hosted agent - can attack",
			findings: []detections.Finding{
				{Type: detections.VulnSelfHostedAgent},
			},
			want: true,
		},
		{
			name:     "no findings - cannot attack",
			findings: []detections.Finding{},
			want:     false,
		},
		{
			name: "excessive permissions - cannot attack",
			findings: []detections.Finding{
				{Type: detections.VulnExcessivePermissions},
			},
			want: false,
		},
		{
			name: "pwn request - cannot attack",
			findings: []detections.Finding{
				{Type: detections.VulnPwnRequest},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, plugin.CanAttack(tt.findings))
		})
	}
}

func TestGeneratePipelineYAML_DefaultCommand(t *testing.T) {
	plugin := New()
	yaml := plugin.generatePipelineYAML("my-pool", "")

	assert.Contains(t, yaml, "trigger: none")
	assert.Contains(t, yaml, "name: 'my-pool'")
	assert.NotContains(t, yaml, "vmImage")
	assert.Contains(t, yaml, "Agent Exec - Trajan")
	assert.Contains(t, yaml, "whoami")
	assert.Contains(t, yaml, "hostname")
	assert.Contains(t, yaml, "base64 | tr -d '\\n' | base64")
}

func TestGeneratePipelineYAML_CustomCommand(t *testing.T) {
	plugin := New()
	yaml := plugin.generatePipelineYAML("test-pool", "cat /etc/passwd")

	assert.Contains(t, yaml, "name: 'test-pool'")
	assert.Contains(t, yaml, "cat /etc/passwd")
	assert.NotContains(t, yaml, "whoami")
}

func TestGeneratePipelineYAML_PoolName(t *testing.T) {
	plugin := New()

	tests := []struct {
		name     string
		poolName string
	}{
		{"simple name", "self-hosted"},
		{"name with spaces", "My Self-Hosted Pool"},
		{"name with special chars", "pool-123_test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := plugin.generatePipelineYAML(tt.poolName, "echo hello")
			assert.Contains(t, yaml, fmt.Sprintf("name: '%s'", tt.poolName))
			assert.NotContains(t, yaml, "vmImage")
		})
	}
}

// --- resolvePool tests via httptest ---

// newTestServer creates an httptest server that serves agent pools and agent queues.
// poolsJSON is returned for /_apis/distributedtask/pools requests.
// queuesJSON is returned for /{project}/_apis/distributedtask/queues requests.
func newTestServer(t *testing.T, poolsJSON, queuesJSON interface{}) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case strings.HasPrefix(path, "/_apis/distributedtask/pools"):
			if poolsJSON == nil {
				http.Error(w, `{"message":"not configured"}`, http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(poolsJSON)
		case strings.Contains(path, "/_apis/distributedtask/queues"):
			if queuesJSON == nil {
				http.Error(w, `{"message":"not configured"}`, http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(queuesJSON)
		default:
			http.Error(w, fmt.Sprintf("unexpected path: %s", path), http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestResolvePool_ExplicitPool_Success(t *testing.T) {
	pools := azuredevops.AgentPoolList{
		Value: []azuredevops.AgentPool{
			{ID: 1, Name: "my-self-hosted", IsHosted: false, PoolType: "automation"},
			{ID: 2, Name: "Azure Pipelines", IsHosted: true, PoolType: "automation"},
		},
		Count: 2,
	}
	queues := azuredevops.AgentQueueList{
		Value: []azuredevops.AgentQueue{
			{ID: 10, Name: "my-self-hosted", Pool: struct {
				ID       int    `json:"id"`
				Name     string `json:"name"`
				IsHosted bool   `json:"isHosted"`
			}{ID: 1, Name: "my-self-hosted", IsHosted: false}},
		},
		Count: 1,
	}

	server := newTestServer(t, pools, queues)
	client := azuredevops.NewClient(server.URL, "test-pat")
	plugin := New()

	result, queueID, err := plugin.resolvePool(context.Background(), client, "TestProject", map[string]string{"pool": "my-self-hosted"})
	require.NoError(t, err)
	assert.Equal(t, "my-self-hosted", result)
	assert.Equal(t, 10, queueID)
}

func TestResolvePool_ExplicitPool_IsHosted(t *testing.T) {
	pools := azuredevops.AgentPoolList{
		Value: []azuredevops.AgentPool{
			{ID: 1, Name: "Azure Pipelines", IsHosted: true, PoolType: "automation"},
		},
		Count: 1,
	}
	// Queues shouldn't be reached, but provide them to avoid server errors
	queues := azuredevops.AgentQueueList{Value: []azuredevops.AgentQueue{}, Count: 0}

	server := newTestServer(t, pools, queues)
	client := azuredevops.NewClient(server.URL, "test-pat")
	plugin := New()

	_, _, err := plugin.resolvePool(context.Background(), client, "TestProject", map[string]string{"pool": "Azure Pipelines"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Microsoft-hosted")
}

func TestResolvePool_ExplicitPool_NotFound(t *testing.T) {
	pools := azuredevops.AgentPoolList{
		Value: []azuredevops.AgentPool{
			{ID: 1, Name: "existing-pool", IsHosted: false},
		},
		Count: 1,
	}
	queues := azuredevops.AgentQueueList{Value: []azuredevops.AgentQueue{}, Count: 0}

	server := newTestServer(t, pools, queues)
	client := azuredevops.NewClient(server.URL, "test-pat")
	plugin := New()

	_, _, err := plugin.resolvePool(context.Background(), client, "TestProject", map[string]string{"pool": "nonexistent-pool"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	assert.Contains(t, err.Error(), "nonexistent-pool")
}

func TestResolvePool_ExplicitPool_NotAccessible(t *testing.T) {
	pools := azuredevops.AgentPoolList{
		Value: []azuredevops.AgentPool{
			{ID: 1, Name: "private-pool", IsHosted: false, PoolType: "automation"},
		},
		Count: 1,
	}
	// Queues list does NOT include "private-pool" — it's not accessible from this project
	queues := azuredevops.AgentQueueList{
		Value: []azuredevops.AgentQueue{
			{ID: 10, Name: "Azure Pipelines", Pool: struct {
				ID       int    `json:"id"`
				Name     string `json:"name"`
				IsHosted bool   `json:"isHosted"`
			}{ID: 2, Name: "Azure Pipelines", IsHosted: true}},
		},
		Count: 1,
	}

	server := newTestServer(t, pools, queues)
	client := azuredevops.NewClient(server.URL, "test-pat")
	plugin := New()

	_, _, err := plugin.resolvePool(context.Background(), client, "TestProject", map[string]string{"pool": "private-pool"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not accessible")
	assert.Contains(t, err.Error(), "private-pool")
}

func TestResolvePool_AutoDiscover_SinglePool(t *testing.T) {
	// No pools endpoint needed — auto-discover only uses queues
	queues := azuredevops.AgentQueueList{
		Value: []azuredevops.AgentQueue{
			{ID: 10, Name: "Azure Pipelines", Pool: struct {
				ID       int    `json:"id"`
				Name     string `json:"name"`
				IsHosted bool   `json:"isHosted"`
			}{ID: 1, Name: "Azure Pipelines", IsHosted: true}},
			{ID: 11, Name: "my-agents", Pool: struct {
				ID       int    `json:"id"`
				Name     string `json:"name"`
				IsHosted bool   `json:"isHosted"`
			}{ID: 2, Name: "my-agents", IsHosted: false}},
		},
		Count: 2,
	}

	server := newTestServer(t, nil, queues)
	client := azuredevops.NewClient(server.URL, "test-pat")
	plugin := New()

	// Empty extraOpts means auto-discover
	result, queueID, err := plugin.resolvePool(context.Background(), client, "TestProject", map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, "my-agents", result)
	assert.Equal(t, 11, queueID)
}

func TestResolvePool_AutoDiscover_NoPools(t *testing.T) {
	// All queues are hosted — no self-hosted pools found
	queues := azuredevops.AgentQueueList{
		Value: []azuredevops.AgentQueue{
			{ID: 10, Name: "Azure Pipelines", Pool: struct {
				ID       int    `json:"id"`
				Name     string `json:"name"`
				IsHosted bool   `json:"isHosted"`
			}{ID: 1, Name: "Azure Pipelines", IsHosted: true}},
			{ID: 11, Name: "Hosted Ubuntu", Pool: struct {
				ID       int    `json:"id"`
				Name     string `json:"name"`
				IsHosted bool   `json:"isHosted"`
			}{ID: 2, Name: "Hosted Ubuntu", IsHosted: true}},
		},
		Count: 2,
	}

	server := newTestServer(t, nil, queues)
	client := azuredevops.NewClient(server.URL, "test-pat")
	plugin := New()

	_, _, err := plugin.resolvePool(context.Background(), client, "TestProject", map[string]string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no self-hosted pools")
}

func TestResolvePool_AutoDiscover_MultiplePools(t *testing.T) {
	queues := azuredevops.AgentQueueList{
		Value: []azuredevops.AgentQueue{
			{ID: 10, Name: "pool-a-queue", Pool: struct {
				ID       int    `json:"id"`
				Name     string `json:"name"`
				IsHosted bool   `json:"isHosted"`
			}{ID: 1, Name: "pool-a", IsHosted: false}},
			{ID: 11, Name: "pool-b-queue", Pool: struct {
				ID       int    `json:"id"`
				Name     string `json:"name"`
				IsHosted bool   `json:"isHosted"`
			}{ID: 2, Name: "pool-b", IsHosted: false}},
		},
		Count: 2,
	}

	server := newTestServer(t, nil, queues)
	client := azuredevops.NewClient(server.URL, "test-pat")
	plugin := New()

	_, _, err := plugin.resolvePool(context.Background(), client, "TestProject", map[string]string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "multiple self-hosted pools")
	assert.Contains(t, err.Error(), "--pool")
	assert.Contains(t, err.Error(), "pool-a")
	assert.Contains(t, err.Error(), "pool-b")
}

func TestResolvePool_AutoDiscover_DeduplicatesPools(t *testing.T) {
	// Multiple queues all pointing to the same underlying pool — should deduplicate
	queues := azuredevops.AgentQueueList{
		Value: []azuredevops.AgentQueue{
			{ID: 10, Name: "queue-1", Pool: struct {
				ID       int    `json:"id"`
				Name     string `json:"name"`
				IsHosted bool   `json:"isHosted"`
			}{ID: 1, Name: "shared-pool", IsHosted: false}},
			{ID: 11, Name: "queue-2", Pool: struct {
				ID       int    `json:"id"`
				Name     string `json:"name"`
				IsHosted bool   `json:"isHosted"`
			}{ID: 1, Name: "shared-pool", IsHosted: false}},
			{ID: 12, Name: "queue-3", Pool: struct {
				ID       int    `json:"id"`
				Name     string `json:"name"`
				IsHosted bool   `json:"isHosted"`
			}{ID: 1, Name: "shared-pool", IsHosted: false}},
		},
		Count: 3,
	}

	server := newTestServer(t, nil, queues)
	client := azuredevops.NewClient(server.URL, "test-pat")
	plugin := New()

	result, queueID, err := plugin.resolvePool(context.Background(), client, "TestProject", map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, "shared-pool", result, "should deduplicate multiple queues pointing to same pool")
	assert.Equal(t, 10, queueID)
}

// --- YAML edge-case tests ---

func TestGeneratePipelineYAML_CommandWithSpecialChars(t *testing.T) {
	plugin := New()

	tests := []struct {
		name    string
		command string
		expect  string
	}{
		{
			name:    "command with quotes",
			command: `echo "hello world"`,
			expect:  `echo "hello world"`,
		},
		{
			name:    "command with single quotes",
			command: `echo 'secret value'`,
			expect:  `echo 'secret value'`,
		},
		{
			name:    "command with pipe",
			command: "cat /etc/passwd | grep root",
			expect:  "cat /etc/passwd | grep root",
		},
		{
			name:    "command with redirect",
			command: "ls -la > /tmp/output.txt 2>&1",
			expect:  "ls -la > /tmp/output.txt 2>&1",
		},
		{
			name:    "command with backticks",
			command: "echo `whoami`",
			expect:  "echo `whoami`",
		},
		{
			name:    "command with semicolons and chaining",
			command: "whoami; id; hostname && uname -a || echo failed",
			expect:  "whoami; id; hostname && uname -a || echo failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := plugin.generatePipelineYAML("test-pool", tt.command)
			assert.Contains(t, yaml, tt.expect)
			assert.Contains(t, yaml, "trigger: none")
			assert.Contains(t, yaml, "name: 'test-pool'")
			assert.Contains(t, yaml, "base64 | tr -d '\\n' | base64")
		})
	}
}

func TestGeneratePipelineYAML_EmptyPoolName(t *testing.T) {
	plugin := New()
	yaml := plugin.generatePipelineYAML("", "echo hello")

	// Even with empty pool name, YAML should be generated (pool name validation
	// happens in resolvePool, not in generatePipelineYAML)
	assert.Contains(t, yaml, "name: ''")
	assert.Contains(t, yaml, "echo hello")
	assert.Contains(t, yaml, "trigger: none")
	assert.Contains(t, yaml, "base64 | tr -d '\\n' | base64")
}
