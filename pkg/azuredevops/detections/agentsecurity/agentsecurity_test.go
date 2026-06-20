package agentsecurity

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestAgentSecurityDetection_Name(t *testing.T) {
	d := New()
	assert.Equal(t, "agent-security", d.Name())
}

func TestAgentSecurityDetection_Platform(t *testing.T) {
	d := New()
	assert.Equal(t, platforms.PlatformAzureDevOps, d.Platform())
}

func TestAgentSecurityDetection_Severity(t *testing.T) {
	d := New()
	assert.Equal(t, detections.SeverityHigh, d.Severity())
}

func TestAgentSecurityDetection_Detect_SelfHostedPool(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "my-self-hosted-pool")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find self-hosted pool")

	finding := findings[0]
	assert.Equal(t, detections.VulnSelfHostedAgent, finding.Type)
	assert.Equal(t, detections.ClassRunnerSecurity, finding.Class)
	assert.Equal(t, platforms.PlatformAzureDevOps, finding.Platform)
}

func TestAgentSecurityDetection_Detect_UbuntuLatestSafe(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for ubuntu-latest")
}

func TestAgentSecurityDetection_Detect_WindowsLatestSafe(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "windows-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for windows-latest")
}

func TestAgentSecurityDetection_Detect_MacOSSafe(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "macos-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for macos-latest")
}

func TestAgentSecurityDetection_Detect_VMImageSafe(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "vmimage:ubuntu-22.04")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for vmimage")
}

func TestAgentSecurityDetection_Detect_Ubuntu2204Safe(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "ubuntu-22.04")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for ubuntu-22.04")
}

func TestAgentSecurityDetection_Detect_MultipleJobsMixed(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	job1 := graph.NewJobNode("job1", "build", "ubuntu-latest")
	job1.SetParent(wf.ID())
	g.AddNode(job1)
	g.AddEdge(wf.ID(), job1.ID(), graph.EdgeContains)

	job2 := graph.NewJobNode("job2", "deploy", "custom-pool")
	job2.SetParent(wf.ID())
	g.AddNode(job2)
	g.AddEdge(wf.ID(), job2.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Len(t, findings, 1, "Expected exactly 1 finding for self-hosted pool")
}

func TestAgentSecurityDetection_Detect_WithAPIPoolData(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	g.SetMetadata("ado_agent_pools", []azuredevops.AgentPool{
		{ID: 1, Name: "Azure Pipelines", IsHosted: true},
		{ID: 2, Name: "Hosted Ubuntu 1604", IsHosted: true},
		{ID: 3, Name: "shire-self-hosted", IsHosted: false},
	})

	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	jobHosted := graph.NewJobNode("job1", "build", "Hosted Ubuntu 1604")
	jobHosted.SetParent(wf.ID())
	g.AddNode(jobHosted)
	g.AddEdge(wf.ID(), jobHosted.ID(), graph.EdgeContains)

	jobSelfHosted := graph.NewJobNode("job2", "deploy", "shire-self-hosted")
	jobSelfHosted.SetParent(wf.ID())
	g.AddNode(jobSelfHosted)
	g.AddEdge(wf.ID(), jobSelfHosted.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Evidence, "shire-self-hosted")
}

func TestAgentSecurityDetection_Detect_APIDataHostedPoolNotFlagged(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	g.SetMetadata("ado_agent_pools", []azuredevops.AgentPool{
		{ID: 1, Name: "Azure Pipelines", IsHosted: true},
		{ID: 2, Name: "My Custom Hosted", IsHosted: true},
	})

	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "My Custom Hosted")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Pool marked IsHosted by API should not be flagged")
}

func TestAgentSecurityDetection_Detect_APIOverridesVMImageHeuristic(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	g.SetMetadata("ado_agent_pools", []azuredevops.AgentPool{
		{ID: 1, Name: "Azure Pipelines", IsHosted: true},
		{ID: 2, Name: "ubuntu-builders", IsHosted: false},
	})

	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "ubuntu-builders")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.Len(t, findings, 1, "Self-hosted pool with ubuntu prefix must be detected when API says IsHosted=false")
	assert.Contains(t, findings[0].Evidence, "ubuntu-builders")
}

func TestAgentSecurityDetection_Detect_AzurePipelinesPoolOffline(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "Azure Pipelines")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Azure Pipelines pool should not be flagged in offline mode")
}

func TestIsSelfHostedPool(t *testing.T) {
	apiPools := map[string]bool{
		"azure pipelines":    true,
		"hosted ubuntu 1604": true,
		"ubuntu-builders":    false,
		"shire-self-hosted":  false,
	}

	tests := []struct {
		name    string
		runsOn  string
		poolMap map[string]bool
		want    bool
	}{
		{"empty runsOn", "", nil, false},
		{"vmImage ubuntu-latest", "ubuntu-latest", nil, false},
		{"vmImage windows-2022", "windows-2022", nil, false},
		{"vmImage macos-15", "macos-15", nil, false},
		{"vmImage prefix", "vmimage:ubuntu-22.04", nil, false},
		{"offline: Azure Pipelines pool", "Azure Pipelines", nil, false},
		{"offline: unknown pool is self-hosted", "my-pool", nil, true},
		{"API: hosted pool not flagged", "Hosted Ubuntu 1604", apiPools, false},
		{"API: unknown pool flagged as self-hosted", "my-pool", apiPools, true},
		{"API: vmImage still safe", "ubuntu-latest", apiPools, false},
		{"API: self-hosted pool with ubuntu prefix detected", "ubuntu-builders", apiPools, true},
		{"API: self-hosted pool by name", "shire-self-hosted", apiPools, true},
		{"API: hosted pool with Azure Pipelines name", "Azure Pipelines", apiPools, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSelfHostedPool(tt.runsOn, tt.poolMap)
			assert.Equal(t, tt.want, got)
		})
	}
}
