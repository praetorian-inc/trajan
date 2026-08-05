package serviceconnections

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestServiceConnectionsDetection_Detect_DynamicConnectionFromParameter(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step with dynamic service connection from parameter
	step := graph.NewStepNode("step1", "azure-deploy", 10)
	step.Uses = "task:AzureCLI@2"
	step.With = map[string]string{
		"azureSubscription": "${{ parameters.subscription }}",
		"scriptType":        "bash",
	}
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find dynamic service connection")

	finding := findings[0]
	assert.Equal(t, detections.VulnServiceConnectionHijacking, finding.Type)
	assert.Equal(t, platforms.PlatformAzureDevOps, finding.Platform, "Finding platform should be 'azuredevops'")
	assert.Equal(t, detections.SeverityCritical, finding.Severity)
}

func TestServiceConnectionsDetection_Detect_StaticConnection(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step with static (safe) service connection
	step := graph.NewStepNode("step1", "azure-deploy-safe", 20)
	step.Uses = "task:AzureCLI@2"
	step.With = map[string]string{
		"azureSubscription": "my-production-connection",
		"scriptType":        "bash",
	}
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	// Static connections should not produce VulnServiceConnectionHijacking
	for _, f := range findings {
		assert.NotEqual(t, detections.VulnServiceConnectionHijacking, f.Type,
			"Expected no hijacking finding for static connection")
	}
}

func TestServiceConnectionsDetection_Detect_ConnectionInEnvVariable(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step with service connection in environment variable (potential secret leak)
	step := graph.NewStepNode("step1", "deploy-with-env", 25)
	step.Run = "echo 'Deploying...'"
	step.Env = map[string]string{
		"AZURE_CONNECTION": "${{ parameters.azureSubscription }}",
		"DEPLOY_ENV":       "production",
	}
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find service connection in env variable")

	finding := findings[0]
	assert.Equal(t, detections.SeverityHigh, finding.Severity, "Env variable exposure should be High severity")
}

func TestServiceConnectionsDetection_Detect_MultipleIssues(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Step 1: Dynamic connection from parameter
	step1 := graph.NewStepNode("step1", "step1", 10)
	step1.Uses = "task:AzureCLI@2"
	step1.With = map[string]string{
		"azureSubscription": "${{ parameters.conn }}",
	}
	step1.SetParent(job.ID())
	g.AddNode(step1)
	g.AddEdge(job.ID(), step1.ID(), graph.EdgeContains)

	// Step 2: Connection in environment variable
	step2 := graph.NewStepNode("step2", "step2", 20)
	step2.Run = "deploy.sh"
	step2.Env = map[string]string{
		"SERVICE_CONN": "${{ parameters.subscription }}",
	}
	step2.SetParent(job.ID())
	g.AddNode(step2)
	g.AddEdge(job.ID(), step2.ID(), graph.EdgeContains)

	// Step 3: Safe static connection (should not be flagged)
	step3 := graph.NewStepNode("step3", "step3", 30)
	step3.Uses = "task:AzureCLI@2"
	step3.With = map[string]string{
		"azureSubscription": "prod-connection",
	}
	step3.SetParent(job.ID())
	g.AddNode(step3)
	g.AddEdge(job.ID(), step3.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Len(t, findings, 2, "Expected 2 findings (dynamic connection + env variable)")
}

func TestServiceConnectionsDetection_Detect_NoServiceConnection(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step with no service connection
	step := graph.NewStepNode("step1", "build", 5)
	step.Run = "npm run build"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for step without service connection")
}

func TestServiceConnectionsDetection_Detect_MultipleConnectionParameters(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step with multiple connection-related parameters (test all known patterns)
	step := graph.NewStepNode("step1", "complex-deploy", 15)
	step.Uses = "task:CustomDeploy@1"
	step.With = map[string]string{
		"connectedServiceName":            "${{ parameters.svc1 }}",
		"kubernetesServiceConnection":     "${{ variables.k8s }}",
		"dockerRegistryServiceConnection": "static-registry-conn", // Safe
		"azureServiceConnection":          "${{ parameters.azure }}",
	}
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(findings), 3, "Expected at least 3 findings for multiple dynamic connections")
}

// TestServiceConnectionsDetection_Detect_DynamicConnectionFromStepOutput tests detection of
// dynamic connections from step outputs, which can be attacker-controlled
func TestServiceConnectionsDetection_Detect_DynamicConnectionFromStepOutput(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Step output can be attacker-controlled if the step runs attacker code
	step := graph.NewStepNode("step1", "deploy-with-step-output", 10)
	step.Uses = "task:AzureCLI@2"
	step.With = map[string]string{
		"azureSubscription": "${{ steps.get_conn.outputs.connection }}",
		"scriptType":        "bash",
	}
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find dynamic service connection from step output")

	finding := findings[0]
	assert.Equal(t, detections.SeverityCritical, finding.Severity, "Dynamic connection should be Critical")
}

func TestServiceConnectionsDetection_Detect_DynamicConnectionFromJobOutput(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Job output can be attacker-controlled
	step := graph.NewStepNode("step1", "deploy-with-job-output", 15)
	step.Uses = "task:AzureCLI@2"
	step.With = map[string]string{
		"azureSubscription": "${{ jobs.build.outputs.subscription }}",
		"scriptType":        "bash",
	}
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.NotEmpty(t, findings, "Expected to find dynamic service connection from job output")
}

func TestServiceConnectionsDetection_Detect_DynamicConnectionFromEnv(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Environment variable references can be attacker-controlled
	step := graph.NewStepNode("step1", "deploy-with-env", 20)
	step.Uses = "task:AzureCLI@2"
	step.With = map[string]string{
		"azureSubscription": "${{ env.AZURE_SUBSCRIPTION }}",
		"scriptType":        "bash",
	}
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.NotEmpty(t, findings, "Expected to find dynamic service connection from env reference")
}

// TestServiceConnectionsDetection_Detect_GenericEnvVariablesNotFlagged tests that generic
// environment variables that aren't service connections should NOT be flagged
func TestServiceConnectionsDetection_Detect_GenericEnvVariablesNotFlagged(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Generic environment variables that aren't service connections should NOT be flagged
	step := graph.NewStepNode("step1", "build-with-env", 25)
	step.Run = "echo 'Building...'"
	step.Env = map[string]string{
		"SERVICE_NAME":    "${{ parameters.serviceName }}",
		"AWS_REGION":      "${{ parameters.region }}",
		"AZURE_LOCATION":  "${{ parameters.location }}",
		"K8S_NAMESPACE":   "${{ parameters.namespace }}",
		"DOCKER_IMAGE":    "${{ parameters.image }}",
		"GCP_PROJECT":     "${{ parameters.project }}",
		"CREDENTIAL_TYPE": "${{ parameters.credType }}",
	}
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for generic env variables that aren't service connections")
}

func TestServiceConnectionsDetection_Detect_ActualConnectionEnvFlagged(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Actual service connection-related env vars SHOULD be flagged
	step := graph.NewStepNode("step1", "deploy-with-connection-env", 30)
	step.Run = "echo 'Deploying...'"
	step.Env = map[string]string{
		"SERVICE_CONNECTION":     "${{ parameters.connection }}",
		"AZURE_SUBSCRIPTION_ID":  "${{ parameters.subscriptionId }}",
		"K8S_SERVICE_CONNECTION": "${{ parameters.k8sConn }}",
		"DOCKER_REGISTRY_CONN":   "${{ parameters.registry }}",
	}
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.NotEmpty(t, findings, "Expected to find service connections in env variables")
}

// Overexposed (overpermissioned) service connection tests

func TestServiceConnectionsDetection_Detect_ConnectionUsedByMultiplePipelines(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()

	// Create 4 workflows all using the same connection
	for i := 1; i <= 4; i++ {
		wf := graph.NewWorkflowNode("wf"+string(rune('0'+i)), "pipeline"+string(rune('0'+i))+".yml", "pipeline"+string(rune('0'+i))+".yml", "owner/repo", nil)
		g.AddNode(wf)

		step := graph.NewStepNode("step"+string(rune('0'+i)), "deploy", 10)
		step.With = map[string]string{
			"azureSubscription": "shared-connection",
		}
		step.SetParent(wf.ID())
		g.AddNode(step)
		g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)
	}

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find overexposed connection")

	found := false
	for _, f := range findings {
		if f.Type == detections.VulnOverexposedServiceConnections {
			found = true
			assert.Equal(t, detections.ClassPrivilegeEscalation, f.Class)
			assert.Equal(t, platforms.PlatformAzureDevOps, f.Platform)
			// Finding fires when count reaches 3 (threshold is >= 3); evidence reflects
			// the count at the moment the threshold was first crossed.
			assert.Contains(t, f.Evidence, "shared-connection")
		}
	}
	assert.True(t, found, "Expected VulnOverexposedServiceConnections finding")
}

func TestServiceConnectionsDetection_Detect_ConnectionUsedBy2Pipelines_NoFinding(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()

	// Create 2 workflows using the same connection (below the threshold of 3, should NOT trigger)
	for i := 1; i <= 2; i++ {
		wf := graph.NewWorkflowNode("wf"+string(rune('0'+i)), "pipeline"+string(rune('0'+i))+".yml", "pipeline"+string(rune('0'+i))+".yml", "owner/repo", nil)
		g.AddNode(wf)

		step := graph.NewStepNode("step"+string(rune('0'+i)), "deploy", 10)
		step.With = map[string]string{
			"azureSubscription": "shared-connection",
		}
		step.SetParent(wf.ID())
		g.AddNode(step)
		g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)
	}

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)

	for _, f := range findings {
		assert.NotEqual(t, detections.VulnOverexposedServiceConnections, f.Type,
			"Expected no VulnOverexposedServiceConnections for connection used by only 2 workflows")
	}
}

func TestServiceConnectionsDetection_Detect_MultipleConnections(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()

	// Connection A used by 4 workflows (should be flagged)
	for i := 1; i <= 4; i++ {
		wf := graph.NewWorkflowNode("wfA"+string(rune('0'+i)), "pipelineA"+string(rune('0'+i))+".yml", "pipelineA"+string(rune('0'+i))+".yml", "owner/repo", nil)
		g.AddNode(wf)

		step := graph.NewStepNode("stepA"+string(rune('0'+i)), "deploy", 10)
		step.With = map[string]string{
			"azureSubscription": "connection-a",
		}
		step.SetParent(wf.ID())
		g.AddNode(step)
		g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)
	}

	// Connection B used by 2 workflows (should NOT be flagged)
	for i := 1; i <= 2; i++ {
		wf := graph.NewWorkflowNode("wfB"+string(rune('0'+i)), "pipelineB"+string(rune('0'+i))+".yml", "pipelineB"+string(rune('0'+i))+".yml", "owner/repo", nil)
		g.AddNode(wf)

		step := graph.NewStepNode("stepB"+string(rune('0'+i)), "deploy", 20)
		step.With = map[string]string{
			"azureSubscription": "connection-b",
		}
		step.SetParent(wf.ID())
		g.AddNode(step)
		g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)
	}

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)

	overexposedFindings := 0
	for _, f := range findings {
		if f.Type == detections.VulnOverexposedServiceConnections {
			overexposedFindings++
			assert.Contains(t, f.Evidence, "connection-a")
		}
	}
	assert.Equal(t, 1, overexposedFindings, "Expected exactly 1 overexposed finding for connection-a only")
}

func TestServiceConnectionsDetection_Detect_NoServiceConnections(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()

	// Create workflows without service connections
	for i := 1; i <= 5; i++ {
		wf := graph.NewWorkflowNode("wf"+string(rune('0'+i)), "pipeline"+string(rune('0'+i))+".yml", "pipeline"+string(rune('0'+i))+".yml", "owner/repo", nil)
		g.AddNode(wf)

		step := graph.NewStepNode("step"+string(rune('0'+i)), "build", 10)
		step.Run = "npm run build"
		step.SetParent(wf.ID())
		g.AddNode(step)
		g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)
	}

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings without service connections")
}

// TestServiceConnectionsDetection_FindingLine_PointsToInputField verifies that the finding Line
// points to the line of the vulnerable azureSubscription input field, not the step start line.
func TestServiceConnectionsDetection_FindingLine_PointsToInputField(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Step starts at line 26, but the azureSubscription input is at line 29
	step := graph.NewStepNode("step1", "azure-deploy", 26)
	step.Uses = "AzureCLI@2"
	step.With = map[string]string{
		"azureSubscription": "${{ parameters.connectionName }}",
		"scriptType":        "bash",
	}
	// WithLines maps the input key to the exact line of that field
	step.WithLines = map[string]int{
		"azureSubscription": 29,
		"scriptType":        30,
	}
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find dynamic service connection")

	var hijackFinding *detections.Finding
	for i := range findings {
		if findings[i].Type == detections.VulnServiceConnectionHijacking {
			hijackFinding = &findings[i]
			break
		}
	}
	require.NotNil(t, hijackFinding, "Expected VulnServiceConnectionHijacking finding")
	assert.Equal(t, 29, hijackFinding.Line,
		"Finding Line should point to the azureSubscription field (29), not the step start (26)")
}

// TestServiceConnectionsDetection_FindingLine_PointsToEnvKey verifies that the finding Line
// for a service connection in env points to the specific env key line, not the step start.
func TestServiceConnectionsDetection_FindingLine_PointsToEnvKey(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Step starts at line 15, the AZURE_CONNECTION env key is at line 18
	step := graph.NewStepNode("step1", "deploy-with-env", 15)
	step.Run = "echo 'Deploying...'"
	step.Env = map[string]string{
		"AZURE_CONNECTION": "${{ parameters.azureSubscription }}",
	}
	step.EnvLines = map[string]int{
		"AZURE_CONNECTION": 18,
	}
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find service connection in env variable")

	var hijackFinding *detections.Finding
	for i := range findings {
		if findings[i].Type == detections.VulnServiceConnectionHijacking {
			hijackFinding = &findings[i]
			break
		}
	}
	require.NotNil(t, hijackFinding, "Expected VulnServiceConnectionHijacking finding")
	assert.Equal(t, 18, hijackFinding.Line,
		"Finding Line should point to the AZURE_CONNECTION env key (18), not the step start (15)")
}

// TestServiceConnectionsDetection_FindingLine_FallsBackToStepLine verifies that when WithLines
// is nil or missing a key, the finding falls back to the step start line.
func TestServiceConnectionsDetection_FindingLine_FallsBackToStepLine(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "azure-pipelines.yml", "azure-pipelines.yml", "owner/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Step has no WithLines — should fall back to step.Line
	step := graph.NewStepNode("step1", "azure-deploy", 42)
	step.Uses = "AzureCLI@2"
	step.With = map[string]string{
		"azureSubscription": "${{ parameters.connectionName }}",
	}
	// WithLines is nil (not set)
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find dynamic service connection")

	var hijackFinding *detections.Finding
	for i := range findings {
		if findings[i].Type == detections.VulnServiceConnectionHijacking {
			hijackFinding = &findings[i]
			break
		}
	}
	require.NotNil(t, hijackFinding, "Expected VulnServiceConnectionHijacking finding")
	assert.Equal(t, 42, hijackFinding.Line,
		"Finding Line should fall back to step start (42) when WithLines is nil")
}

// TestServiceConnectionsDetection_Detect_OverexposedConnectionAcrossMultipleDetectCalls verifies
// that the overexposed-connection finding fires when Detect is called 3 or more times on separate
// single-workflow graphs that each reference the same service connection. This exercises the
// cross-call accumulation behavior introduced by making connectionUsage a struct field.
func TestServiceConnectionsDetection_Detect_OverexposedConnectionAcrossMultipleDetectCalls(t *testing.T) {
	d := New()
	ctx := context.Background()

	buildGraph := func(wfID, wfName string) *graph.Graph {
		g := graph.NewGraph()
		wf := graph.NewWorkflowNode(wfID, wfName, wfName+".yml", "owner/repo", nil)
		g.AddNode(wf)
		step := graph.NewStepNode("step-"+wfID, "deploy", 10)
		step.With = map[string]string{
			"azureSubscription": "shared-prod-connection",
		}
		step.SetParent(wf.ID())
		g.AddNode(step)
		g.AddEdge(wf.ID(), step.ID(), graph.EdgeContains)
		return g
	}

	// First call: 1 workflow references the connection — below threshold, no overexposed finding
	findings1, err := d.Detect(ctx, buildGraph("wf1", "pipeline1"))
	require.NoError(t, err)
	for _, f := range findings1 {
		assert.NotEqual(t, detections.VulnOverexposedServiceConnections, f.Type,
			"Expected no overexposed finding after first Detect call")
	}

	// Second call: 2 workflows total — still below threshold of 3
	findings2, err := d.Detect(ctx, buildGraph("wf2", "pipeline2"))
	require.NoError(t, err)
	for _, f := range findings2 {
		assert.NotEqual(t, detections.VulnOverexposedServiceConnections, f.Type,
			"Expected no overexposed finding after second Detect call")
	}

	// Third call: 3 workflows total — meets the >= 3 threshold, finding must be returned
	findings3, err := d.Detect(ctx, buildGraph("wf3", "pipeline3"))
	require.NoError(t, err)

	found := false
	for _, f := range findings3 {
		if f.Type == detections.VulnOverexposedServiceConnections {
			found = true
			assert.Equal(t, platforms.PlatformAzureDevOps, f.Platform)
			assert.Equal(t, detections.ClassPrivilegeEscalation, f.Class)
			assert.Equal(t, detections.SeverityMedium, f.Severity)
			assert.Contains(t, f.Evidence, "shared-prod-connection")
			assert.Contains(t, f.Evidence, "3 workflows")
		}
	}
	assert.True(t, found, "Expected VulnOverexposedServiceConnections finding on 3rd Detect call")

	// Fourth call: same connection in a 4th workflow — finding must NOT be emitted again (dedup)
	findings4, err := d.Detect(ctx, buildGraph("wf4", "pipeline4"))
	require.NoError(t, err)
	for _, f := range findings4 {
		assert.NotEqual(t, detections.VulnOverexposedServiceConnections, f.Type,
			"Expected no duplicate overexposed finding on 4th Detect call (already emitted)")
	}
}
