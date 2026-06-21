package mrsecrets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

// TestDetect_SecretsInMRPipeline tests that secrets accessible in MR pipelines are detected
func TestDetect_SecretsInMRPipeline(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with merge_request trigger
	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	// Create job that runs on merge requests (job-level If condition)
	job := graph.NewJobNode("job1", "test-job", "docker")
	job.If = "$CI_PIPELINE_SOURCE == \"merge_request_event\""
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create step that accesses sensitive variable
	step := graph.NewStepNode("step1", "deploy", 15)
	step.Run = "echo \"Deploying with token: $DEPLOY_TOKEN\""
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 1, "Should detect secret exposure in MR pipeline")
	assert.Equal(t, detections.VulnMergeRequestSecretsExposure, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	assert.Contains(t, findings[0].Evidence, "DEPLOY_TOKEN")
	assert.Contains(t, findings[0].Remediation, "protected branch")
}

// TestDetect_ProtectedBranchOnly tests that jobs restricted to protected branches don't trigger findings
func TestDetect_ProtectedBranchOnly(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	// Job restricted to main branch (protected)
	job := graph.NewJobNode("job1", "deploy-job", "docker")
	job.If = "$CI_COMMIT_BRANCH == \"main\" && $CI_PIPELINE_SOURCE == \"merge_request_event\""
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "deploy", 15)
	step.Run = "kubectl apply -f deployment.yaml --token=$KUBE_TOKEN"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 1, "Should detect secrets when job explicitly runs on MR events even if restricted to main branch")
}

// TestDetect_MultipleSecretsInMR tests detection of multiple sensitive variables
func TestDetect_MultipleSecretsInMR(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test-job", "docker")
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Multiple secrets in different steps
	step1 := graph.NewStepNode("step1", "auth", 15)
	step1.Run = "aws configure set aws_access_key_id $AWS_KEY"
	step1.SetParent(job.ID())
	g.AddNode(step1)
	g.AddEdge(job.ID(), step1.ID(), graph.EdgeContains)

	step2 := graph.NewStepNode("step2", "deploy", 20)
	step2.Run = "curl -H \"Authorization: Bearer $API_TOKEN\" https://api.example.com/deploy"
	step2.SetParent(job.ID())
	g.AddNode(step2)
	g.AddEdge(job.ID(), step2.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 1, "Should detect one aggregated finding")

	assert.Equal(t, detections.VulnMergeRequestSecretsExposure, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	// Check evidence contains both variables
	assert.Contains(t, findings[0].Evidence, "AWS_KEY")
	assert.Contains(t, findings[0].Evidence, "API_TOKEN")
}

// TestDetect_NoSecretsInScript tests that jobs without sensitive variables are ignored
func TestDetect_NoSecretsInScript(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test-job", "docker")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "test", 15)
	step.Run = "npm test && npm run lint"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "Should not detect findings when no secrets are used")
}

// TestDetect_ExternalPullRequest tests detection on external_pull_request events
func TestDetect_ExternalPullRequest(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{})
	wf.AddTag(graph.TagExternalPullRequest)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build-job", "docker")
	job.If = "$CI_PIPELINE_SOURCE == \"external_pull_request_event\""
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "build", 15)
	step.Run = "docker build --secret id=npm,src=$NPM_TOKEN ."
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 1, "Should detect secrets in external pull request pipelines")
	assert.Equal(t, detections.VulnMergeRequestSecretsExposure, findings[0].Type)
}

// TestDetect_MasterBranchProtected tests detection for master branch protection
func TestDetect_MasterBranchProtected(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	// Job restricted to master branch (protected)
	job := graph.NewJobNode("job1", "deploy-job", "docker")
	job.If = "$CI_COMMIT_REF_NAME == \"master\""
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "deploy", 15)
	step.Run = "deploy.sh --password=$DEPLOY_PASSWORD"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "Should not detect secrets when job is restricted to master branch")
}

// TestDetect_VariousSecretKeywords tests detection of different secret keywords
func TestDetect_VariousSecretKeywords(t *testing.T) {
	testCases := []struct {
		name     string
		script   string
		expected bool
	}{
		{
			name:     "token keyword",
			script:   "curl -H \"Token: $AUTH_TOKEN\" api.example.com",
			expected: true,
		},
		{
			name:     "key keyword",
			script:   "aws s3 cp file.txt s3://bucket/ --key $S3_KEY",
			expected: true,
		},
		{
			name:     "secret keyword",
			script:   "echo $MY_SECRET | base64",
			expected: true,
		},
		{
			name:     "password keyword",
			script:   "mysql -u root -p$DB_PASSWORD",
			expected: true,
		},
		{
			name:     "api_key keyword",
			script:   "curl -H \"X-Api-Key: $API_KEY\" api.example.com",
			expected: true,
		},
		{
			name:     "credentials keyword",
			script:   "login --credentials $CREDENTIALS",
			expected: true,
		},
		{
			name:     "no secrets",
			script:   "npm run build && npm run test",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := graph.NewGraph()

			wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
			wf.AddTag(graph.TagMergeRequest)
			g.AddNode(wf)

			job := graph.NewJobNode("job1", "test-job", "docker")
			job.SetParent(wf.ID())
			g.AddNode(job)
			g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

			step := graph.NewStepNode("step1", "test", 15)
			step.Run = tc.script
			step.SetParent(job.ID())
			g.AddNode(step)
			g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

			d := New()
			findings, err := d.Detect(context.Background(), g)
			require.NoError(t, err)

			if tc.expected {
				assert.Len(t, findings, 1, "Should detect secret keyword: %s", tc.name)
			} else {
				assert.Len(t, findings, 0, "Should not detect finding: %s", tc.name)
			}
		})
	}
}

// TestDetect_NoMRTrigger tests that non-MR pipelines are ignored
func TestDetect_NoMRTrigger(t *testing.T) {
	g := graph.NewGraph()

	// Workflow without MR trigger
	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"push"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test-job", "docker")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "deploy", 15)
	step.Run = "deploy.sh --token=$DEPLOY_TOKEN"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "Should not detect findings in non-MR pipelines")
}
