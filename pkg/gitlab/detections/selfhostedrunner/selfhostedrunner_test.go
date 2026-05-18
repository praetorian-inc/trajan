package selfhostedrunner

import (
	"context"
	"testing"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDetect_SelfHostedOnMR tests detection of self-hosted runner on MR trigger
// This should create a finding (HIGH severity)
func TestDetect_SelfHostedOnMR(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with merge_request trigger
	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	// Create job with self-hosted runner tag
	job := graph.NewJobNode("job1", "test", "self-hosted")
	job.RunnerTags = []string{"self-hosted"}
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step
	step := graph.NewStepNode("step1", "test", 12)
	step.Run = "echo 'testing'"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 1)
	assert.Equal(t, detections.VulnSelfHostedRunner, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	assert.Equal(t, "gitlab", findings[0].Platform)
	assert.Equal(t, detections.ClassRunnerSecurity, findings[0].Class)
	assert.Contains(t, findings[0].Evidence, "self-hosted")
	assert.Contains(t, findings[0].Evidence, "merge request")
	assert.Equal(t, "test", findings[0].Job)
	assert.Equal(t, 10, findings[0].Line)
}

// TestDetect_SelfHostedOnProtectedBranch tests self-hosted runner on protected branch
// This should NOT create a finding (protected branch is safe)
func TestDetect_SelfHostedOnProtectedBranch(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with push trigger (no MR)
	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"push"})
	wf.AddTag(graph.TagPush)
	g.AddNode(wf)

	// Create job with self-hosted runner and protected branch condition
	job := graph.NewJobNode("job1", "deploy", "self-hosted")
	job.RunnerTags = []string{"self-hosted"}
	job.If = "$CI_COMMIT_BRANCH == \"main\""
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step
	step := graph.NewStepNode("step1", "deploy", 12)
	step.Run = "deploy.sh"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "Should not flag self-hosted runner on protected branch")
}

// TestDetect_GroupRunnerOnMR tests group-specific runner on MR trigger
// Group runners can be shared across projects, creating risk
func TestDetect_GroupRunnerOnMR(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with merge_request trigger
	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	// Create job with group runner tag
	job := graph.NewJobNode("job1", "test", "group-runner")
	job.RunnerTags = []string{"group-runner"}
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step
	step := graph.NewStepNode("step1", "test", 12)
	step.Run = "npm test"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 1)
	assert.Equal(t, detections.VulnSelfHostedRunner, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	assert.Contains(t, findings[0].Evidence, "group-runner")
}

// TestDetect_ExternalPullRequest tests self-hosted runner on external_pull_request
// External PRs from forks are also untrusted
func TestDetect_ExternalPullRequest(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with external_pull_request trigger
	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"external_pull_request_event"})
	wf.AddTag(graph.TagExternalPullRequest)
	g.AddNode(wf)

	// Create job with self-hosted runner
	job := graph.NewJobNode("job1", "test", "self-hosted")
	job.RunnerTags = []string{"self-hosted"}
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step
	step := graph.NewStepNode("step1", "test", 12)
	step.Run = "make test"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 1)
	assert.Equal(t, detections.VulnSelfHostedRunner, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	assert.Contains(t, findings[0].Evidence, "external")
}

// TestDetect_JobLevelMRCondition tests job with MR condition in If field
// Job explicitly checks for merge_request_event in its rules
func TestDetect_JobLevelMRCondition(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow without MR trigger
	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{})
	g.AddNode(wf)

	// Create job with self-hosted runner and MR condition
	job := graph.NewJobNode("job1", "test", "self-hosted")
	job.RunnerTags = []string{"self-hosted"}
	job.If = "$CI_PIPELINE_SOURCE == \"merge_request_event\""
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step
	step := graph.NewStepNode("step1", "test", 12)
	step.Run = "npm test"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 1)
	assert.Equal(t, detections.VulnSelfHostedRunner, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
}

// TestDetect_GitLabSaaSRunner tests GitLab.com SaaS runner on MR
// GitLab-hosted runners (saas-linux-small-amd64) are safe
func TestDetect_GitLabSaaSRunner(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with merge_request trigger
	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	// Create job with GitLab SaaS runner tag
	job := graph.NewJobNode("job1", "test", "saas-linux-small-amd64")
	job.RunnerTags = []string{"saas-linux-small-amd64"}
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step
	step := graph.NewStepNode("step1", "test", 12)
	step.Run = "npm test"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "Should not flag GitLab SaaS runners")
}

// TestDetect_NoTagsOnMR tests job without runner tags on MR
// Jobs without tags default to shared runners (safe on GitLab.com)
func TestDetect_NoTagsOnMR(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with merge_request trigger
	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	// Create job without runner tags (empty string)
	job := graph.NewJobNode("job1", "test", "")
	job.RunnerTags = []string{}
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step
	step := graph.NewStepNode("step1", "test", 12)
	step.Run = "npm test"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "Should not flag jobs with no tags (default to shared runners)")
}

// TestDetect_MultipleTagsWithSelfHosted tests job with multiple tags including self-hosted
func TestDetect_MultipleTagsWithSelfHosted(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with merge_request trigger
	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	// Create job with multiple tags including self-hosted
	job := graph.NewJobNode("job1", "test", "docker, self-hosted, linux")
	job.RunnerTags = []string{"docker", "self-hosted", "linux"}
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step
	step := graph.NewStepNode("step1", "test", 12)
	step.Run = "npm test"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 1)
	assert.Equal(t, detections.VulnSelfHostedRunner, findings[0].Type)
	assert.Contains(t, findings[0].Evidence, "self-hosted")
}

// TestDetect_MixedCaseMergeRequest tests mixed case merge_request_event
func TestDetect_MixedCaseMergeRequest(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with mixed case merge_request trigger
	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"Merge_REQUEST_Event"})
	g.AddNode(wf)

	// Create job with self-hosted runner
	job := graph.NewJobNode("job1", "test", "self-hosted")
	job.RunnerTags = []string{"self-hosted"}
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step
	step := graph.NewStepNode("step1", "test", 12)
	step.Run = "npm test"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 1, "Should detect mixed case merge_request_event")
}

// TestDetect_ProtectedBranchPatterns tests various protected branch patterns
func TestDetect_ProtectedBranchPatterns(t *testing.T) {
	tests := []struct {
		name      string
		ifCond    string
		shouldTag bool
	}{
		{
			name:      "main branch equality",
			ifCond:    "$CI_COMMIT_BRANCH == \"main\"",
			shouldTag: false,
		},
		{
			name:      "master branch equality",
			ifCond:    "$CI_COMMIT_BRANCH == \"master\"",
			shouldTag: false,
		},
		{
			name:      "main branch regex",
			ifCond:    "$CI_COMMIT_REF_NAME =~ /^main$/",
			shouldTag: false,
		},
		{
			name:      "master branch regex",
			ifCond:    "$CI_COMMIT_REF_NAME =~ /^master$/",
			shouldTag: false,
		},
		{
			name:      "feature branch",
			ifCond:    "$CI_COMMIT_BRANCH == \"feature-123\"",
			shouldTag: false,
		},
		{
			name:      "MR with branch condition",
			ifCond:    "$CI_PIPELINE_SOURCE == \"merge_request_event\" && $CI_COMMIT_BRANCH == \"feature\"",
			shouldTag: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := graph.NewGraph()

			// Create workflow with merge_request trigger
			wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
			wf.AddTag(graph.TagMergeRequest)
			g.AddNode(wf)

			// Create job with self-hosted runner and If condition
			job := graph.NewJobNode("job1", "test", "self-hosted")
			job.RunnerTags = []string{"self-hosted"}
			job.If = tt.ifCond
			job.SetParent(wf.ID())
			job.Line = 10
			g.AddNode(job)
			g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

			// Create a step
			step := graph.NewStepNode("step1", "test", 12)
			step.Run = "npm test"
			step.SetParent(job.ID())
			g.AddNode(step)
			g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

			d := New()
			findings, err := d.Detect(context.Background(), g)
			require.NoError(t, err)

			if tt.shouldTag {
				assert.Len(t, findings, 1, "Should flag non-protected branch")
			} else {
				assert.Len(t, findings, 0, "Should not flag protected branch")
			}
		})
	}
}

// TestDetect_CustomTagsOnMR tests custom/organization-specific runner tags on MR
func TestDetect_CustomTagsOnMR(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with merge_request trigger
	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	// Create job with custom organization runner tag
	job := graph.NewJobNode("job1", "test", "my-company-runner")
	job.RunnerTags = []string{"my-company-runner"}
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create a step
	step := graph.NewStepNode("step1", "test", 12)
	step.Run = "npm test"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	// Custom tags that aren't GitLab SaaS tags should be flagged
	assert.Len(t, findings, 1)
	assert.Equal(t, detections.VulnSelfHostedRunner, findings[0].Type)
	assert.Contains(t, findings[0].Evidence, "my-company-runner")
}

// TestDetect_SharedRunnersOnMR tests shared runner tags on MR (safe)
func TestDetect_SharedRunnersOnMR(t *testing.T) {
	safeRunners := []string{
		"saas-linux-small-amd64",
		"saas-linux-medium-amd64",
		"saas-linux-large-amd64",
		"saas-macos-medium-m1",
		"saas-windows-medium-amd64",
	}

	for _, runner := range safeRunners {
		t.Run(runner, func(t *testing.T) {
			g := graph.NewGraph()

			// Create workflow with merge_request trigger
			wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
			wf.AddTag(graph.TagMergeRequest)
			g.AddNode(wf)

			// Create job with GitLab SaaS runner
			job := graph.NewJobNode("job1", "test", runner)
			job.RunnerTags = []string{runner}
			job.SetParent(wf.ID())
			job.Line = 10
			g.AddNode(job)
			g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

			// Create a step
			step := graph.NewStepNode("step1", "test", 12)
			step.Run = "npm test"
			step.SetParent(job.ID())
			g.AddNode(step)
			g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

			d := New()
			findings, err := d.Detect(context.Background(), g)
			require.NoError(t, err)

			assert.Len(t, findings, 0, "Should not flag GitLab SaaS runner: %s", runner)
		})
	}
}
