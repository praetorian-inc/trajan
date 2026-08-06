package selfhostedrunner

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestDetect_SelfHostedOnMR(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test", "self-hosted")
	job.RunnerTags = []string{"self-hosted"}
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

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

func TestDetect_SelfHostedOnProtectedBranch(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"push"})
	wf.AddTag(graph.TagPush)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "self-hosted")
	job.RunnerTags = []string{"self-hosted"}
	job.If = "$CI_COMMIT_BRANCH == \"main\""
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

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

// A group runner is shared across projects, so it carries the same risk.
func TestDetect_GroupRunnerOnMR(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test", "group-runner")
	job.RunnerTags = []string{"group-runner"}
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

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

// External PRs from forks are also untrusted
func TestDetect_ExternalPullRequest(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"external_pull_request_event"})
	wf.AddTag(graph.TagExternalPullRequest)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test", "self-hosted")
	job.RunnerTags = []string{"self-hosted"}
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

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

func TestDetect_JobLevelMRCondition(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test", "self-hosted")
	job.RunnerTags = []string{"self-hosted"}
	job.If = "$CI_PIPELINE_SOURCE == \"merge_request_event\""
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

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

// Jobs without tags default to shared runners (safe on GitLab.com)
func TestDetect_NoTagsOnMR(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test", "")
	job.RunnerTags = []string{}
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

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

func TestDetect_MultipleTagsWithSelfHosted(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test", "docker, self-hosted, linux")
	job.RunnerTags = []string{"docker", "self-hosted", "linux"}
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

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

func TestDetect_MixedCaseMergeRequest(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"Merge_REQUEST_Event"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test", "self-hosted")
	job.RunnerTags = []string{"self-hosted"}
	job.SetParent(wf.ID())
	job.Line = 10
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

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
			name:      "MR with branch condition",
			ifCond:    "$CI_PIPELINE_SOURCE == \"merge_request_event\" && $CI_COMMIT_BRANCH == \"feature\"",
			shouldTag: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := graph.NewGraph()

			wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
			wf.AddTag(graph.TagMergeRequest)
			g.AddNode(wf)

			job := graph.NewJobNode("job1", "test", "self-hosted")
			job.RunnerTags = []string{"self-hosted"}
			job.If = tt.ifCond
			job.SetParent(wf.ID())
			job.Line = 10
			g.AddNode(job)
			g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

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

			wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
			wf.AddTag(graph.TagMergeRequest)
			g.AddNode(wf)

			job := graph.NewJobNode("job1", "test", runner)
			job.RunnerTags = []string{runner}
			job.SetParent(wf.ID())
			job.Line = 10
			g.AddNode(job)
			g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

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
