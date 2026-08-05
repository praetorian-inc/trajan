package permissions

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

func TestDetect_JobTokenInMergeRequest(t *testing.T) {
	g := graph.NewGraph()

	// A merge_request trigger is zero-click.
	wf := graph.NewWorkflowNode("wf1", "test-workflow", ".gitlab-ci.yml", "test/repo", []string{"merge_request"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test-job", "")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "deploy", 10)
	step.Run = "curl -H \"Authorization: Bearer $CI_JOB_TOKEN\" https://api.example.com"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)

	require.NoError(t, err)
	require.Len(t, findings, 1)

	assert.Equal(t, "gitlab", findings[0].Platform)
	assert.Contains(t, findings[0].Evidence, "CI_JOB_TOKEN")
}

func TestDetect_JobTokenInPush(t *testing.T) {
	g := graph.NewGraph()

	// A push trigger is not zero-click.
	wf := graph.NewWorkflowNode("wf1", "test-workflow", ".gitlab-ci.yml", "test/repo", []string{"push"})
	wf.AddTag(graph.TagPush)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test-job", "")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "deploy", 10)
	step.Run = "curl -H \"Authorization: Bearer $CI_JOB_TOKEN\" https://api.example.com"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)

	require.NoError(t, err)
	assert.Empty(t, findings, "Push triggers are not zero-click, should not generate findings")
}

func TestDetect_SafeVariableUsage(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test-workflow", ".gitlab-ci.yml", "test/repo", []string{"merge_request"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test-job", "")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "test", 10)
	step.Run = "echo 'Running tests' && npm test"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)

	require.NoError(t, err)
	assert.Empty(t, findings)
}
