package permissions

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestDetection_ImplementsInterface(t *testing.T) {
	var _ detections.Detection = (*Detection)(nil)
}

func TestDetection_Name(t *testing.T) {
	d := New()
	assert.Equal(t, "token-exposure", d.Name())
}

func TestDetection_Platform(t *testing.T) {
	d := New()
	assert.Equal(t, "gitlab", d.Platform())
}

func TestDetect_JobTokenInMergeRequest(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow triggered by merge request (zero-click)
	wf := graph.NewWorkflowNode("wf1", "test-workflow", ".gitlab-ci.yml", "test/repo", []string{"merge_request"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	// Create job
	job := graph.NewJobNode("job1", "test-job", "")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create step that uses CI_JOB_TOKEN
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

	// Create workflow triggered by push (not zero-click)
	wf := graph.NewWorkflowNode("wf1", "test-workflow", ".gitlab-ci.yml", "test/repo", []string{"push"})
	wf.AddTag(graph.TagPush)
	g.AddNode(wf)

	// Create job with CI_JOB_TOKEN
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

	// Create workflow
	wf := graph.NewWorkflowNode("wf1", "test-workflow", ".gitlab-ci.yml", "test/repo", []string{"merge_request"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	// Create job that doesn't expose dangerous tokens
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
