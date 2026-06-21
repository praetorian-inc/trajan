package injection

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
	assert.Equal(t, "script-injection", d.Name())
}

func TestDetect_InjectionInScript(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test", "")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "deploy", 10)
	step.Run = "echo $CI_MERGE_REQUEST_TITLE"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnScriptInjection, findings[0].Type)
	assert.Contains(t, findings[0].Evidence, "CI_MERGE_REQUEST_TITLE")
}

func TestDetect_SafeScript(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test", "")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "test", 10)
	step.Run = "npm test"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)

	require.NoError(t, err)
	assert.Empty(t, findings)
}
