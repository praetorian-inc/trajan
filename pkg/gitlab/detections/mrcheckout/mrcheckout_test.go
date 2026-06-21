package mrcheckout

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestDetect_UnsafeCheckoutInMR(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with merge_request trigger
	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	// Create job
	job := graph.NewJobNode("job1", "test", "")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create steps for unsafe checkout pattern
	step1 := graph.NewStepNode("step1", "fetch", 10)
	step1.Run = "git fetch origin $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA"
	step1.SetParent(job.ID())
	g.AddNode(step1)
	g.AddEdge(job.ID(), step1.ID(), graph.EdgeContains)

	step2 := graph.NewStepNode("step2", "checkout", 11)
	step2.Run = "git checkout FETCH_HEAD"
	step2.SetParent(job.ID())
	g.AddNode(step2)
	g.AddEdge(job.ID(), step2.ID(), graph.EdgeContains)

	step3 := graph.NewStepNode("step3", "install", 12)
	step3.Run = "npm install"
	step3.SetParent(job.ID())
	g.AddNode(step3)
	g.AddEdge(job.ID(), step3.ID(), graph.EdgeContains)

	step4 := graph.NewStepNode("step4", "test", 13)
	step4.Run = "npm test"
	step4.SetParent(job.ID())
	g.AddNode(step4)
	g.AddEdge(job.ID(), step4.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 1)
	assert.Equal(t, detections.VulnMergeRequestUnsafeCheckout, findings[0].Type)
	assert.Equal(t, detections.SeverityCritical, findings[0].Severity)
	assert.Contains(t, findings[0].Evidence, "checks out untrusted code")
}

func TestDetect_SafeCheckout(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test", "")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step1 := graph.NewStepNode("step1", "install", 10)
	step1.Run = "npm install"
	step1.SetParent(job.ID())
	g.AddNode(step1)
	g.AddEdge(job.ID(), step1.ID(), graph.EdgeContains)

	step2 := graph.NewStepNode("step2", "test", 11)
	step2.Run = "npm test"
	step2.SetParent(job.ID())
	g.AddNode(step2)
	g.AddEdge(job.ID(), step2.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0)
}

// Test for bug #3: Same-line checkout + execution
func TestDetect_SameLineCheckoutAndExecution(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test", "")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Single line with both checkout and execution
	step1 := graph.NewStepNode("step1", "checkout-and-install", 10)
	step1.Run = "git checkout $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA && npm install"
	step1.SetParent(job.ID())
	g.AddNode(step1)
	g.AddEdge(job.ID(), step1.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 1, "Should detect same-line checkout + execution")
	assert.Equal(t, detections.VulnMergeRequestUnsafeCheckout, findings[0].Type)
	assert.Equal(t, detections.SeverityCritical, findings[0].Severity)
	assert.Contains(t, findings[0].Evidence, "checks out untrusted code")
	assert.Contains(t, findings[0].Evidence, "Execution sink found:")
}

// Test for bug #2: Mixed case trigger
func TestDetect_MixedCaseTrigger(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_REQUEST_event"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test", "")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step1 := graph.NewStepNode("step1", "checkout", 10)
	step1.Run = "git checkout FETCH_HEAD"
	step1.SetParent(job.ID())
	g.AddNode(step1)
	g.AddEdge(job.ID(), step1.ID(), graph.EdgeContains)

	step2 := graph.NewStepNode("step2", "install", 11)
	step2.Run = "npm install"
	step2.SetParent(job.ID())
	g.AddNode(step2)
	g.AddEdge(job.ID(), step2.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 1, "Should detect MR trigger with mixed case")
	assert.Equal(t, detections.VulnMergeRequestUnsafeCheckout, findings[0].Type)
	assert.Equal(t, detections.SeverityCritical, findings[0].Severity)
}

// Test uppercase merge_request_event
func TestDetect_UppercaseMergeRequestEvent(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"MERGE_REQUEST_EVENT"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test", "")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step1 := graph.NewStepNode("step1", "checkout", 10)
	step1.Run = "git checkout FETCH_HEAD"
	step1.SetParent(job.ID())
	g.AddNode(step1)
	g.AddEdge(job.ID(), step1.ID(), graph.EdgeContains)

	step2 := graph.NewStepNode("step2", "install", 11)
	step2.Run = "npm install"
	step2.SetParent(job.ID())
	g.AddNode(step2)
	g.AddEdge(job.ID(), step2.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 1, "Should detect uppercase merge_request_event")
}

// Test with job-level If condition
func TestDetect_JobLevelIfCondition(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test", "")
	job.If = "$CI_PIPELINE_SOURCE == \"merge_request_event\""
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step1 := graph.NewStepNode("step1", "checkout", 10)
	step1.Run = "git checkout FETCH_HEAD"
	step1.SetParent(job.ID())
	g.AddNode(step1)
	g.AddEdge(job.ID(), step1.ID(), graph.EdgeContains)

	step2 := graph.NewStepNode("step2", "install", 11)
	step2.Run = "npm install"
	step2.SetParent(job.ID())
	g.AddNode(step2)
	g.AddEdge(job.ID(), step2.ID(), graph.EdgeContains)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 1, "Should detect MR trigger in job If condition")
}
