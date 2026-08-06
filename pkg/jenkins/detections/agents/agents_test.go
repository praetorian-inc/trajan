package agents

import (
	"context"
	"testing"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestDetect_AnyAgent(t *testing.T) {
	d := New()
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "Jenkinsfile", "Jenkinsfile", "org/repo", []string{"push"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "Build", "any")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(context.Background(), g)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("Detect() returned %d findings, want 1", len(findings))
	}
	if findings[0].Type != detections.VulnSelfHostedRunner {
		t.Errorf("finding type = %q, want %q", findings[0].Type, detections.VulnSelfHostedRunner)
	}
	if findings[0].Platform != "jenkins" {
		t.Errorf("finding platform = %q, want %q", findings[0].Platform, "jenkins")
	}
}

func TestDetect_MasterAgent(t *testing.T) {
	d := New()
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "Jenkinsfile", "Jenkinsfile", "org/repo", []string{"push"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "Build", "master")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(context.Background(), g)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("Detect() returned %d findings, want 1", len(findings))
	}
}

func TestDetect_EmptyAgent(t *testing.T) {
	d := New()
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "Jenkinsfile", "Jenkinsfile", "org/repo", []string{"push"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "Build", "")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(context.Background(), g)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("Detect() returned %d findings, want 1", len(findings))
	}
}

func TestDetect_SafeAgent(t *testing.T) {
	d := New()
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "Jenkinsfile", "Jenkinsfile", "org/repo", []string{"push"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "Build", "linux-agent")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(context.Background(), g)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("Detect() returned %d findings, want 0", len(findings))
	}
}
