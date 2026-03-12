package unpinned

import (
	"context"
	"testing"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetection_ImplementsInterface(t *testing.T) {
	var _ detections.Detection = (*Detection)(nil)
}

func TestDetection_Name(t *testing.T) {
	d := New()
	assert.Equal(t, "unpinned-include", d.Name())
}

func TestDetection_Platform(t *testing.T) {
	d := New()
	assert.Equal(t, "gitlab", d.Platform())
}

func TestDetection_Severity(t *testing.T) {
	d := New()
	assert.Equal(t, detections.SeverityLow, d.Severity())
}

func TestDetect_UnpinnedProjectInclude(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with unpinned project include
	wf := graph.NewWorkflowNode("wf1", "test-workflow", ".gitlab-ci.yml", "test/repo", []string{"merge_request"})
	wf.Includes = []graph.Include{
		{
			Type:    "project",
			Project: "group/project",
			Path:    "/templates/ci.yml",
			Ref:     "", // Unpinned - no ref specified
		},
	}
	g.AddNode(wf)

	d := New()
	findings, err := d.Detect(context.Background(), g)

	require.NoError(t, err)
	require.Len(t, findings, 1)

	assert.Equal(t, detections.VulnUnpinnedAction, findings[0].Type)
	assert.Equal(t, "gitlab", findings[0].Platform)
	assert.Equal(t, detections.SeverityLow, findings[0].Severity)
	assert.Contains(t, findings[0].Evidence, "group/project")
}

func TestDetect_PinnedProjectIncludeWithBranch(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with project include pinned to branch (not SHA)
	wf := graph.NewWorkflowNode("wf1", "test-workflow", ".gitlab-ci.yml", "test/repo", []string{"merge_request"})
	wf.Includes = []graph.Include{
		{
			Type:    "project",
			Project: "group/project",
			Path:    "/templates/ci.yml",
			Ref:     "main", // Pinned to branch - still vulnerable
		},
	}
	g.AddNode(wf)

	d := New()
	findings, err := d.Detect(context.Background(), g)

	require.NoError(t, err)
	require.Len(t, findings, 1, "Branch refs are not secure pinning")
}

func TestDetect_PinnedProjectIncludeWithSHA(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with project include pinned to commit SHA
	wf := graph.NewWorkflowNode("wf1", "test-workflow", ".gitlab-ci.yml", "test/repo", []string{"merge_request"})
	wf.Includes = []graph.Include{
		{
			Type:    "project",
			Project: "group/project",
			Path:    "/templates/ci.yml",
			Ref:     "abc123def456abc123def456abc123def456ab12", // 40-char SHA
		},
	}
	g.AddNode(wf)

	d := New()
	findings, err := d.Detect(context.Background(), g)

	require.NoError(t, err)
	assert.Empty(t, findings, "Includes pinned to commit SHA should not generate findings")
}

func TestDetect_LocalInclude(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with local include
	wf := graph.NewWorkflowNode("wf1", "test-workflow", ".gitlab-ci.yml", "test/repo", []string{"merge_request"})
	wf.Includes = []graph.Include{
		{
			Type: "local",
			Path: "/templates/ci.yml",
		},
	}
	g.AddNode(wf)

	d := New()
	findings, err := d.Detect(context.Background(), g)

	require.NoError(t, err)
	assert.Empty(t, findings, "Local includes are version-controlled and don't need pinning")
}

func TestDetect_TemplateInclude(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with GitLab template include
	wf := graph.NewWorkflowNode("wf1", "test-workflow", ".gitlab-ci.yml", "test/repo", []string{"merge_request"})
	wf.Includes = []graph.Include{
		{
			Type:     "template",
			Template: "Auto-DevOps.gitlab-ci.yml",
		},
	}
	g.AddNode(wf)

	d := New()
	findings, err := d.Detect(context.Background(), g)

	require.NoError(t, err)
	assert.Empty(t, findings, "GitLab templates are managed by GitLab and trusted")
}

func TestDetect_RemoteInclude(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with remote include
	wf := graph.NewWorkflowNode("wf1", "test-workflow", ".gitlab-ci.yml", "test/repo", []string{"merge_request"})
	wf.Includes = []graph.Include{
		{
			Type:   "remote",
			Remote: "https://example.com/ci-template.yml",
		},
	}
	g.AddNode(wf)

	d := New()
	findings, err := d.Detect(context.Background(), g)

	require.NoError(t, err)
	require.Len(t, findings, 1, "Remote includes are always risky")
	assert.Contains(t, findings[0].Evidence, "example.com")
}

func TestDetect_MultipleIncludes(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with multiple includes
	wf := graph.NewWorkflowNode("wf1", "test-workflow", ".gitlab-ci.yml", "test/repo", []string{"merge_request"})
	wf.Includes = []graph.Include{
		{
			Type: "local",
			Path: "/local.yml",
		},
		{
			Type:    "project",
			Project: "group/project1",
			Ref:     "abc123def456abc123def456abc123def456ab12", // Pinned
		},
		{
			Type:    "project",
			Project: "group/project2",
			Ref:     "main", // Unpinned (branch)
		},
		{
			Type:    "project",
			Project: "group/project3",
			Ref:     "", // Unpinned (no ref)
		},
	}
	g.AddNode(wf)

	d := New()
	findings, err := d.Detect(context.Background(), g)

	require.NoError(t, err)
	assert.Len(t, findings, 2, "Should detect the 2 unpinned project includes")
}
