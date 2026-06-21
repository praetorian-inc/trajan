package gates

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis/flow"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

func TestDetector_DeploymentApproval(t *testing.T) {
	tests := []struct {
		name     string
		jobName  string
		wantGate bool
	}{
		{
			name:     "production job triggers deployment gate",
			jobName:  "deploy-production",
			wantGate: true,
		},
		{
			name:     "deploy job triggers deployment gate",
			jobName:  "deploy-to-staging",
			wantGate: true,
		},
		{
			name:     "release job triggers deployment gate",
			jobName:  "release-artifacts",
			wantGate: true,
		},
		{
			name:     "regular job does not trigger gate",
			jobName:  "run-tests",
			wantGate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create graph with job node
			g := graph.NewGraph()
			job := graph.NewJobNode("job-1", tt.jobName, "ubuntu-latest")
			g.AddNode(job)

			// Detect gates
			detector := NewDetector()
			gates := detector.DetectGates(g, []string{"job-1"})

			if tt.wantGate {
				require.Len(t, gates, 1, "expected one deployment approval gate")
				assert.Equal(t, flow.GateDeploymentApproval, gates[0].Type)
				assert.Contains(t, gates[0].Description, "environment or has deployment-related name")
			} else {
				assert.Empty(t, gates, "expected no gates")
			}
		})
	}
}

func TestDetector_LabelRequired(t *testing.T) {
	tests := []struct {
		name     string
		triggers []string
		wantGate bool
	}{
		{
			name:     "labeled trigger indicates gate",
			triggers: []string{"pull_request_target:labeled"},
			wantGate: true,
		},
		{
			name:     "multiple triggers with labeled indicates gate",
			triggers: []string{"pull_request_target:opened", "pull_request_target:labeled"},
			wantGate: true,
		},
		{
			name:     "no labeled trigger means no gate",
			triggers: []string{"pull_request_target:opened"},
			wantGate: false,
		},
		{
			name:     "issue_comment has no label gate",
			triggers: []string{"issue_comment"},
			wantGate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create graph with workflow node
			g := graph.NewGraph()
			wf := graph.NewWorkflowNode("wf-1", "test-workflow", ".github/workflows/test.yml", "owner/repo", tt.triggers)
			g.AddNode(wf)

			// Detect gates
			detector := NewDetector()
			gates := detector.DetectGates(g, []string{"wf-1"})

			if tt.wantGate {
				require.Len(t, gates, 1, "expected one label required gate")
				assert.Equal(t, flow.GateLabelRequired, gates[0].Type)
				assert.Contains(t, gates[0].Description, "labeled only")
			} else {
				assert.Empty(t, gates, "expected no gates")
			}
		})
	}
}

func TestDetector_AuthorAssociation(t *testing.T) {
	tests := []struct {
		name     string
		stepIf   string
		stepRun  string
		stepName string
		wantGate bool
	}{
		{
			name:     "if condition checks author_association",
			stepIf:   "github.event.comment.author_association == 'MEMBER'",
			wantGate: true,
		},
		{
			name:     "run command checks author_association",
			stepRun:  "if [ ${{ github.event.comment.author_association }} == 'MEMBER' ]; then echo ok; fi",
			wantGate: true,
		},
		{
			name:     "no author_association check",
			stepRun:  "echo 'hello world'",
			wantGate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create graph with step node
			g := graph.NewGraph()
			step := graph.NewStepNode("step-1", tt.stepName, 10)
			step.If = tt.stepIf
			step.Run = tt.stepRun
			g.AddNode(step)

			// Detect gates
			detector := NewDetector()
			gates := detector.DetectGates(g, []string{"step-1"})

			if tt.wantGate {
				require.Len(t, gates, 1, "expected one author association gate")
				assert.Equal(t, flow.GateAuthorAssociation, gates[0].Type)
				assert.Contains(t, gates[0].Description, "author_association")
			} else {
				assert.Empty(t, gates, "expected no gates")
			}
		})
	}
}

func TestDetector_PermissionCheck(t *testing.T) {
	tests := []struct {
		name     string
		stepUses string
		stepRun  string
		stepName string
		wantGate bool
	}{
		{
			name:     "github-script with MEMBER check",
			stepUses: "actions/github-script@v6",
			stepRun:  "if (context.payload.comment.author_association === 'MEMBER') { ... }",
			wantGate: true,
		},
		{
			name:     "github-script with permission keyword",
			stepUses: "actions/github-script@v6",
			stepRun:  "checkPermission(context)",
			wantGate: true,
		},
		{
			name:     "step name indicates permission check",
			stepName: "Check user permissions",
			wantGate: true,
		},
		{
			name:     "step name indicates access check",
			stepName: "Validate access rights",
			wantGate: true,
		},
		{
			name:     "no permission check",
			stepUses: "actions/checkout@v4",
			stepName: "Checkout code",
			wantGate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create graph with step node
			g := graph.NewGraph()
			step := graph.NewStepNode("step-1", tt.stepName, 10)
			step.Uses = tt.stepUses
			step.Run = tt.stepRun
			g.AddNode(step)

			// Detect gates
			detector := NewDetector()
			gates := detector.DetectGates(g, []string{"step-1"})

			if tt.wantGate {
				require.Len(t, gates, 1, "expected one permission check gate")
				assert.Equal(t, flow.GatePermissionCheck, gates[0].Type)
				assert.Contains(t, gates[0].Description, "permission validation")
			} else {
				assert.Empty(t, gates, "expected no gates")
			}
		})
	}
}

func TestDetector_MultipleGatesInPath(t *testing.T) {
	// Create graph with multiple nodes containing gates
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf-1", "test-workflow", ".github/workflows/test.yml", "owner/repo", []string{"pull_request_target:labeled"})
	g.AddNode(wf)

	job := graph.NewJobNode("job-1", "deploy-production", "ubuntu-latest")
	g.AddNode(job)

	step := graph.NewStepNode("step-1", "Check permissions", 10)
	step.Uses = "actions/github-script@v6"
	step.Run = "checkPermission(context)"
	g.AddNode(step)

	// Detect gates in path
	detector := NewDetector()
	gates := detector.DetectGates(g, []string{"wf-1", "job-1", "step-1"})

	// Should detect all three gates
	require.Len(t, gates, 3, "expected three gates")

	gateTypes := make(map[flow.GateType]bool)
	for _, gate := range gates {
		gateTypes[gate.Type] = true
	}

	assert.True(t, gateTypes[flow.GateLabelRequired], "should detect label required gate")
	assert.True(t, gateTypes[flow.GateDeploymentApproval], "should detect deployment approval gate")
	assert.True(t, gateTypes[flow.GatePermissionCheck], "should detect permission check gate")
}

func TestHasBlockingGate(t *testing.T) {
	detector := NewDetector()

	tests := []struct {
		name  string
		gates []flow.GateInfo
		want  bool
	}{
		{
			name: "deployment approval is blocking",
			gates: []flow.GateInfo{
				{Type: flow.GateDeploymentApproval},
			},
			want: true,
		},
		{
			name: "permission check is blocking",
			gates: []flow.GateInfo{
				{Type: flow.GatePermissionCheck},
			},
			want: true,
		},
		{
			name: "label required is not blocking",
			gates: []flow.GateInfo{
				{Type: flow.GateLabelRequired},
			},
			want: false,
		},
		{
			name: "author association is not blocking",
			gates: []flow.GateInfo{
				{Type: flow.GateAuthorAssociation},
			},
			want: false,
		},
		{
			name: "mix with blocking gate returns true",
			gates: []flow.GateInfo{
				{Type: flow.GateLabelRequired},
				{Type: flow.GatePermissionCheck},
			},
			want: true,
		},
		{
			name:  "no gates returns false",
			gates: []flow.GateInfo{},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.HasBlockingGate(tt.gates)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHasSoftGate(t *testing.T) {
	detector := NewDetector()

	tests := []struct {
		name  string
		gates []flow.GateInfo
		want  bool
	}{
		{
			name: "label required is soft gate",
			gates: []flow.GateInfo{
				{Type: flow.GateLabelRequired},
			},
			want: true,
		},
		{
			name: "author association is soft gate",
			gates: []flow.GateInfo{
				{Type: flow.GateAuthorAssociation},
			},
			want: true,
		},
		{
			name: "deployment approval is not soft gate",
			gates: []flow.GateInfo{
				{Type: flow.GateDeploymentApproval},
			},
			want: false,
		},
		{
			name: "permission check is not soft gate",
			gates: []flow.GateInfo{
				{Type: flow.GatePermissionCheck},
			},
			want: false,
		},
		{
			name:  "no gates returns false",
			gates: []flow.GateInfo{},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.HasSoftGate(tt.gates)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCalculateConfidence(t *testing.T) {
	detector := NewDetector()

	tests := []struct {
		name           string
		baseConfidence flow.Confidence
		gates          []flow.GateInfo
		want           flow.Confidence
	}{
		{
			name:           "no gates keeps confidence",
			baseConfidence: flow.ConfidenceHigh,
			gates:          []flow.GateInfo{},
			want:           flow.ConfidenceHigh,
		},
		{
			name:           "blocking gate reduces to low",
			baseConfidence: flow.ConfidenceHigh,
			gates: []flow.GateInfo{
				{Type: flow.GateDeploymentApproval},
			},
			want: flow.ConfidenceLow,
		},
		{
			name:           "soft gate reduces high to medium",
			baseConfidence: flow.ConfidenceHigh,
			gates: []flow.GateInfo{
				{Type: flow.GateLabelRequired},
			},
			want: flow.ConfidenceMedium,
		},
		{
			name:           "soft gate reduces medium to low",
			baseConfidence: flow.ConfidenceMedium,
			gates: []flow.GateInfo{
				{Type: flow.GateAuthorAssociation},
			},
			want: flow.ConfidenceLow,
		},
		{
			name:           "soft gate on low stays low",
			baseConfidence: flow.ConfidenceLow,
			gates: []flow.GateInfo{
				{Type: flow.GateLabelRequired},
			},
			want: flow.ConfidenceLow,
		},
		{
			name:           "multiple soft gates reduce by multiple levels",
			baseConfidence: flow.ConfidenceHigh,
			gates: []flow.GateInfo{
				{Type: flow.GateLabelRequired},
				{Type: flow.GateAuthorAssociation},
			},
			want: flow.ConfidenceLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.CalculateConfidence(tt.baseConfidence, tt.gates)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsBlockingGate(t *testing.T) {
	tests := []struct {
		name     string
		gateType flow.GateType
		want     bool
	}{
		{
			name:     "deployment approval is blocking",
			gateType: flow.GateDeploymentApproval,
			want:     true,
		},
		{
			name:     "permission check is blocking",
			gateType: flow.GatePermissionCheck,
			want:     true,
		},
		{
			name:     "label required is not blocking",
			gateType: flow.GateLabelRequired,
			want:     false,
		},
		{
			name:     "author association is not blocking",
			gateType: flow.GateAuthorAssociation,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsBlockingGate(tt.gateType)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsSoftGate(t *testing.T) {
	tests := []struct {
		name     string
		gateType flow.GateType
		want     bool
	}{
		{
			name:     "label required is soft gate",
			gateType: flow.GateLabelRequired,
			want:     true,
		},
		{
			name:     "author association is soft gate",
			gateType: flow.GateAuthorAssociation,
			want:     true,
		},
		{
			name:     "deployment approval is not soft gate",
			gateType: flow.GateDeploymentApproval,
			want:     false,
		},
		{
			name:     "permission check is not soft gate",
			gateType: flow.GatePermissionCheck,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSoftGate(tt.gateType)
			assert.Equal(t, tt.want, got)
		})
	}
}
