package pwnrequest

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestPwnRequestPlugin_DetectsUnsafeCheckout(t *testing.T) {
	yaml := `
name: PR Target
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install && npm test
`
	g, err := analysis.BuildGraph("owner/repo", "pr.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnPwnRequest, findings[0].Type)
	assert.Equal(t, detections.SeverityCritical, findings[0].Severity)
}

func TestPwnRequestPlugin_SafeCheckout(t *testing.T) {
	yaml := `
name: PR Target Safe
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "Only checking out base branch"
`
	g, err := analysis.BuildGraph("owner/repo", "safe.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0)
}

func TestPwnRequestPlugin_EvidenceNamesSinkCommand(t *testing.T) {
	// Operators need to see WHICH command is the sink, not "may execute
	// untrusted code, review to confirm." Gato-X-style: "Sink: <command>".
	yaml := `
name: PR Target with Pnpm Sink
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: pnpm install
`
	findings, err := testWorkflow(t, yaml)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	assert.Contains(t, findings[0].Evidence, "Sink: pnpm install",
		"Evidence must name the specific execution sink command")

	require.NotNil(t, findings[0].Details)
	assert.Equal(t, "pnpm install", findings[0].Details.Metadata["sink"],
		"Metadata[sink] must be the bare command for programmatic consumers")
}

func TestPwnRequestPlugin_EvidenceTruncatesLongSinkCommand(t *testing.T) {
	yaml := `
name: PR Target with Long Sink
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: pnpm --filter=@example/very-long-package-name run build:with:many:colons:and:options --flag-one --flag-two --flag-three
`
	findings, err := testWorkflow(t, yaml)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	// The command exceeds 60 chars; assert we truncate (with ellipsis) so
	// long evidence strings stay readable.
	assert.Contains(t, findings[0].Evidence, "Sink: pnpm --filter=")
	assert.Contains(t, findings[0].Evidence, "...")
}

func TestPwnRequestPlugin_Properties(t *testing.T) {
	p := New()
	assert.Equal(t, "pwn-request", p.Name())
	assert.Equal(t, "github", p.Platform())
	assert.Equal(t, detections.SeverityCritical, p.Severity())
}

// testWorkflow is a helper that builds a graph from workflow YAML and runs the pwn-request detection.
func testWorkflow(t *testing.T, yaml string) ([]detections.Finding, error) {
	t.Helper()
	g, err := analysis.BuildGraph("owner/repo", "test.yml", []byte(yaml))
	if err != nil {
		return nil, err
	}
	plugin := New()
	return plugin.Detect(context.Background(), g)
}

func TestUsesLocalInPullRequestTarget(t *testing.T) {
	workflow := `
on: pull_request_target

jobs:
  build:
    uses: ./.github/workflows/reusable.yml
`
	findings, err := testWorkflow(t, workflow)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnPwnRequest, findings[0].Type)
	assert.Equal(t, detections.SeverityCritical, findings[0].Severity)
	assert.Contains(t, findings[0].Evidence, "Local workflow loading")
	assert.Contains(t, findings[0].Evidence, "uses: ./")
	assert.Contains(t, findings[0].Evidence, "pull_request_target")
}

func TestUsesLocalInIssueComment(t *testing.T) {
	workflow := `
on: issue_comment

jobs:
  respond:
    uses: ./workflows/respond.yml
`
	findings, err := testWorkflow(t, workflow)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnPwnRequest, findings[0].Type)
	assert.Contains(t, findings[0].Evidence, "Local workflow loading")
	assert.Contains(t, findings[0].Evidence, "./workflows/respond.yml")
}

func TestUsesLocalInWorkflowRun(t *testing.T) {
	workflow := `
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

jobs:
  notify:
    uses: ./.github/workflows/notify.yml
`
	findings, err := testWorkflow(t, workflow)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnPwnRequest, findings[0].Type)
	assert.Contains(t, findings[0].Evidence, "Local workflow loading")
}

func TestUsesLocalInPushTrigger(t *testing.T) {
	workflow := `
on: push

jobs:
  build:
    uses: ./.github/workflows/build.yml
`
	findings, err := testWorkflow(t, workflow)
	require.NoError(t, err)
	// Should NOT flag - push is not a privileged trigger
	assert.Len(t, findings, 0)
}

func TestPwnRequestDiscussionTrigger(t *testing.T) {
	workflow := `
on:
  discussion:
    types: [created]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ steps.pr.outputs.head_sha }}
      - run: npm test
`

	findings, err := testWorkflow(t, workflow)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnPwnRequest, findings[0].Type)
	assert.Equal(t, detections.SeverityCritical, findings[0].Severity)
}

func TestUsesLocalWithDotGithubPrefix(t *testing.T) {
	workflow := `
on: pull_request_target

jobs:
  build:
    uses: .github/workflows/build.yml
`
	findings, err := testWorkflow(t, workflow)
	require.NoError(t, err)
	// Should NOT detect - .github without ./ is external reference
	assert.Len(t, findings, 0)
}

func TestUsesExternalWorkflow(t *testing.T) {
	workflow := `
on: pull_request_target

jobs:
  build:
    uses: external-org/workflows/.github/workflows/build.yml@abc123
`
	findings, err := testWorkflow(t, workflow)
	require.NoError(t, err)
	// Should NOT detect local workflow loading (external is different issue)
	for _, f := range findings {
		assert.NotContains(t, f.Evidence, "Local workflow loading")
	}
}

func TestUsesLocalMultipleJobs(t *testing.T) {
	workflow := `
on: pull_request_target

jobs:
  safe-job:
    runs-on: ubuntu-latest
    steps:
      - run: echo "safe"

  vulnerable-job:
    uses: ./workflows/build.yml

  another-safe-job:
    runs-on: ubuntu-latest
    steps:
      - run: echo "also safe"
`
	findings, err := testWorkflow(t, workflow)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "vulnerable-job", findings[0].Job)
}

func TestUsesLocalInDiscussionComment(t *testing.T) {
	workflow := `
on:
  discussion_comment:
    types: [created]

jobs:
  respond:
    uses: ./.github/workflows/respond.yml
`
	findings, err := testWorkflow(t, workflow)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnPwnRequest, findings[0].Type)
	assert.Contains(t, findings[0].Evidence, "Local workflow loading")
	assert.Contains(t, findings[0].Evidence, "discussion_comment")
}

func TestIntegrationLocalWorkflowLoading(t *testing.T) {
	workflowContent, err := os.ReadFile("testdata/local-workflow-loading.yml")
	require.NoError(t, err)

	findings, err := testWorkflow(t, string(workflowContent))
	require.NoError(t, err)

	// Should detect 2 vulnerable jobs
	require.Len(t, findings, 2)

	// Verify both are pwn_request type with local workflow loading evidence
	for _, f := range findings {
		assert.Equal(t, detections.VulnPwnRequest, f.Type)
		assert.Equal(t, detections.SeverityCritical, f.Severity)
		assert.Equal(t, detections.ConfidenceHigh, f.Confidence)
		assert.Equal(t, detections.ComplexityZeroClick, f.Complexity)
		assert.Contains(t, f.Evidence, "Local workflow loading")
	}

	// Verify job names
	jobNames := []string{findings[0].Job, findings[1].Job}
	assert.Contains(t, jobNames, "build")
	assert.Contains(t, jobNames, "test")
}
