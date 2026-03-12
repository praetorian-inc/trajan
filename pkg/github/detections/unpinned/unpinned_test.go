package unpinned

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestUnpinnedActionsDetection_DetectsVersionTag(t *testing.T) {
	yaml := `
name: Test Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	g, err := analysis.BuildGraph("owner/repo", "test.yml", []byte(yaml))
	require.NoError(t, err)

	detection := New()
	findings, err := detection.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnUnpinnedAction, findings[0].Type)
	assert.Equal(t, detections.SeverityLow, findings[0].Severity)
	assert.Equal(t, detections.ConfidenceHigh, findings[0].Confidence)
	assert.Equal(t, detections.ComplexityZeroClick, findings[0].Complexity)
	assert.Equal(t, "actions/checkout@v4", findings[0].Evidence)
	assert.Contains(t, findings[0].Remediation, "Pin dependency to full commit SHA")
}

func TestUnpinnedActionsDetection_DetectsBranchRef(t *testing.T) {
	yaml := `
name: Test Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: third-party/action@main
`
	g, err := analysis.BuildGraph("owner/repo", "test.yml", []byte(yaml))
	require.NoError(t, err)

	detection := New()
	findings, err := detection.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnUnpinnedAction, findings[0].Type)
	assert.Equal(t, "third-party/action@main", findings[0].Evidence)
}

func TestUnpinnedActionsDetection_SafeSHAPinned(t *testing.T) {
	yaml := `
name: Test Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
`
	g, err := analysis.BuildGraph("owner/repo", "test.yml", []byte(yaml))
	require.NoError(t, err)

	detection := New()
	findings, err := detection.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "40-character SHA should be safe")
}

func TestUnpinnedActionsDetection_SafeLocalAction(t *testing.T) {
	yaml := `
name: Test Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: ./local-action
`
	g, err := analysis.BuildGraph("owner/repo", "test.yml", []byte(yaml))
	require.NoError(t, err)

	detection := New()
	findings, err := detection.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "local actions should be safe")
}

func TestUnpinnedActionsDetection_SafeDockerImage(t *testing.T) {
	yaml := `
name: Test Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine:3.18
`
	g, err := analysis.BuildGraph("owner/repo", "test.yml", []byte(yaml))
	require.NoError(t, err)

	detection := New()
	findings, err := detection.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "docker images should be safe")
}
