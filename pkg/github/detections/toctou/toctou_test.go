package toctou

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestTOCTOUPlugin_DetectsMutableRefCheckout(t *testing.T) {
	yaml := `
name: Dispatch TOCTOU
on: workflow_dispatch
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ inputs.pr }}/head
      - run: ./deploy.sh
`
	g, err := analysis.BuildGraph("owner/repo", "toctou.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnTOCTOU, findings[0].Type)
	assert.Equal(t, detections.SeverityMedium, findings[0].Severity)
	assert.Contains(t, findings[0].Evidence, "refs/pull/")
}

func TestTOCTOUPlugin_DetectsBranchInput(t *testing.T) {
	yaml := `
name: Dispatch TOCTOU Branch
on: workflow_dispatch
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ inputs.branch }}
      - run: npm install && npm run build
`
	g, err := analysis.BuildGraph("owner/repo", "branch.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnTOCTOU, findings[0].Type)
	assert.Equal(t, detections.SeverityMedium, findings[0].Severity)
	assert.Contains(t, findings[0].Evidence, "inputs.branch")
}

func TestTOCTOUPlugin_SafeWithSHAInput(t *testing.T) {
	yaml := `
name: Dispatch Safe SHA
on: workflow_dispatch
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ inputs.sha }}
      - run: ./deploy.sh
`
	g, err := analysis.BuildGraph("owner/repo", "safe-sha.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0)
}

func TestTOCTOUPlugin_SafeWithGitHubSHA(t *testing.T) {
	yaml := `
name: Dispatch Safe GitHub SHA
on: workflow_dispatch
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.sha }}
      - run: npm test
`
	g, err := analysis.BuildGraph("owner/repo", "safe-github-sha.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0)
}
