package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitHubParser_CapturesLineNumbers(t *testing.T) {
	content := []byte(`name: Test Workflow
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Build
        run: echo "building"
`)

	parser := NewGitHubParser()
	normalized, err := parser.Parse(content)
	require.NoError(t, err)
	require.NotNil(t, normalized)

	buildJob, ok := normalized.Jobs["build"]
	require.True(t, ok, "should have 'build' job")
	assert.Greater(t, buildJob.Line, 0, "job should have line number > 0")
	assert.Equal(t, 4, buildJob.Line, "build job should be on line 4")

	require.Len(t, buildJob.Steps, 2, "should have 2 steps")

	checkoutStep := buildJob.Steps[0]
	assert.Greater(t, checkoutStep.Line, 0, "step should have line number > 0")
	assert.Equal(t, 7, checkoutStep.Line, "checkout step should be on line 7")

	buildStep := buildJob.Steps[1]
	assert.Greater(t, buildStep.Line, 0, "step should have line number > 0")
	assert.Equal(t, 9, buildStep.Line, "build step should be on line 9")
}
