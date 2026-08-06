package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseWorkflow_PullRequestTarget(t *testing.T) {
	yaml := `
name: PR Target
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`

	wf, err := ParseWorkflow([]byte(yaml))
	require.NoError(t, err)

	triggers := wf.GetTriggers()
	assert.Contains(t, triggers, "pull_request_target")

	step := wf.Jobs["test"].Steps[0]
	assert.Equal(t, "${{ github.event.pull_request.head.sha }}", step.With["ref"])
}

func TestParseWorkflow_MultiTrigger(t *testing.T) {
	yaml := `
name: Multi
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo test
`

	wf, err := ParseWorkflow([]byte(yaml))
	require.NoError(t, err)

	triggers := wf.GetTriggers()
	assert.Contains(t, triggers, "push")
	assert.Contains(t, triggers, "pull_request")
}

func TestJob_IsSelfHostedRunner(t *testing.T) {
	yaml := `
name: Runners
on: push
jobs:
  github:
    runs-on: ubuntu-latest
    steps:
      - run: echo github
  selfhosted:
    runs-on: self-hosted
    steps:
      - run: echo selfhosted
`

	wf, err := ParseWorkflow([]byte(yaml))
	require.NoError(t, err)

	assert.False(t, wf.Jobs["github"].IsSelfHostedRunner())
	assert.True(t, wf.Jobs["selfhosted"].IsSelfHostedRunner())
}

func TestJob_IsSelfHostedRunner_MatrixStrategy(t *testing.T) {
	yaml := `
name: Matrix
on: push
jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: ["ubuntu-latest", "windows-latest", "macos-latest"]
    steps:
      - run: echo test
`
	wf, err := ParseWorkflow([]byte(yaml))
	require.NoError(t, err)
	assert.False(t, wf.Jobs["test"].IsSelfHostedRunner(), "all GitHub-hosted matrix values should not be self-hosted")

	yaml2 := `
name: Matrix Self-Hosted
on: push
jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: ["ubuntu-latest", "self-hosted"]
    steps:
      - run: echo test
`
	wf2, err := ParseWorkflow([]byte(yaml2))
	require.NoError(t, err)
	assert.True(t, wf2.Jobs["test"].IsSelfHostedRunner(), "matrix with self-hosted value should be flagged")

	yaml3 := `
name: Matrix Custom
on: push
jobs:
  test:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["my-custom-runner"]
    steps:
      - run: echo test
`
	wf3, err := ParseWorkflow([]byte(yaml3))
	require.NoError(t, err)
	assert.True(t, wf3.Jobs["test"].IsSelfHostedRunner(), "matrix with custom runner should be flagged")

	yaml4 := `
name: Input Runner
on:
  workflow_call:
    inputs:
      runner:
        type: string
jobs:
  test:
    runs-on: ${{ inputs.runner }}
    steps:
      - run: echo test
`
	wf4, err := ParseWorkflow([]byte(yaml4))
	require.NoError(t, err)
	assert.True(t, wf4.Jobs["test"].IsSelfHostedRunner(), "unresolvable expression should be flagged conservatively")
}

func TestJob_IsSelfHostedRunner_ReusableWorkflowCaller(t *testing.T) {
	yaml1 := `
name: CI
on: push
jobs:
  call-build:
    uses: org/shared-workflows/.github/workflows/build.yml@main
`
	wf1, err := ParseWorkflow([]byte(yaml1))
	require.NoError(t, err)
	assert.False(t, wf1.Jobs["call-build"].IsSelfHostedRunner(), "reusable workflow caller should not be flagged as self-hosted")
}

func TestJob_IsSelfHostedRunner_LocalReusableWorkflowCaller(t *testing.T) {
	yaml1 := `
name: CI
on: push
jobs:
  call-local:
    uses: ./.github/workflows/reusable-build.yml
`
	wf1, err := ParseWorkflow([]byte(yaml1))
	require.NoError(t, err)
	assert.False(t, wf1.Jobs["call-local"].IsSelfHostedRunner(), "local reusable workflow caller should not be flagged as self-hosted")
}
