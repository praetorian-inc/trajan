// pkg/analysis/parser/workflow_test.go
package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseWorkflow_Basic(t *testing.T) {
	yaml := `
name: Build
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "Hello"
`

	wf, err := ParseWorkflow([]byte(yaml))
	require.NoError(t, err)

	assert.Equal(t, "Build", wf.Name)
	assert.Contains(t, wf.GetTriggers(), "push")
	assert.Len(t, wf.Jobs, 1)
	assert.Contains(t, wf.Jobs, "build")

	job := wf.Jobs["build"]
	assert.Equal(t, "ubuntu-latest", job.GetRunsOn())
	assert.Len(t, job.Steps, 2)
	assert.Equal(t, "actions/checkout@v4", job.Steps[0].Uses)
	assert.Equal(t, `echo "Hello"`, job.Steps[1].Run)
}

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

func TestJob_GetNeeds(t *testing.T) {
	yaml := `
name: Pipeline
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
  test:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - run: echo test
  deploy:
    runs-on: ubuntu-latest
    needs: [build, test]
    steps:
      - run: echo deploy
`

	wf, err := ParseWorkflow([]byte(yaml))
	require.NoError(t, err)

	assert.Empty(t, wf.Jobs["build"].GetNeeds())
	assert.Equal(t, []string{"build"}, wf.Jobs["test"].GetNeeds())
	assert.ElementsMatch(t, []string{"build", "test"}, wf.Jobs["deploy"].GetNeeds())
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
	// Matrix with all GitHub-hosted runners — should NOT be flagged
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

	// Matrix with self-hosted runner — should be flagged
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

	// Matrix with custom runner label — should be flagged
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

	// Expression without matrix (e.g. inputs) — should be flagged (conservative)
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
	// Cross-repo reusable workflow caller — has uses but no runs-on
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
	// Local reusable workflow caller — has uses with ./ prefix
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
