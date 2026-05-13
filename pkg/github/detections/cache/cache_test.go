package cache

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestCachePoisoningPlugin_DetectsWorkflowRunWithCacheAndExecution(t *testing.T) {
	yaml := `
name: Workflow Run Cache
on: workflow_run
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: node_modules
          key: npm-${{ hashFiles('package-lock.json') }}
      - run: npm run build
`
	g, err := analysis.BuildGraph("owner/repo", "cache.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnCachePoisoning, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	assert.Equal(t, "workflow_run", findings[0].Trigger)
}

func TestCachePoisoningPlugin_DetectsPullRequestTargetWithCacheAndExecution(t *testing.T) {
	yaml := `
name: Pull Request Target Cache
on: pull_request_target
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v3
        with:
          path: dist
          key: build-cache
      - run: ./deploy.sh
`
	g, err := analysis.BuildGraph("owner/repo", "pr-target-cache.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnCachePoisoning, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	assert.Equal(t, "pull_request_target", findings[0].Trigger)
}

func TestCachePoisoningPlugin_SafePullRequestWithCacheAndExecution(t *testing.T) {
	yaml := `
name: Pull Request Cache (Safe)
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: node_modules
          key: npm-cache
      - run: npm run build
`
	g, err := analysis.BuildGraph("owner/repo", "pr-safe.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "pull_request (not target) should be safe")
}

func TestCachePoisoningPlugin_DetectsPullRequestTargetWithCacheAndPnpmInstall(t *testing.T) {
	// Regression for the empirical harness S3 scenario: pull_request_target +
	// actions/cache + pnpm install (no checkout). Before PR 1 added pnpm to
	// IsExecutionSink this fired silently — a TanStack-class blind spot.
	yaml := `
name: Pull Request Target Cache + Pnpm
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.pnpm-store
          key: pnpm-store-${{ hashFiles('pnpm-lock.yaml') }}
      - run: pnpm install
`
	g, err := analysis.BuildGraph("owner/repo", "pr-target-pnpm.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnCachePoisoning, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	assert.Equal(t, "pull_request_target", findings[0].Trigger)
}

func TestCachePoisoningPlugin_SafeCacheWithoutExecution(t *testing.T) {
	yaml := `
name: Workflow Run Cache Without Execution
on: workflow_run
jobs:
  cache:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: build
          key: build-artifacts
`
	g, err := analysis.BuildGraph("owner/repo", "cache-no-exec.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "cache without subsequent execution should be safe")
}
