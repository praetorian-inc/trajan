package permissions

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestExcessivePermissions_CriticalPullRequestTarget(t *testing.T) {
	yaml := `
name: PR Target with Write
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - run: npm install
`
	g, err := analysis.BuildGraph("owner/repo", "pr.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnExcessivePermissions, findings[0].Type)
	assert.Equal(t, detections.SeverityCritical, findings[0].Severity)
	assert.Equal(t, "pull_request_target", findings[0].Trigger)
	assert.Contains(t, findings[0].Evidence, "dangerous write permissions: contents")
}

func TestExcessivePermissions_SafePullRequest(t *testing.T) {
	yaml := `
name: Safe PR
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - run: npm install
`
	g, err := analysis.BuildGraph("owner/repo", "safe.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	// pull_request with contents:write is safe
	assert.Len(t, findings, 0)
}

func TestExcessivePermissions_HighIssueCommentContents(t *testing.T) {
	yaml := `
name: Issue Comment with Write
on: issue_comment
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - run: npm install
`
	g, err := analysis.BuildGraph("owner/repo", "issue.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnExcessivePermissions, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	assert.Equal(t, "issue_comment", findings[0].Trigger)
	assert.Contains(t, findings[0].Evidence, "dangerous write permissions: contents")
}

func TestExcessivePermissions_HighIssueCommentPullRequests(t *testing.T) {
	yaml := `
name: Issue Comment with PR Write
on: issue_comment
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - run: npm install
`
	g, err := analysis.BuildGraph("owner/repo", "issue-pr.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnExcessivePermissions, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	assert.Equal(t, "issue_comment", findings[0].Trigger)
	assert.Contains(t, findings[0].Evidence, "dangerous write permissions: pull-requests")
}

func TestExcessivePermissions_HighPullRequestTargetActions(t *testing.T) {
	yaml := `
name: PR Target with Actions Write
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      actions: write
    steps:
      - uses: actions/checkout@v4
      - run: npm test
`
	g, err := analysis.BuildGraph("owner/repo", "prt-actions.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnExcessivePermissions, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	assert.Equal(t, "pull_request_target", findings[0].Trigger)
	assert.Contains(t, findings[0].Evidence, "dangerous write permissions: actions")
}

func TestExcessivePermissions_SafePushWrite(t *testing.T) {
	yaml := `
name: Safe Push
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - run: npm install
`
	g, err := analysis.BuildGraph("owner/repo", "push.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	// push with write permissions is generally safe (on protected branches)
	assert.Len(t, findings, 0)
}

func TestExcessivePermissions_SafeReadPermissions(t *testing.T) {
	yaml := `
name: PR Target with Read
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
    steps:
      - uses: actions/checkout@v4
      - run: npm test
`
	g, err := analysis.BuildGraph("owner/repo", "safe-read.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	// Read-only permissions are safe
	assert.Len(t, findings, 0)
}

// NEW TESTS: Missing permissions block detection

func TestExcessivePermissions_HighMissingPermissionsPullRequestTarget(t *testing.T) {
	yaml := `
name: PR Target without Permissions
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install
`
	g, err := analysis.BuildGraph("owner/repo", "pr-no-perms.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	// Should detect missing permissions block on risky trigger
	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnExcessivePermissions, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	assert.Equal(t, "pull_request_target", findings[0].Trigger)
	assert.Contains(t, findings[0].Evidence, "missing permissions block")
}

func TestExcessivePermissions_HighMissingPermissionsIssueComment(t *testing.T) {
	yaml := `
name: Issue Comment without Permissions
on: issue_comment
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./deploy.sh
`
	g, err := analysis.BuildGraph("owner/repo", "issue-no-perms.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	// Should detect missing permissions block on risky trigger
	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnExcessivePermissions, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	assert.Equal(t, "issue_comment", findings[0].Trigger)
	assert.Contains(t, findings[0].Evidence, "missing permissions block")
}

func TestExcessivePermissions_MediumMissingPermissionsWorkflowRun(t *testing.T) {
	yaml := `
name: Workflow Run without Permissions
on: workflow_run
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
`
	g, err := analysis.BuildGraph("owner/repo", "wf-run-no-perms.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	// Should detect missing permissions block on workflow_run trigger
	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnExcessivePermissions, findings[0].Type)
	assert.Equal(t, detections.SeverityMedium, findings[0].Severity)
	assert.Equal(t, "workflow_run", findings[0].Trigger)
	assert.Contains(t, findings[0].Evidence, "missing permissions block")
}

func TestExcessivePermissions_SafeEmptyPermissionsBlock(t *testing.T) {
	yaml := `
name: PR Target with Empty Permissions
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - uses: actions/checkout@v4
      - run: npm test
`
	g, err := analysis.BuildGraph("owner/repo", "pr-empty-perms.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	// Explicit empty permissions block is safe (read-only)
	assert.Len(t, findings, 0)
}

func TestExcessivePermissions_SafePushNoPermissions(t *testing.T) {
	yaml := `
name: Push without Permissions
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install
`
	g, err := analysis.BuildGraph("owner/repo", "push-no-perms.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	// push without permissions block is safe (trusted trigger)
	assert.Len(t, findings, 0)
}

// id-token: write OIDC tests. Per the TanStack / Mini Shai-Hulud post-mortem,
// OIDC token theft via id-token: write on pull_request_target was the actual
// escalation vector — attacker code in the PR minted a valid npm publish token
// via OIDC federation. PR 3 surfaces this explicitly rather than letting it
// blend into generic "dangerous write permissions" findings.

func TestExcessivePermissions_CriticalIdTokenOnPullRequestTarget(t *testing.T) {
	yaml := `
name: PR Target with OIDC
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - run: npm publish
`
	g, err := analysis.BuildGraph("owner/repo", "prt-oidc.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnExcessivePermissions, findings[0].Type)
	assert.Equal(t, detections.SeverityCritical, findings[0].Severity)
	assert.Equal(t, "pull_request_target", findings[0].Trigger)
	assert.Contains(t, findings[0].Evidence, "id-token")
	assert.Contains(t, findings[0].Evidence, "OIDC")
}

func TestExcessivePermissions_HighIdTokenOnWorkflowRun(t *testing.T) {
	yaml := `
name: Workflow Run with OIDC
on: workflow_run
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - run: npm publish
`
	g, err := analysis.BuildGraph("owner/repo", "wfr-oidc.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnExcessivePermissions, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	assert.Equal(t, "workflow_run", findings[0].Trigger)
	assert.Contains(t, findings[0].Evidence, "id-token")
	assert.Contains(t, findings[0].Evidence, "OIDC")
}

func TestExcessivePermissions_HighIdTokenOnIssueComment(t *testing.T) {
	yaml := `
name: Issue Comment with OIDC
on: issue_comment
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - run: npm publish
`
	g, err := analysis.BuildGraph("owner/repo", "ic-oidc.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnExcessivePermissions, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	assert.Equal(t, "issue_comment", findings[0].Trigger)
	assert.Contains(t, findings[0].Evidence, "id-token")
	assert.Contains(t, findings[0].Evidence, "OIDC")
}

func TestExcessivePermissions_Properties(t *testing.T) {
	p := New()
	assert.Equal(t, "excessive-permissions", p.Name())
	assert.Equal(t, "github", p.Platform())
	assert.Equal(t, detections.SeverityHigh, p.Severity())
}
