package runner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/github"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// mockContentsServer creates a test HTTP server that serves workflow files
// via the GitHub Contents API format. files maps "owner/repo/path" to content.
func mockContentsServer(t *testing.T, files map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Path format: /repos/owner/repo/contents/path?ref=ref
		// We match on the path portion after /repos/
		path := r.URL.Path
		for key, content := range files {
			if path == "/repos/"+key {
				encoded := base64.StdEncoding.EncodeToString([]byte(content))
				resp := map[string]string{
					"content":  encoded,
					"encoding": "base64",
				}
				w.Header().Set("X-RateLimit-Remaining", "4999")
				w.Header().Set("X-RateLimit-Limit", "5000")
				json.NewEncoder(w).Encode(resp)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"Not Found"}`))
	}))
}

func TestRunnerPlugin_DetectsSelfHosted(t *testing.T) {
	yaml := `
name: Build
on: push
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo "Running on self-hosted"
`
	g, err := analysis.BuildGraph("owner/repo", "build.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnSelfHostedRunner, findings[0].Type)
	assert.Contains(t, findings[0].Evidence, "self-hosted")
}

func TestRunnerPlugin_GitHubHostedIsSafe(t *testing.T) {
	yaml := `
name: Build
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "GitHub hosted"
`
	g, err := analysis.BuildGraph("owner/repo", "safe.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0)
}

func TestRunnerPlugin_Properties(t *testing.T) {
	p := New()
	assert.Equal(t, "self-hosted-runner", p.Name())
	assert.Equal(t, "github", p.Platform())
	assert.Equal(t, detections.SeverityHigh, p.Severity())
}

func TestRunnerPlugin_ReusableWorkflowCallerNoFalsePositive(t *testing.T) {
	// A caller job with uses: and no runs-on should NOT produce a finding
	// when there is no metadata to resolve the callee (fail-open = no finding).
	yaml := `
name: CI
on: push
jobs:
  call-build:
    uses: org/shared/.github/workflows/build.yml@main
`
	g, err := analysis.BuildGraph("owner/repo", ".github/workflows/ci.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "reusable workflow caller with no metadata should produce 0 findings")
}

func TestRunnerPlugin_ReusableWorkflowCallerResolvesToSelfHosted(t *testing.T) {
	// Callee has runs-on: self-hosted → should produce a finding
	callerYAML := `
name: CI
on: push
jobs:
  call-build:
    uses: org/shared/.github/workflows/build.yml@main
`
	calleeYAML := `
name: Build
on: workflow_call
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo "build"
`
	server := mockContentsServer(t, map[string]string{
		"org/shared/contents/.github/workflows/build.yml": calleeYAML,
	})
	defer server.Close()

	g, err := analysis.BuildGraph("owner/repo", ".github/workflows/ci.yml", []byte(callerYAML))
	require.NoError(t, err)
	g.SetMetadata("github_client", github.NewClient(server.URL, "test-token"))

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1, "callee with self-hosted runner should produce a finding")
	assert.Equal(t, detections.VulnSelfHostedRunner, findings[0].Type)
}

func TestRunnerPlugin_ReusableWorkflowCallerResolvesToGitHubHosted(t *testing.T) {
	// Callee has runs-on: ubuntu-latest → should NOT produce a finding
	callerYAML := `
name: CI
on: push
jobs:
  call-build:
    uses: org/shared/.github/workflows/build.yml@main
`
	calleeYAML := `
name: Build
on: workflow_call
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "build"
`
	server := mockContentsServer(t, map[string]string{
		"org/shared/contents/.github/workflows/build.yml": calleeYAML,
	})
	defer server.Close()

	g, err := analysis.BuildGraph("owner/repo", ".github/workflows/ci.yml", []byte(callerYAML))
	require.NoError(t, err)
	g.SetMetadata("github_client", github.NewClient(server.URL, "test-token"))

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "callee with GitHub-hosted runner should produce 0 findings")
}

func TestRunnerPlugin_LocalReusableWorkflowResolution(t *testing.T) {
	// Local reusable workflow caller (./) resolved via all_workflows
	callerYAML := `
name: CI
on: push
jobs:
  call-local:
    uses: ./.github/workflows/reusable-build.yml
`
	calleeYAML := `
name: Reusable Build
on: workflow_call
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo "build"
`
	g, err := analysis.BuildGraph("owner/repo", ".github/workflows/ci.yml", []byte(callerYAML))
	require.NoError(t, err)

	allWorkflows := map[string][]platforms.Workflow{
		"owner/repo": {
			{
				Name:     "reusable-build.yml",
				Path:     ".github/workflows/reusable-build.yml",
				Content:  []byte(calleeYAML),
				RepoSlug: "owner/repo",
			},
		},
	}
	g.SetMetadata("all_workflows", allWorkflows)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1, "local callee with self-hosted runner should produce a finding")
	assert.Equal(t, detections.VulnSelfHostedRunner, findings[0].Type)
}

func TestRunnerPlugin_NestedReusableWorkflow_TwoLevels(t *testing.T) {
	// A calls B (cross-repo), B calls C (local to B's repo), C has self-hosted.
	// Tests recursive resolution AND correct slug threading.
	callerYAML := `
name: CI
on: push
jobs:
  call-b:
    uses: org/middle/.github/workflows/b.yml@main
`
	// B is in org/middle and calls C locally
	middleYAML := `
name: Middle
on: workflow_call
jobs:
  call-c:
    uses: ./.github/workflows/c.yml
`
	// C is in org/middle (same repo as B) and uses self-hosted
	leafYAML := `
name: Leaf
on: workflow_call
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo "self-hosted leaf"
`
	// B is fetched via API (cross-repo), C is resolved locally in org/middle
	server := mockContentsServer(t, map[string]string{
		"org/middle/contents/.github/workflows/b.yml": middleYAML,
	})
	defer server.Close()

	g, err := analysis.BuildGraph("owner/repo", ".github/workflows/ci.yml", []byte(callerYAML))
	require.NoError(t, err)

	// C is in org/middle's all_workflows (local ./ ref resolves from here)
	allWorkflows := map[string][]platforms.Workflow{
		"org/middle": {
			{Name: "c.yml", Path: ".github/workflows/c.yml", Content: []byte(leafYAML), RepoSlug: "org/middle"},
		},
	}
	g.SetMetadata("all_workflows", allWorkflows)
	g.SetMetadata("github_client", github.NewClient(server.URL, "test-token"))

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1, "nested callee (2 levels) with self-hosted runner should produce a finding")
	assert.Equal(t, detections.VulnSelfHostedRunner, findings[0].Type)
}

func TestRunnerPlugin_NestedReusableWorkflow_ThreeLevels(t *testing.T) {
	// A → B → C → D, where D has self-hosted. Three levels of indirection.
	callerYAML := `
name: CI
on: push
jobs:
  call-b:
    uses: org/b/.github/workflows/b.yml@main
`
	bYAML := `
name: B
on: workflow_call
jobs:
  call-c:
    uses: org/c/.github/workflows/c.yml@main
`
	cYAML := `
name: C
on: workflow_call
jobs:
  call-d:
    uses: ./.github/workflows/d.yml
`
	dYAML := `
name: D
on: workflow_call
jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - run: echo "deep self-hosted"
`
	// B and C are fetched via API (cross-repo), D is local to org/c
	server := mockContentsServer(t, map[string]string{
		"org/b/contents/.github/workflows/b.yml": bYAML,
		"org/c/contents/.github/workflows/c.yml": cYAML,
	})
	defer server.Close()

	g, err := analysis.BuildGraph("owner/repo", ".github/workflows/ci.yml", []byte(callerYAML))
	require.NoError(t, err)

	// D is local to org/c
	allWorkflows := map[string][]platforms.Workflow{
		"org/c": {
			{Name: "d.yml", Path: ".github/workflows/d.yml", Content: []byte(dYAML), RepoSlug: "org/c"},
		},
	}
	g.SetMetadata("all_workflows", allWorkflows)
	g.SetMetadata("github_client", github.NewClient(server.URL, "test-token"))

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1, "nested callee (3 levels) with self-hosted runner should produce a finding")
	assert.Equal(t, detections.VulnSelfHostedRunner, findings[0].Type)
}

func TestRunnerPlugin_NestedReusableWorkflow_DepthLimitFailsOpen(t *testing.T) {
	// Build a chain deeper than maxReusableWorkflowDepth (4).
	// Each level calls the next. Should fail open (0 findings), not panic.
	callerYAML := `
name: CI
on: push
jobs:
  call-l1:
    uses: org/r/.github/workflows/l1.yml@main
`
	makeLevel := func(next string) string {
		return fmt.Sprintf(`
name: Level
on: workflow_call
jobs:
  next:
    uses: %s
`, next)
	}

	leafYAML := `
name: Deep Leaf
on: workflow_call
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo "too deep"
`

	server := mockContentsServer(t, map[string]string{
		"org/r/contents/.github/workflows/l1.yml": makeLevel("org/r/.github/workflows/l2.yml@main"),
		"org/r/contents/.github/workflows/l2.yml": makeLevel("org/r/.github/workflows/l3.yml@main"),
		"org/r/contents/.github/workflows/l3.yml": makeLevel("org/r/.github/workflows/l4.yml@main"),
		"org/r/contents/.github/workflows/l4.yml": makeLevel("org/r/.github/workflows/l5.yml@main"),
		"org/r/contents/.github/workflows/l5.yml": leafYAML,
	})
	defer server.Close()

	g, err := analysis.BuildGraph("owner/repo", ".github/workflows/ci.yml", []byte(callerYAML))
	require.NoError(t, err)
	g.SetMetadata("github_client", github.NewClient(server.URL, "test-token"))

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "chain exceeding max depth should fail open with 0 findings")
}

func TestRunnerPlugin_NestedReusableWorkflow_WrongSlugNoFalsePositive(t *testing.T) {
	// A calls B in org/middle. B calls ./.github/workflows/c.yml (local to org/middle).
	// c.yml only exists in owner/repo, NOT in org/middle.
	// Should NOT resolve — the local ref must use B's repo slug, not A's.
	callerYAML := `
name: CI
on: push
jobs:
  call-b:
    uses: org/middle/.github/workflows/b.yml@main
`
	middleYAML := `
name: Middle
on: workflow_call
jobs:
  call-c:
    uses: ./.github/workflows/c.yml
`
	selfHostedYAML := `
name: SelfHosted
on: workflow_call
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo "self-hosted"
`
	// B is fetched via API
	server := mockContentsServer(t, map[string]string{
		"org/middle/contents/.github/workflows/b.yml": middleYAML,
	})
	defer server.Close()

	g, err := analysis.BuildGraph("owner/repo", ".github/workflows/ci.yml", []byte(callerYAML))
	require.NoError(t, err)

	allWorkflows := map[string][]platforms.Workflow{
		// c.yml is NOT in org/middle — it's missing
		"owner/repo": {
			// c.yml exists here but should NOT be used for B's local ./ reference
			{Name: "c.yml", Path: ".github/workflows/c.yml", Content: []byte(selfHostedYAML), RepoSlug: "owner/repo"},
		},
	}
	g.SetMetadata("all_workflows", allWorkflows)
	g.SetMetadata("github_client", github.NewClient(server.URL, "test-token"))

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "local ref in B should resolve against org/middle, not owner/repo")
}

func TestRunnerPlugin_CacheKeyIsolation_LocalRefs(t *testing.T) {
	// Two repos both call ./.github/workflows/build.yml locally.
	// Repo A's build.yml is self-hosted, Repo B's is GitHub-hosted.
	// The cache must not cross-contaminate.
	repoAYAML := `
name: CI-A
on: push
jobs:
  build:
    uses: ./.github/workflows/build.yml
`
	repoBYAML := `
name: CI-B
on: push
jobs:
  build:
    uses: ./.github/workflows/build.yml
`
	buildSelfHosted := `
name: Build
on: workflow_call
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo "self-hosted"
`
	buildGitHubHosted := `
name: Build
on: workflow_call
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "github-hosted"
`
	// Build two separate graphs and merge findings via the resolver directly
	allWorkflows := map[string][]platforms.Workflow{
		"org/repo-a": {
			{Name: "build.yml", Path: ".github/workflows/build.yml", Content: []byte(buildSelfHosted), RepoSlug: "org/repo-a"},
		},
		"org/repo-b": {
			{Name: "build.yml", Path: ".github/workflows/build.yml", Content: []byte(buildGitHubHosted), RepoSlug: "org/repo-b"},
		},
	}

	resolver := newResolver(nil, allWorkflows)
	ctx := context.Background()

	// Resolve for repo A — should be self-hosted
	isSH_A, _, err := resolver.resolveCallee(ctx, "org/repo-a", "./.github/workflows/build.yml", 0)
	require.NoError(t, err)
	assert.True(t, isSH_A, "repo A's build.yml should be self-hosted")

	// Resolve for repo B — should NOT be self-hosted (must not reuse A's cache)
	isSH_B, _, err := resolver.resolveCallee(ctx, "org/repo-b", "./.github/workflows/build.yml", 0)
	require.NoError(t, err)
	assert.False(t, isSH_B, "repo B's build.yml should be GitHub-hosted, not cached from repo A")

	// Verify both graphs produce correct findings
	gA, err := analysis.BuildGraph("org/repo-a", ".github/workflows/ci.yml", []byte(repoAYAML))
	require.NoError(t, err)
	gA.SetMetadata("all_workflows", allWorkflows)

	plugin := New()
	findingsA, err := plugin.Detect(ctx, gA)
	require.NoError(t, err)
	assert.Len(t, findingsA, 1, "repo A should have 1 self-hosted finding")

	gB, err := analysis.BuildGraph("org/repo-b", ".github/workflows/ci.yml", []byte(repoBYAML))
	require.NoError(t, err)
	gB.SetMetadata("all_workflows", allWorkflows)

	findingsB, err := plugin.Detect(ctx, gB)
	require.NoError(t, err)
	assert.Len(t, findingsB, 0, "repo B should have 0 findings")
}
