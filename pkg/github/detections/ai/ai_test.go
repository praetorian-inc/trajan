package ai

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

// findingsByType filters findings to only those matching the given vulnerability type.
func findingsByType(findings []detections.Finding, t detections.VulnerabilityType) []detections.Finding {
	var result []detections.Finding
	for _, f := range findings {
		if f.Type == t {
			result = append(result, f)
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

func TestAIRisk_Properties(t *testing.T) {
	p := New()
	assert.Equal(t, "ai-risk", p.Name())
	assert.Equal(t, "github", p.Platform())
	assert.Equal(t, detections.SeverityMedium, p.Severity())
}

// ---------------------------------------------------------------------------
// Check 1: Token Exfiltration
// ---------------------------------------------------------------------------

// Test 1: AI action + GITHUB_TOKEN + untrusted input on issue_comment -> MEDIUM
func TestTokenExfiltration_AIActionWithGitHubToken(t *testing.T) {
	yaml := `
name: AI Token Exfiltration Test
on:
  issue_comment:
    types: [created]
jobs:
  ai-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: coderabbit-ai/pr-review@v1
        with:
          prompt: ${{ github.event.comment.body }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
`
	g, err := analysis.BuildGraph("owner/repo", "ai-token.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	tokenFindings := findingsByType(findings, detections.VulnAITokenExfiltration)
	require.Len(t, tokenFindings, 1)
	assert.Equal(t, detections.SeverityMedium, tokenFindings[0].Severity)
	assert.Equal(t, detections.ConfidenceHigh, tokenFindings[0].Confidence)
}

// Test 2: AI action + custom secret + untrusted input -> MEDIUM
func TestTokenExfiltration_AIActionWithCustomSecret(t *testing.T) {
	yaml := `
name: AI with Secret
on:
  issue_comment:
    types: [created]
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: claude-ai/code-review@v1
        with:
          analysis: ${{ github.event.comment.body }}
        env:
          AWS_KEY: ${{ secrets.AWS_KEY }}
`
	g, err := analysis.BuildGraph("owner/repo", "ai-secret.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	tokenFindings := findingsByType(findings, detections.VulnAITokenExfiltration)
	require.Len(t, tokenFindings, 1)
	assert.Equal(t, detections.SeverityMedium, tokenFindings[0].Severity)
}

// Test 3: AI action + no secrets -> no token exfiltration finding
func TestTokenExfiltration_AIActionNoSecrets(t *testing.T) {
	yaml := `
name: AI Without Secrets
on:
  issue_comment:
    types: [created]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: coderabbit-ai/review@v1
        with:
          input: ${{ github.event.comment.body }}
        env:
          LOG_LEVEL: debug
`
	g, err := analysis.BuildGraph("owner/repo", "ai-no-secrets.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	tokenFindings := findingsByType(findings, detections.VulnAITokenExfiltration)
	assert.Len(t, tokenFindings, 0)
}

// Test 4: AI action + secrets but no untrusted trigger (push) -> no token exfiltration
func TestTokenExfiltration_AIActionSecretsSafeTrigger(t *testing.T) {
	yaml := `
name: AI With Secrets But Safe
on: push
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: claude/analyzer@v1
        with:
          target: main
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
`
	g, err := analysis.BuildGraph("owner/repo", "ai-safe.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	tokenFindings := findingsByType(findings, detections.VulnAITokenExfiltration)
	assert.Len(t, tokenFindings, 0)
}

// ---------------------------------------------------------------------------
// Check 2: Code Injection
// ---------------------------------------------------------------------------

// Test 5: AI + contents:write + untrusted input -> MEDIUM
func TestCodeInjection_ContentsWriteWithUntrustedInput(t *testing.T) {
	yaml := `
name: AI Code Review
on: issues
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - name: Review with AI
        uses: actions/coderabbit@v1
        with:
          prompt: "Review code: ${{ github.event.issue.body }}"
`
	g, err := analysis.BuildGraph("owner/repo", "ai-review.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	codeFindings := findingsByType(findings, detections.VulnAICodeInjection)
	require.Len(t, codeFindings, 1)
	assert.Equal(t, detections.SeverityMedium, codeFindings[0].Severity)
}

// Test 6: AI + pull-requests:write + untrusted input -> MEDIUM
func TestCodeInjection_PullRequestsWriteWithUntrustedInput(t *testing.T) {
	yaml := `
name: AI Review
on: issue_comment
jobs:
  ai_review:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - name: Copilot review
        uses: copilot@v1
        with:
          input: "${{ github.event.comment.body }}"
`
	g, err := analysis.BuildGraph("owner/repo", "copilot-review.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	codeFindings := findingsByType(findings, detections.VulnAICodeInjection)
	require.Len(t, codeFindings, 1)
	assert.Equal(t, detections.SeverityMedium, codeFindings[0].Severity)
}

// Test 7: AI + contents:read -> no code injection
func TestCodeInjection_ReadOnlyPermissions(t *testing.T) {
	yaml := `
name: AI Analysis
on: push
jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Analyze with Claude
        uses: claude-ai/action@v1
        with:
          prompt: "Analyze the code"
`
	g, err := analysis.BuildGraph("owner/repo", "safe-ai.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	codeFindings := findingsByType(findings, detections.VulnAICodeInjection)
	assert.Len(t, codeFindings, 0)
}

// Test 8: Missing permissions block -> MEDIUM (nil = write defaults)
func TestCodeInjection_MissingPermissionsBlock(t *testing.T) {
	yaml := `
name: AI Handler
on: issues
jobs:
  handle:
    runs-on: ubuntu-latest
    steps:
      - name: Handle issue
        uses: qodo@v1
        with:
          input: "${{ github.event.issue.body }}"
`
	g, err := analysis.BuildGraph("owner/repo", "no-perms.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	codeFindings := findingsByType(findings, detections.VulnAICodeInjection)
	require.Len(t, codeFindings, 1)
	assert.Equal(t, detections.SeverityMedium, codeFindings[0].Severity)
}

// ---------------------------------------------------------------------------
// Check 3: Supply Chain Poisoning
// ---------------------------------------------------------------------------

// Test 9: packages:write + untrusted input -> MEDIUM
func TestSupplyChainPoisoning_PackagesWriteWithUntrustedInput(t *testing.T) {
	yaml := `
name: AI Supply Chain
on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      packages: write
    steps:
      - uses: copilot@v1
        with:
          prompt: "${{ github.event.issue.body }}"
`
	g, err := analysis.BuildGraph("owner/repo", "ai-supply.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	supplyFindings := findingsByType(findings, detections.VulnAISupplyChainPoisoning)
	require.Len(t, supplyFindings, 1)
	assert.Equal(t, detections.SeverityMedium, supplyFindings[0].Severity)
}

// Test 10: BUG FIX - nil permissions + untrusted input -> MEDIUM
func TestSupplyChainPoisoning_NilPermissionsWithUntrustedInput(t *testing.T) {
	yaml := `
name: AI No Perms
on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: copilot@v1
        with:
          prompt: "${{ github.event.issue.body }}"
`
	g, err := analysis.BuildGraph("owner/repo", "ai-nil-perms.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	supplyFindings := findingsByType(findings, detections.VulnAISupplyChainPoisoning)
	require.Len(t, supplyFindings, 1, "BUG FIX: nil permissions should be treated as dangerous (GitHub defaults to read+write)")
	assert.Equal(t, detections.SeverityMedium, supplyFindings[0].Severity)
}

// Test 11: read-only permissions -> no supply chain finding
func TestSupplyChainPoisoning_ReadOnlyPermissions(t *testing.T) {
	yaml := `
name: Safe AI
on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      packages: read
      contents: read
    steps:
      - uses: copilot@v1
        with:
          prompt: "${{ github.event.issue.body }}"
`
	g, err := analysis.BuildGraph("owner/repo", "ai-read-only.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	supplyFindings := findingsByType(findings, detections.VulnAISupplyChainPoisoning)
	assert.Len(t, supplyFindings, 0)
}

// ---------------------------------------------------------------------------
// Check 4: Privilege Escalation
// ---------------------------------------------------------------------------

// Test 12: members:write on AI trigger -> MEDIUM
func TestPrivilegeEscalation_MembersWriteOnAITrigger(t *testing.T) {
	yaml := `
name: AI Priv Esc
on: issue_comment
jobs:
  manage:
    runs-on: ubuntu-latest
    permissions:
      members: write
    steps:
      - uses: copilot@v1
`
	g, err := analysis.BuildGraph("owner/repo", "ai-priv.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	privFindings := findingsByType(findings, detections.VulnAIPrivilegeEscalation)
	require.Len(t, privFindings, 1)
	assert.Equal(t, detections.SeverityMedium, privFindings[0].Severity)
}

// Test 13: safe trigger (push) -> no priv esc
func TestPrivilegeEscalation_SafeTrigger(t *testing.T) {
	yaml := `
name: Safe AI
on: push
jobs:
  manage:
    runs-on: ubuntu-latest
    permissions:
      members: write
    steps:
      - uses: copilot@v1
`
	g, err := analysis.BuildGraph("owner/repo", "ai-safe-push.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	privFindings := findingsByType(findings, detections.VulnAIPrivilegeEscalation)
	assert.Len(t, privFindings, 0)
}

// ---------------------------------------------------------------------------
// Check 5: Workflow Sabotage
// ---------------------------------------------------------------------------

// Test 14: actions:write on issue_comment -> MEDIUM
func TestWorkflowSabotage_ActionsWriteOnIssueComment(t *testing.T) {
	yaml := `
name: AI Workflow Sabotage
on:
  issue_comment:
    types: [created]
jobs:
  ai-check:
    runs-on: ubuntu-latest
    permissions:
      actions: write
    steps:
      - uses: coderabbit-ai/pr-review@v1
`
	g, err := analysis.BuildGraph("owner/repo", "ai-sabotage.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	sabotageFindings := findingsByType(findings, detections.VulnAIWorkflowSabotage)
	require.Len(t, sabotageFindings, 1)
	assert.Equal(t, detections.SeverityMedium, sabotageFindings[0].Severity)
}

// Test 15: actions:write on pull_request_target -> LOW
func TestWorkflowSabotage_ActionsWriteOnPullRequestTarget(t *testing.T) {
	yaml := `
name: AI Workflow
on: pull_request_target
jobs:
  ai-check:
    runs-on: ubuntu-latest
    permissions:
      actions: write
    steps:
      - uses: coderabbit-ai/pr-review@v1
`
	g, err := analysis.BuildGraph("owner/repo", "ai-workflow-prt.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	sabotageFindings := findingsByType(findings, detections.VulnAIWorkflowSabotage)
	require.Len(t, sabotageFindings, 1)
	assert.Equal(t, detections.SeverityLow, sabotageFindings[0].Severity)
}

// Test 16: nil permissions on AI trigger -> finding (nil = actions:write defaults)
func TestWorkflowSabotage_NilPermissionsOnAITrigger(t *testing.T) {
	yaml := `
name: AI Workflow No Perms
on:
  issue_comment:
    types: [created]
jobs:
  ai-check:
    runs-on: ubuntu-latest
    steps:
      - uses: coderabbit-ai/pr-review@v1
`
	g, err := analysis.BuildGraph("owner/repo", "ai-no-perms.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	sabotageFindings := findingsByType(findings, detections.VulnAIWorkflowSabotage)
	require.NotEmpty(t, sabotageFindings, "nil permissions should default to actions:write and produce a finding")
}

// Test 17: explicit permissions block without actions:write -> no sabotage finding
func TestWorkflowSabotage_ExplicitPermissionsNoActionsWrite(t *testing.T) {
	yaml := `
name: AI Workflow Safe
on:
  issue_comment:
    types: [created]
jobs:
  ai-check:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: coderabbit-ai/pr-review@v1
`
	g, err := analysis.BuildGraph("owner/repo", "ai-safe-perms.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	sabotageFindings := findingsByType(findings, detections.VulnAIWorkflowSabotage)
	assert.Len(t, sabotageFindings, 0)
}

// ---------------------------------------------------------------------------
// Check 6: MCP Abuse
// ---------------------------------------------------------------------------

// Test 18: MCP + GITHUB_TOKEN -> LOW
func TestMCPAbuse_MCPWithGitHubToken(t *testing.T) {
	yaml := `
name: AI MCP Abuse
on: push
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: copilot@v1
        with:
          enable-github-mcp: "true"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
`
	g, err := analysis.BuildGraph("owner/repo", "ai-mcp.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	mcpFindings := findingsByType(findings, detections.VulnAIMCPAbuse)
	require.Len(t, mcpFindings, 1)
	assert.Equal(t, detections.SeverityLow, mcpFindings[0].Severity)
}

// Test 19: MCP + untrusted input only -> LOW
func TestMCPAbuse_MCPWithUntrustedInputOnly(t *testing.T) {
	yaml := `
name: AI MCP Untrusted
on: issues
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: copilot@v1
        with:
          enable-github-mcp: "true"
          prompt: "${{ github.event.issue.body }}"
`
	g, err := analysis.BuildGraph("owner/repo", "ai-mcp-untrusted.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	mcpFindings := findingsByType(findings, detections.VulnAIMCPAbuse)
	require.Len(t, mcpFindings, 1)
	assert.Equal(t, detections.SeverityLow, mcpFindings[0].Severity)
}

// Test 20: No MCP indicators -> no MCP finding
func TestMCPAbuse_NoMCPIndicators(t *testing.T) {
	yaml := `
name: AI No MCP
on: push
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: copilot@v1
        with:
          prompt: "review code"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
`
	g, err := analysis.BuildGraph("owner/repo", "ai-no-mcp.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	mcpFindings := findingsByType(findings, detections.VulnAIMCPAbuse)
	assert.Len(t, mcpFindings, 0)
}

// ---------------------------------------------------------------------------
// Check 6: Unsafe User Access (Clinejection-style)
// ---------------------------------------------------------------------------

// Test: AI action with allowed_non_write_users: "*" -> MEDIUM sabotage
func TestUnsafeUserAccess_WildcardAllowedUsers(t *testing.T) {
	yaml := `
name: AI Unsafe Access
on: issue_comment
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`
	g, err := analysis.BuildGraph("owner/repo", "ai-unsafe-access.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	sabotageFindings := findingsByType(findings, detections.VulnAIWorkflowSabotage)
	// Find the specific unsafe user access finding (wildcard evidence)
	var unsafeFindings []detections.Finding
	for _, f := range sabotageFindings {
		if f.Severity == detections.SeverityMedium && strings.Contains(f.Evidence, "allowing any user") {
			unsafeFindings = append(unsafeFindings, f)
		}
	}
	require.Len(t, unsafeFindings, 1)
	assert.Equal(t, detections.SeverityMedium, unsafeFindings[0].Severity)
	assert.Equal(t, detections.ConfidenceHigh, unsafeFindings[0].Confidence)
	assert.Equal(t, detections.ComplexityZeroClick, unsafeFindings[0].Complexity)
	assert.Contains(t, unsafeFindings[0].Evidence, "allowed_non_write_users")
}

// Test: AI action without wildcard access -> no unsafe access finding
func TestUnsafeUserAccess_NoWildcard(t *testing.T) {
	yaml := `
name: AI Safe Access
on: issue_comment
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`
	g, err := analysis.BuildGraph("owner/repo", "ai-safe-access.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	sabotageFindings := findingsByType(findings, detections.VulnAIWorkflowSabotage)
	// Verify no unsafe user access sabotage finding with wildcard evidence
	for _, f := range sabotageFindings {
		if f.Severity == detections.SeverityMedium && strings.Contains(f.Evidence, "allowing any user") {
			t.Error("Should not produce an unsafe user access finding when no wildcard is configured")
		}
	}
}

// ---------------------------------------------------------------------------
// Edge Cases
// ---------------------------------------------------------------------------

// Test 21: Non-AI action -> no findings at all
func TestEdgeCase_NonAIAction(t *testing.T) {
	yaml := `
name: Regular Build
on: issue_comment
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      actions: write
    steps:
      - uses: actions/checkout@v3
        with:
          input: "${{ github.event.issue.body }}"
`
	g, err := analysis.BuildGraph("owner/repo", "regular.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0)
}

// Test: AI + contents:write + untrusted input via step.Run -> MEDIUM
func TestCodeInjection_ViaStepRun(t *testing.T) {
	yaml := `
name: AI Run Injection
on: issues
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - name: AI review
        uses: coderabbit@v1
        run: echo "${{ github.event.issue.body }}"
`
	g, err := analysis.BuildGraph("owner/repo", "ai-run-injection.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	codeFindings := findingsByType(findings, detections.VulnAICodeInjection)
	require.Len(t, codeFindings, 1)
	assert.Equal(t, detections.SeverityMedium, codeFindings[0].Severity)
}

// Test: AI + both contents:write AND pull-requests:write -> MEDIUM (contents takes precedence)
func TestCodeInjection_ContentsAndPullRequestsWrite(t *testing.T) {
	yaml := `
name: AI Dual Perms
on: issues
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - name: AI review
        uses: coderabbit@v1
        with:
          prompt: "${{ github.event.issue.body }}"
`
	g, err := analysis.BuildGraph("owner/repo", "ai-dual-perms.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	codeFindings := findingsByType(findings, detections.VulnAICodeInjection)
	require.Len(t, codeFindings, 1)
	assert.Equal(t, detections.SeverityMedium, codeFindings[0].Severity,
		"contents:write should produce MEDIUM even when pull-requests:write is also present")
}

// Test: hasSecretAccess via `with` block (existing tests use `env`)
func TestTokenExfiltration_SecretInWithBlock(t *testing.T) {
	yaml := `
name: AI Secret Via With
on:
  issue_comment:
    types: [created]
jobs:
  ai-check:
    runs-on: ubuntu-latest
    steps:
      - uses: coderabbit-ai/pr-review@v1
        with:
          api_key: ${{ secrets.API_KEY }}
          prompt: ${{ github.event.comment.body }}
`
	g, err := analysis.BuildGraph("owner/repo", "ai-secret-with.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	tokenFindings := findingsByType(findings, detections.VulnAITokenExfiltration)
	require.Len(t, tokenFindings, 1,
		"secret in 'with' block should be detected by hasSecretAccess")
	assert.Equal(t, detections.SeverityMedium, tokenFindings[0].Severity)
}

// Test: Detection on empty graph -> 0 findings, no error
func TestDetect_EmptyGraph(t *testing.T) {
	g, err := analysis.BuildGraph("owner/repo", "empty.yml", []byte(`
name: Empty
on: push
`))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// Test 22: Multiple AI steps -> multiple findings
func TestEdgeCase_MultipleAISteps(t *testing.T) {
	yaml := `
name: Multi AI
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - name: Review with Coderabbit
        uses: coderabbit@v1
        with:
          prompt: "${{ github.event.pull_request.body }}"
      - name: Review with Claude
        uses: claude@v1
        with:
          input: "${{ github.event.pull_request.body }}"
`
	g, err := analysis.BuildGraph("owner/repo", "multi-ai.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	codeFindings := findingsByType(findings, detections.VulnAICodeInjection)
	assert.GreaterOrEqual(t, len(codeFindings), 2, "should detect code injection for each AI step")
}
