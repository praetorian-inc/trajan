package gitlab

import "testing"

// The cat-06 approval-policy rules read approval_policy.{fallback_behavior,
// enforcement_type, bypass_actor_broad, scanners}. These assert the P2-collected
// policy YAML is parsed into those literals. The oracle is the GitLab scan-result
// policy schema (fallback_behavior.fail: open|closed; require_approval action;
// bypass_settings actor lists) and the three frozen rule predicates.

func TestApprovalPolicyFallbackFailOpen(t *testing.T) {
	spec := parsePolicyYAML(`
name: block on vulns
rules:
  - type: scan_finding
    scanners: [sast, dependency_scanning]
actions:
  - type: require_approval
    approvals_required: 1
fallback_behavior:
  fail: open
`)
	if spec == nil {
		t.Fatal("policy YAML failed to parse")
	}
	if fb := entMap(spec["fallback_behavior"]); entStr(fb["fail"]) != "open" {
		t.Fatalf("fallback fail=%q want open", entStr(fb["fail"]))
	}
	sc := policyScanners(spec)
	if len(sc) != 2 || sc[0] != "sast" {
		t.Errorf("scanners=%v want [sast dependency_scanning]", sc)
	}
	if warnMode(spec) {
		t.Error("approvals_required:1 must not be warn mode")
	}
	if !hasRequireApproval(spec) {
		t.Error("require_approval action must be detected")
	}
}

func TestApprovalPolicyWarnMode(t *testing.T) {
	spec := parsePolicyYAML(`
actions:
  - type: require_approval
    approvals_required: 0
`)
	if !warnMode(spec) {
		t.Error("approvals_required:0 require_approval must be warn mode (dismissable)")
	}
}

func TestApprovalPolicyBypassBroad(t *testing.T) {
	broad := parsePolicyYAML(`
bypass_settings:
  service_accounts:
    - id: 7
`)
	if !bypassActorBroad(broad) {
		t.Error("bypass_settings with a service_accounts list must be broad")
	}
	narrow := parsePolicyYAML(`
name: no bypass
actions:
  - type: require_approval
    approvals_required: 1
`)
	if bypassActorBroad(narrow) {
		t.Error("absent bypass_settings must not be broad")
	}
}
