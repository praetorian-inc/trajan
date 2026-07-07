package github

import (
	"slices"
	"testing"
)

func TestOrgOnlyFilterSelectsExactlyOrgSubjects(t *testing.T) {
	rules, err := LoadRules()
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	full := len(rules)
	// exercise the production filter (--org-detections-only path) directly; clone
	// first because orgOnlyRules mutates its input via slices.DeleteFunc.
	org := orgOnlyRules(slices.Clone(rules))
	if len(org) == 0 {
		t.Fatal("expected at least one subject==org rule")
	}
	if len(org) >= full {
		t.Fatalf("org-only set (%d) should be a strict subset of the full set (%d)", len(org), full)
	}
	for _, r := range org {
		if r.SubjectKind() != "org" {
			t.Errorf("org-only set leaked a %q-subject rule (%s)", r.SubjectKind(), r.ID)
		}
	}

	// Every org-subject rule in the full corpus must survive the filter.
	wantOrg := 0
	for _, r := range rules {
		if r.SubjectKind() == "org" {
			wantOrg++
		}
	}
	if len(org) != wantOrg {
		t.Errorf("org-only set has %d rules, want all %d org-subject rules", len(org), wantOrg)
	}
}

func TestMembersCanCreatePrivateReposRuleFires(t *testing.T) {
	rules, err := LoadRules()
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	var rule *Rule
	for i := range rules {
		if rules[i].ID == "cat-13/members-can-create-private-repositories" {
			rule = &rules[i]
			break
		}
	}
	if rule == nil {
		t.Fatal("members-can-create-private-repositories rule not found")
	}
	if rule.SubjectKind() != "org" {
		t.Fatalf("rule subject kind = %q, want org", rule.SubjectKind())
	}

	fires := map[string]any{"_id": "acme", "members_can_create_private_repositories": true}
	if got := EvaluateRule(rule, []map[string]any{fires}, nil); len(got) != 1 {
		t.Errorf("rule should fire when members_can_create_private_repositories is true, got %d", len(got))
	}

	silent := map[string]any{"_id": "acme", "members_can_create_private_repositories": false}
	if got := EvaluateRule(rule, []map[string]any{silent}, nil); len(got) != 0 {
		t.Errorf("rule should stay silent when the setting is false, got %d", len(got))
	}
}
