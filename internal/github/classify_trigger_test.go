package github

import (
	"reflect"
	"testing"
)

func TestClassifyTriggerTrustBuckets(t *testing.T) {
	cases := []struct {
		trigger string
		want    string
	}{
		{"pull_request", "low"},
		{"pull_request_target", "low"},
		{"pull_request_review", "low"},
		{"pull_request_review_comment", "low"},
		{"issue_comment", "low"},
		{"issues", "low"},
		{"discussion", "low"},
		{"discussion_comment", "low"},
		{"fork", "low"},
		{"watch", "low"},
		{"star", "low"},
		{"public", "low"},

		{"workflow_dispatch", "medium"},
		{"repository_dispatch", "medium"},
		{"workflow_run", "medium"},
		{"workflow_call", "medium"},
		{"check_run", "medium"},
		{"check_suite", "medium"},
		{"label", "medium"},

		{"push", "high"},
		{"release", "high"},
		{"deployment", "high"},
		{"deployment_status", "high"},
		{"schedule", "high"},
		{"milestone", "high"},
		{"page_build", "high"},
		{"create", "high"},
		{"delete", "high"},
		{"registry_package", "high"},
		{"branch_protection_rule", "high"},
	}
	for _, c := range cases {
		if got := classifyTrigger(c.trigger); got != c.want {
			t.Errorf("classifyTrigger(%q) = %q, want %q", c.trigger, got, c.want)
		}
	}
}

func TestClassifyTriggerCaseInsensitive(t *testing.T) {
	for _, in := range []string{"Pull_Request", "PUSH", "Workflow_Run", "WORKFLOW_DISPATCH"} {
		lcWant := classifyTrigger(toLowerASCII(in))
		if got := classifyTrigger(in); got != lcWant {
			t.Errorf("classifyTrigger(%q)=%q not case-insensitive (lower-form=%q)", in, got, lcWant)
		}
	}
	if classifyTrigger("Pull_Request") != "low" {
		t.Errorf("mixed-case pull_request should be low")
	}
}

func TestClassifyTriggerUnknownDefaultsToMedium(t *testing.T) {
	// Unknown triggers are conservatively medium, not low or high.
	for _, unknown := range []string{"deployment_review", "merge_group", "totally_made_up", ""} {
		if got := classifyTrigger(unknown); got != "medium" {
			t.Errorf("classifyTrigger(%q) = %q, want medium (unknown->conservative)", unknown, got)
		}
	}
}

func TestTriggerClassSummaryBucketingAndKeyNames(t *testing.T) {
	got := triggerClassSummary([]string{
		"push",
		"pull_request",
		"merge_group",  // unknown -> medium
		"workflow_run", // medium
		"pull_request", // duplicate, must NOT be deduped
		"release",
	})
	want := TriggerClassSummary{
		LowTrust:  []string{"pull_request", "pull_request"},
		Medium:    []string{"merge_group", "workflow_run"},
		HighTrust: []string{"push", "release"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("triggerClassSummary mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

func TestTriggerClassSummaryEmptySlicesNotNil(t *testing.T) {
	// All three slices must marshal to [] not null.
	got := triggerClassSummary(nil)
	if got.LowTrust == nil || got.Medium == nil || got.HighTrust == nil {
		t.Fatalf("empty summary must have non-nil slices, got %+v", got)
	}
	if len(got.LowTrust)+len(got.Medium)+len(got.HighTrust) != 0 {
		t.Fatalf("expected all-empty summary, got %+v", got)
	}
}

func TestAttackerFieldsForTriggersUnknownContributesNothing(t *testing.T) {
	// Only mapped triggers have fields; valid trust-class triggers like push/
	// schedule/label are deliberately absent from the attacker-field map.
	for _, tr := range []string{"push", "schedule", "label", "check_run", "workflow_call", "made_up"} {
		if got := attackerFieldsForTriggers([]string{tr}); len(got) != 0 {
			t.Errorf("attackerFieldsForTriggers([%q]) = %v, want empty", tr, got)
		}
	}
}

func TestAttackerFieldsForTriggersUnionAndDedup(t *testing.T) {
	// pull_request and pull_request_target carry identical field lists, so the
	// union must dedup to the single list.
	single := attackerFieldsForTriggers([]string{"pull_request"})
	union := attackerFieldsForTriggers([]string{"pull_request", "pull_request_target"})
	if !reflect.DeepEqual(single, union) {
		t.Errorf("identical-list triggers must dedup to one list\n one: %v\nboth: %v", single, union)
	}

	// Distinct lists concat in first-sight order.
	mix := attackerFieldsForTriggers([]string{"workflow_dispatch", "repository_dispatch"})
	wantMix := []string{"github.event.inputs", "inputs", "github.event.client_payload"}
	if !reflect.DeepEqual(mix, wantMix) {
		t.Errorf("union order/dedup wrong\n got: %v\nwant: %v", mix, wantMix)
	}
}

func TestExtractInterpolations(t *testing.T) {
	cases := []struct {
		text string
		want []string
	}{
		{"", []string{}},
		{"no interpolation here", []string{}},
		{"${{ github.event.pull_request.title }}", []string{"github.event.pull_request.title"}},
		{"x ${{   github.actor   }} y", []string{"github.actor"}},
		// duplicates NOT deduped, order preserved.
		{"${{ a }} ${{ b }} ${{ a }}", []string{"a", "b", "a"}},
		// non-greedy: first }} closes the match, so the second token is its own match.
		{"${{ inputs.x }}${{ inputs.y }}", []string{"inputs.x", "inputs.y"}},
	}
	for _, c := range cases {
		got := extractInterpolations(c.text)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("extractInterpolations(%q) = %v, want %v", c.text, got, c.want)
		}
	}
}

func TestFindAttackerReferencesExecBindingPrefixMatch(t *testing.T) {
	prTriggers := []string{"pull_request_target"}

	t.Run("bare-and-deeper-prefix", func(t *testing.T) {
		text := "run: echo ${{ github.event.pull_request.head.sha }}"
		got := findAttackerReferences(text, prTriggers)
		want := []string{"github.event.pull_request.head.sha"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("tojson-wrapper-both-casings", func(t *testing.T) {
		for _, wrap := range []string{
			"${{ toJSON(github.event.pull_request.body) }}",
			"${{ toJson(github.event.pull_request.body) }}",
		} {
			got := findAttackerReferences(wrap, prTriggers)
			want := []string{"github.event.pull_request.body"}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("toJSON wrap %q: got %v, want %v", wrap, got, want)
			}
		}
	})

	// comment.body belongs to issue_comment, not the PR triggers.
	t.Run("field-not-in-trigger-set", func(t *testing.T) {
		text := "${{ github.event.comment.body }}"
		if got := findAttackerReferences(text, prTriggers); len(got) != 0 {
			t.Errorf("comment.body must not match under pull_request_target, got %v", got)
		}
		if got := findAttackerReferences(text, []string{"issue_comment"}); !reflect.DeepEqual(got, []string{"github.event.comment.body"}) {
			t.Errorf("comment.body should match under issue_comment, got %v", got)
		}
	})

	t.Run("dedup-first-encounter-order", func(t *testing.T) {
		text := "${{ github.head_ref }} ${{ github.event.number }} ${{ github.head_ref }}"
		got := findAttackerReferences(text, prTriggers)
		want := []string{"github.head_ref", "github.event.number"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("trusted-context-ignored", func(t *testing.T) {
		text := "${{ github.repository }} ${{ secrets.TOKEN }} ${{ github.sha }}"
		if got := findAttackerReferences(text, prTriggers); len(got) != 0 {
			t.Errorf("trusted contexts must not match, got %v", got)
		}
	})

	t.Run("workflow_run-fields", func(t *testing.T) {
		text := "ref: ${{ github.event.workflow_run.head_sha }}"
		got := findAttackerReferences(text, []string{"workflow_run"})
		want := []string{"github.event.workflow_run.head_sha"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
