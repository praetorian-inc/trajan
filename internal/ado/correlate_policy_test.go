package ado

import (
	"reflect"
	"sort"
	"testing"
)

func mr(minCount int, creatorVotes, resetOnPush bool) map[string]any {
	return map[string]any{"settings": map[string]any{
		"minimum_approver_count": float64(minCount),
		"creator_vote_counts":    creatorVotes,
		"reset_on_source_push":   resetOnPush,
	}}
}

func TestBranchWeaknesses(t *testing.T) {
	cases := []struct {
		name string
		gov  govPolicies
		want []string
	}{
		{"no blocking policy at all", govPolicies{}, []string{"no_policy"}},
		{
			"weak review (0 approvers) + stale (no reset)",
			govPolicies{anyBlocking: true, blockingMinReviewers: mr(0, false, false)},
			[]string{"weak_review", "stale_approval"},
		},
		{
			"self-approval allowed",
			govPolicies{anyBlocking: true, blockingMinReviewers: mr(2, true, true)},
			[]string{"self_approve"},
		},
		{
			"strong review (2 approvers, reset on push, no self-approve) => no unreviewed push",
			govPolicies{anyBlocking: true, blockingMinReviewers: mr(2, false, true)},
			nil,
		},
		{
			"optional (non-blocking) build validation",
			govPolicies{
				anyBlocking:      true,
				buildValidations: []map[string]any{{"is_blocking": false, "is_enabled": true}},
			},
			[]string{"optional_build_validation"},
		},
	}
	for _, c := range cases {
		got := branchWeaknesses(c.gov)
		sort.Strings(got)
		want := append([]string(nil), c.want...)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: branchWeaknesses = %v, want %v", c.name, got, want)
		}
	}
}

// A blocking build-validation with a strong reviewer policy leaves no unreviewed
// path (CAN_PUSH_TO must be empty) — the blocking gate holds.
func TestGoverningPolicies_BlockingHolds(t *testing.T) {
	edges := []map[string]any{
		{"policy_type": minReviewersType, "is_blocking": true, "is_enabled": true, "config_id": float64(1)},
		{"policy_type": buildValidationType, "is_blocking": true, "is_enabled": true, "config_id": float64(2)},
	}
	polByConfig := map[int64]map[string]any{1: mr(2, false, true)}
	gov := governingPolicies(edges, polByConfig)
	if !gov.anyBlocking || gov.blockingMinReviewers == nil {
		t.Fatalf("expected a blocking minReviewers gate, got %+v", gov)
	}
	if via := branchWeaknesses(gov); len(via) != 0 {
		t.Errorf("strong blocking gate should yield no via, got %v", via)
	}
}

// A disabled policy does not govern (must be ignored).
func TestGoverningPolicies_DisabledIgnored(t *testing.T) {
	edges := []map[string]any{
		{"policy_type": minReviewersType, "is_blocking": true, "is_enabled": false, "config_id": float64(1)},
	}
	gov := governingPolicies(edges, map[int64]map[string]any{1: mr(2, false, true)})
	if gov.anyBlocking {
		t.Error("a disabled policy must not count as a blocking gate")
	}
	if via := branchWeaknesses(gov); !reflect.DeepEqual(via, []string{"no_policy"}) {
		t.Errorf("disabled-only branch should be no_policy, got %v", via)
	}
}
