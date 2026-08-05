package detect

import (
	"testing"
)

func pred(s string) *Block { return &Block{Predicate: s} }

func mustEval(t *testing.T, b *Block, subj any) bool {
	t.Helper()
	ok, err := evaluateBlock(b, subj)
	if err != nil {
		t.Fatalf("evaluateBlock(%+v): unexpected error %v", b, err)
	}
	return ok
}

func TestEvaluatePredicateEqAndNe(t *testing.T) {
	subj := map[string]any{
		"has_checkout_of_pr_ref":    true,
		"executes_checked_out_code": false,
		"name":                      "ci",
		"count":                     float64(3),
		"missing_is_nil":            nil,
	}
	cases := []struct {
		predicate string
		want      bool
	}{
		{`has_checkout_of_pr_ref == true`, true},
		{`has_checkout_of_pr_ref != true`, false},
		{`executes_checked_out_code == true`, false},
		{`executes_checked_out_code == false`, true},
		{`name == "ci"`, true},
		{`name == 'ci'`, true},
		{`name != "release"`, true},
		{`count == 3`, true},
		{`count == 4`, false},
		{`absent == null`, true},
		{`absent != null`, false},
		{`missing_is_nil == null`, true},
		{`absent == "x"`, false},
		{`absent != "x"`, true},
	}
	for _, c := range cases {
		if got := mustEval(t, pred(c.predicate), subj); got != c.want {
			t.Errorf("%q => %v, want %v", c.predicate, got, c.want)
		}
	}
}

func TestEvaluatePredicateEmptyListEquality(t *testing.T) {
	subj := map[string]any{
		"empty":    []any{},
		"nonempty": []any{"x"},
	}
	if !mustEval(t, pred(`empty == []`), subj) {
		t.Error("empty == [] should be true")
	}
	if mustEval(t, pred(`nonempty == []`), subj) {
		t.Error("nonempty == [] should be false")
	}
	if !mustEval(t, pred(`nonempty != []`), subj) {
		t.Error("a populated list should be != []")
	}
	if !mustEval(t, pred(`absent != []`), subj) {
		t.Error("absent (nil) != [] should be true")
	}
	if mustEval(t, pred(`absent == []`), subj) {
		t.Error("absent (nil) == [] should be false")
	}
}

func TestEvaluatePredicateContains(t *testing.T) {
	subj := map[string]any{
		"triggers": []any{"pull_request_target", "push"},
		"single":   "issue_comment",
	}
	cases := []struct {
		predicate string
		want      bool
	}{
		{`triggers ∋ {pull_request_target, issue_comment}`, true},
		{`triggers ∋ {workflow_dispatch, schedule}`, false},
		{`triggers contains {push}`, true},
		{`single ∋ {issue_comment, pull_request}`, true},
		{`single ∋ {push}`, false},
	}
	for _, c := range cases {
		if got := mustEval(t, pred(c.predicate), subj); got != c.want {
			t.Errorf("%q => %v, want %v", c.predicate, got, c.want)
		}
	}
}

func TestEvaluatePredicateSubset(t *testing.T) {
	subj := map[string]any{
		"labels":  []any{"a", "b"},
		"labels2": []any{"a", "z"},
		"scalar":  "a",
		"empty":   []any{},
	}
	cases := []struct {
		predicate string
		want      bool
	}{
		{`labels ⊆ {a, b, c}`, true},
		{`labels2 ⊆ {a, b, c}`, false},
		{`labels subset_of {a, b}`, true},
		{`scalar ⊆ {a, b}`, false},
		{`empty ⊆ {a}`, true}, // empty list is vacuously a subset
	}
	for _, c := range cases {
		if got := mustEval(t, pred(c.predicate), subj); got != c.want {
			t.Errorf("%q => %v, want %v", c.predicate, got, c.want)
		}
	}
}

func TestEvaluatePredicateMatches(t *testing.T) {
	subj := map[string]any{
		"raw":       "github.actor == 'octocat'",
		"reviewers": []any{"alice", "dependabot[bot]"},
		"nilfield":  nil,
	}
	cases := []struct {
		predicate string
		want      bool
	}{
		{`raw matches "github.actor"`, true}, // unanchored: substring match
		{`raw matches "^release$"`, false},
		{`reviewers matches "Bot|\[bot\]"`, true}, // any list element matching is enough
		{`reviewers matches "nobody"`, false},
		{`nilfield matches "x"`, false},
	}
	for _, c := range cases {
		if got := mustEval(t, pred(c.predicate), subj); got != c.want {
			t.Errorf("%q => %v, want %v", c.predicate, got, c.want)
		}
	}
}

func TestEvaluatePredicateNumericComparisons(t *testing.T) {
	subj := map[string]any{"writer_count": float64(2), "reader_count": float64(0)}
	cases := []struct {
		predicate string
		want      bool
	}{
		{`writer_count >= 2`, true},
		{`writer_count > 2`, false},
		{`writer_count <= 2`, true},
		{`writer_count < 2`, false},
		{`reader_count > 0`, false},
		{`reader_count >= 0`, true},
		{`absent > 0`, false},
		{`absent < 99`, false},
	}
	for _, c := range cases {
		if got := mustEval(t, pred(c.predicate), subj); got != c.want {
			t.Errorf("%q => %v, want %v", c.predicate, got, c.want)
		}
	}
}

func TestEvaluatePredicateInOperator(t *testing.T) {
	subj := map[string]any{"kind": "tag"}
	if !mustEval(t, pred(`kind in {tag, branch}`), subj) {
		t.Error("kind in {tag, branch} should be true")
	}
	if mustEval(t, pred(`kind in {sha, digest}`), subj) {
		t.Error("kind in {sha, digest} should be false")
	}
}

func TestCombinatorEmptyCollections(t *testing.T) {
	subj := map[string]any{}
	if !mustEval(t, &Block{IsCombo: true, AllOf: []Block{}}, subj) {
		t.Error("empty all_of must be true")
	}
	if mustEval(t, &Block{IsCombo: true, AnyOf: []Block{}}, subj) {
		t.Error("empty any_of must be false")
	}
	if !mustEval(t, &Block{IsCombo: true, NoneOf: []Block{}}, subj) {
		t.Error("empty none_of must be true")
	}
	if _, err := evaluateBlock(&Block{IsCombo: true}, subj); err == nil {
		t.Error("combinator with no all_of/any_of/none_of must error")
	}
}

func TestCombinatorConjunction(t *testing.T) {
	subj := map[string]any{
		"a":        true,
		"b":        false,
		"triggers": []any{"pull_request_target"},
	}
	block := &Block{
		IsCombo: true,
		AllOf:   []Block{*pred(`a == true`)},
		AnyOf:   []Block{*pred(`b == true`), *pred(`a == true`)},
		NoneOf:  []Block{*pred(`b == true`)},
	}
	if !mustEval(t, block, subj) {
		t.Error("true all_of + satisfiable any_of + clean none_of should fire")
	}
	block.NoneOf = []Block{*pred(`a == true`)}
	if mustEval(t, block, subj) {
		t.Error("none_of matching a true predicate must suppress the block")
	}
	block.AllOf = []Block{*pred(`a == true`), *pred(`b == true`)}
	block.NoneOf = []Block{*pred(`b == true`)}
	if mustEval(t, block, subj) {
		t.Error("a false all_of member must fail the block")
	}
}

func TestCombinatorNesting(t *testing.T) {
	subj := map[string]any{"x": float64(5), "y": "tag"}
	block := &Block{
		IsCombo: true,
		AnyOf: []Block{
			{IsCombo: true, AllOf: []Block{*pred(`x >= 5`), *pred(`y == "tag"`)}},
			*pred(`x > 100`),
		},
	}
	if !mustEval(t, block, subj) {
		t.Error("nested all_of inside any_of should fire")
	}
}
