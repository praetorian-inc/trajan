package dsl

import (
	"reflect"
	"testing"
)

func mustEval(t *testing.T, predicate string, subj any) bool {
	t.Helper()
	ok, err := EvaluatePredicate(predicate, subj)
	if err != nil {
		t.Fatalf("EvaluatePredicate(%q): unexpected error %v", predicate, err)
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
		if got := mustEval(t, c.predicate, subj); got != c.want {
			t.Errorf("%q => %v, want %v", c.predicate, got, c.want)
		}
	}
}

func TestEvaluatePredicateEmptyListEquality(t *testing.T) {
	subj := map[string]any{
		"empty":    []any{},
		"nonempty": []any{"x"},
	}
	if !mustEval(t, `empty == []`, subj) {
		t.Error("empty == [] should be true")
	}
	if mustEval(t, `nonempty == []`, subj) {
		t.Error("nonempty == [] should be false")
	}
	if !mustEval(t, `nonempty != []`, subj) {
		t.Error("a populated list should be != []")
	}
	if !mustEval(t, `absent != []`, subj) {
		t.Error("absent (nil) != [] should be true")
	}
	if mustEval(t, `absent == []`, subj) {
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
		if got := mustEval(t, c.predicate, subj); got != c.want {
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
		if got := mustEval(t, c.predicate, subj); got != c.want {
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
		if got := mustEval(t, c.predicate, subj); got != c.want {
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
		if got := mustEval(t, c.predicate, subj); got != c.want {
			t.Errorf("%q => %v, want %v", c.predicate, got, c.want)
		}
	}
}

func TestEvaluatePredicateInOperator(t *testing.T) {
	subj := map[string]any{"kind": "tag"}
	if !mustEval(t, `kind in {tag, branch}`, subj) {
		t.Error("kind in {tag, branch} should be true")
	}
	if mustEval(t, `kind in {sha, digest}`, subj) {
		t.Error("kind in {sha, digest} should be false")
	}
}

func TestSplitPredicateOperatorPrecedenceAndQuoting(t *testing.T) {
	cases := []struct {
		predicate string
		field     string
		op        string
		rhs       string
	}{
		{`a >= 2`, "a", "ge", "2"},
		{`a <= 2`, "a", "le", "2"},
		{`a > 2`, "a", "gt", "2"},
		{`a < 2`, "a", "lt", "2"},
		{`a == 2`, "a", "eq", "2"},
		{`a != 2`, "a", "ne", "2"},
		// An == inside the quoted rhs must not be taken as the split operator.
		{`name == "x == y"`, "name", "eq", `"x == y"`},
		{`triggers ∋ {a, b}`, "triggers", "contains", "{a, b}"},
		{`labels ⊆ {a}`, "labels", "subset", "{a}"},
		{`x matches "re"`, "x", "matches", `"re"`},
	}
	for _, c := range cases {
		field, op, rhs, ok := splitPredicate(c.predicate)
		if !ok {
			t.Errorf("%q: split failed", c.predicate)
			continue
		}
		if field != c.field || op != c.op || rhs != c.rhs {
			t.Errorf("split(%q) = (%q,%q,%q), want (%q,%q,%q)",
				c.predicate, field, op, rhs, c.field, c.op, c.rhs)
		}
	}
}

func TestSplitPredicateUnparseable(t *testing.T) {
	if _, _, _, ok := splitPredicate("just_a_bare_field"); ok {
		t.Error("a predicate with no operator must not split")
	}
	if _, err := EvaluatePredicate("nope", map[string]any{}); err == nil {
		t.Error("EvaluatePredicate on an operatorless predicate should error")
	}
}

func TestParseValue(t *testing.T) {
	cases := []struct {
		text string
		want any
	}{
		{"null", nil},
		{"None", nil},
		{"true", true},
		{"false", false},
		{"[]", []any{}},
		{"{}", map[string]any{}},
		{`"quoted"`, "quoted"},
		{`'quoted'`, "quoted"},
		{"42", 42},
		{"bare", "bare"},
	}
	for _, c := range cases {
		if got := parseValue(c.text); !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseValue(%q) = %#v, want %#v", c.text, got, c.want)
		}
	}
	// Set literal: items are trimmed, quote-stripped, and trailing empties dropped.
	set, ok := parseValue(`{a, 'b' , c,}`).(map[string]struct{})
	if !ok {
		t.Fatalf("set literal did not parse to a set: %#v", parseValue(`{a, 'b' , c,}`))
	}
	for _, want := range []string{"a", "b", "c"} {
		if _, present := set[want]; !present {
			t.Errorf("set missing %q: %#v", want, set)
		}
	}
	if len(set) != 3 {
		t.Errorf("set should have 3 members, got %d: %#v", len(set), set)
	}
}
