package github

import (
	"reflect"
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
	if _, err := evaluatePredicate("nope", map[string]any{}); err == nil {
		t.Error("evaluatePredicate on an operatorless predicate should error")
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

func gatePtr(s string) *string { return &s }

func TestClassifyGateNone(t *testing.T) {
	if g := classifyGate(nil); g.GateStrength != "none" {
		t.Errorf("nil if: -> %q, want none", g.GateStrength)
	}
	if g := classifyGate(gatePtr("")); g.GateStrength != "none" {
		t.Errorf("empty if: -> %q, want none", g.GateStrength)
	}
	if g := classifyGate(gatePtr("true")); g.GateStrength != "none" {
		t.Errorf("if: true -> %q, want none", g.GateStrength)
	}
	if g := classifyGate(gatePtr("${{ true }}")); g.GateStrength != "none" {
		t.Errorf("if: ${{ true }} -> %q, want none", g.GateStrength)
	}
}

func TestClassifyGateStrengthByBranch(t *testing.T) {
	cases := []struct {
		name     string
		expr     string
		strength string
		flag     func(GateClassifiers) bool
	}{
		{
			"pseudo conclusion", "github.event.workflow_run.conclusion == 'success'", "pseudo",
			func(c GateClassifiers) bool { return c.IsPseudoGateConclusion },
		},
		{
			"label contains", "contains(github.event.pull_request.labels.*.name, 'safe')", "weak",
			func(c GateClassifiers) bool { return c.IsLabelGate },
		},
		{
			"label name", "github.event.label.name == 'run-ci'", "weak",
			func(c GateClassifiers) bool { return c.IsLabelGate },
		},
		{
			"author association", "github.event.comment.author_association == 'OWNER'", "weak",
			func(c GateClassifiers) bool { return c.IsAuthorAssocGate },
		},
		{
			"strong actor eq", "github.actor == 'octocat'", "strong",
			func(c GateClassifiers) bool {
				return !c.IsLabelGate && !c.IsAuthorAssocGate && !c.IsPseudoGateConclusion
			},
		},
		{
			"strong fromJSON", "contains(fromJSON('[\"a\"]'), github.actor)", "strong",
			func(c GateClassifiers) bool { return true },
		},
		{
			"strong repo owner", "github.repository_owner == 'acme'", "strong",
			func(c GateClassifiers) bool { return true },
		},
		{
			"weak default", "github.ref == 'refs/heads/main'", "weak",
			func(c GateClassifiers) bool { return !c.IsLabelGate && !c.IsAuthorAssocGate },
		},
	}
	for _, c := range cases {
		g := classifyGate(gatePtr(c.expr))
		if g.GateStrength != c.strength {
			t.Errorf("%s: %q -> %q, want %q", c.name, c.expr, g.GateStrength, c.strength)
		}
		if !c.flag(g.GateClassifiers) {
			t.Errorf("%s: classifier flags wrong for %q: %+v", c.name, c.expr, g.GateClassifiers)
		}
	}
}

// Ordering: pseudo beats label beats author_assoc beats strong (first branch wins).
func TestClassifyGateBranchPrecedence(t *testing.T) {
	both := "github.event.workflow_run.conclusion == 'success' && github.event.comment.author_association == 'OWNER'"
	g := classifyGate(gatePtr(both))
	if g.GateStrength != "pseudo" {
		t.Errorf("conclusion+author_assoc -> %q, want pseudo (first branch wins)", g.GateStrength)
	}
	if !g.GateClassifiers.IsPseudoGateConclusion || g.GateClassifiers.IsAuthorAssocGate {
		t.Errorf("only the pseudo flag should be set: %+v", g.GateClassifiers)
	}
	labelAndActor := "github.event.label.name == 'ok' && github.actor == 'octocat'"
	g2 := classifyGate(gatePtr(labelAndActor))
	if g2.GateStrength != "weak" || !g2.GateClassifiers.IsLabelGate {
		t.Errorf("label+actor -> %q (label=%v), want weak/label", g2.GateStrength, g2.GateClassifiers.IsLabelGate)
	}
}

// The strong-branch needle is case-sensitive and assumes exactly one space before ==.
func TestClassifyGateStrongCaseSensitivity(t *testing.T) {
	// Two spaces before == means the "github.repository_owner ==" needle misses.
	g := classifyGate(gatePtr("github.repository_owner  == 'acme'"))
	if g.GateStrength != "weak" {
		t.Errorf("double-space repo_owner -> %q, want weak (needle needs single space)", g.GateStrength)
	}
	expr := "github.actor == 'x'"
	if got := classifyGate(gatePtr(expr)); got.Raw == nil || *got.Raw != expr {
		t.Errorf("Raw not preserved: %+v", got.Raw)
	}
}

func loadSpineRule(t *testing.T) *Rule {
	t.Helper()
	rules, err := LoadRules()
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	for i := range rules {
		if rules[i].ID == "cat-01/prt-checkout-execute" {
			return &rules[i]
		}
	}
	t.Fatalf("spine rule cat-01/prt-checkout-execute not found among %d rules", len(rules))
	return nil
}

func prtJob() map[string]any {
	return map[string]any{
		"_id":                       "fr-01__ci__build",
		"triggers":                  []any{"pull_request_target"},
		"has_checkout_of_pr_ref":    true,
		"executes_checked_out_code": true,
		"if_conditions_summary":     map[string]any{"gate_strength": "weak"},
	}
}

func TestSpineRuleFiresOnPrtCheckoutExecute(t *testing.T) {
	rule := loadSpineRule(t)
	if rule.SubjectKind() != "job" {
		t.Fatalf("spine subject kind = %q, want job", rule.SubjectKind())
	}
	matched := EvaluateRule(rule, []map[string]any{prtJob()}, func(err error) {
		t.Errorf("unexpected eval error: %v", err)
	})
	if len(matched) != 1 {
		t.Fatalf("spine should fire on a PRT-checkout-execute job, got %d matches", len(matched))
	}
	j := prtJob()
	j["triggers"] = []any{"issue_comment"}
	if got := EvaluateRule(rule, []map[string]any{j}, nil); len(got) != 1 {
		t.Errorf("spine should fire on issue_comment + checkout + execute, got %d", len(got))
	}
}

func TestSpineRuleSilentOnBenignVariants(t *testing.T) {
	rule := loadSpineRule(t)

	type variant struct {
		name string
		mut  func(map[string]any)
	}
	variants := []variant{
		{
			"strong gate", func(j map[string]any) {
				j["if_conditions_summary"] = map[string]any{"gate_strength": "strong"}
			},
		},
		{
			"no pr-ref checkout", func(j map[string]any) {
				j["has_checkout_of_pr_ref"] = false
			},
		},
		{
			"no execution", func(j map[string]any) {
				j["executes_checked_out_code"] = false
			},
		},
		{
			"push trigger only", func(j map[string]any) {
				j["triggers"] = []any{"push"}
			},
		},
	}
	for _, v := range variants {
		j := prtJob()
		v.mut(j)
		matched := EvaluateRule(rule, []map[string]any{j}, func(err error) {
			t.Errorf("[%s] unexpected eval error: %v", v.name, err)
		})
		if len(matched) != 0 {
			t.Errorf("[%s] spine should stay silent, got %d matches", v.name, len(matched))
		}
	}
}

// A missing gate_strength is not "strong", so none_of passes and the rule fires.
func TestSpineRuleFiresWhenGateFieldMissing(t *testing.T) {
	rule := loadSpineRule(t)
	j := prtJob()
	delete(j, "if_conditions_summary")
	if got := EvaluateRule(rule, []map[string]any{j}, nil); len(got) != 1 {
		t.Errorf("missing gate field should not suppress the spine, got %d matches", len(got))
	}
}
