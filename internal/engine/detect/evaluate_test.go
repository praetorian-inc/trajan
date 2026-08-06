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
