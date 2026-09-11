package ado

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func TestScalarArrayWidensMixedNumbers(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []any
		want any
	}{
		{"ints stay ints", []any{json.Number("1"), json.Number("2")}, []int64{1, 2}},
		{"a float widens the whole array", []any{json.Number("1.5"), json.Number("2")}, []float64{1.5, 2}},
		{"a leading whole float does not force ints", []any{json.Number("2"), json.Number("1.5")}, []float64{2, 1.5}},
		{"strings stay strings", []any{"a", "b"}, []string{"a", "b"}},
		{"bools stay bools", []any{true, false}, []bool{true, false}},
		{"empty is an empty string array", []any{}, []string{}},
	} {
		if got := scalarArray(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %#v, want %#v", tc.name, got, tc.want)
		}
	}
}

// A heterogeneous array has no Neo4j collection type, so it degrades to JSON strings
// rather than losing elements.
func TestScalarArrayFallsBackForMixedKinds(t *testing.T) {
	got := scalarArray([]any{json.Number("1"), "a"})
	if want := []string{"1", "\"a\""}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

// SET n += {k: null} removes the key, so a finding that no longer fires must be written
// as null or the remediated rule id survives in Neo4j forever.
func TestScalarPropsClearsStaleFindingProperties(t *testing.T) {
	props := scalarProps(map[string]any{"name": "x"}, nil, "Job|o|p|1|s|j", &engine.State{})
	for _, k := range findingProps() {
		v, present := props[k]
		if !present {
			t.Errorf("%s must be written on every push", k)
			continue
		}
		if v != nil {
			t.Errorf("%s should be null when the run has no findings, got %v", k, v)
		}
	}

	withFinding := scalarProps(map[string]any{"findings_high": []any{"cat-01/x"}, "findings_count_high": json.Number("1")},
		[]findingRef{{RuleID: "cat-01/x", Fingerprint: "abc", Severity: "high"}}, "id", &engine.State{})
	if got := withFinding["finding_rule_ids"]; !reflect.DeepEqual(got, []string{"cat-01/x"}) {
		t.Errorf("finding_rule_ids = %#v", got)
	}
	if withFinding["findings_high"] == nil {
		t.Error("a bucket the run did populate must not be nulled")
	}
}
