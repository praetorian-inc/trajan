package ado

import (
	"encoding/json"
	"reflect"
	"testing"
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
