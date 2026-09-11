package ado

import (
	"encoding/json"
	"io"
	"log/slog"
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
		{"an int past 2^53 keeps its value rather than widening",
			[]any{json.Number("9007199254740993"), json.Number("1.5")},
			[]string{"9007199254740993", "1.5"}},
		{"an exact-range int still widens",
			[]any{json.Number("9007199254740992"), json.Number("1.5")},
			[]float64{9007199254740992, 1.5}},
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

func TestWarnCleartextOnlyForRemoteUnencrypted(t *testing.T) {
	var seen []string
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelWarn,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == "url" {
				seen = append(seen, a.Value.String())
			}
			return a
		},
	})))
	defer slog.SetDefault(prev)

	for _, tc := range []struct {
		url, pass string
		warn      bool
	}{
		{"bolt://localhost:7687", "pw", false},
		{"bolt://127.0.0.1:7687", "pw", false},
		{"neo4j://[::1]:7687", "pw", false},
		{"bolt+s://graph.internal:7687", "pw", false},
		{"neo4j+ssc://graph.internal:7687", "pw", false},
		{"bolt://graph.internal:7687", "", false},
		{"bolt://graph.internal:7687", "pw", true},
		{"neo4j://10.0.0.5:7687", "pw", true},
	} {
		before := len(seen)
		warnCleartext(tc.url, tc.pass)
		if got := len(seen) > before; got != tc.warn {
			t.Errorf("%s (pass=%q): warned=%v, want %v", tc.url, tc.pass, got, tc.warn)
		}
	}
}
