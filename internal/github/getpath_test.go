package github

import (
	"reflect"
	"testing"
)

func TestGetPathDictDescentAndMisses(t *testing.T) {
	subj := map[string]any{
		"if_conditions_summary": map[string]any{
			"gate_strength": "strong",
		},
		"repo": "fr-01",
	}
	cases := []struct {
		path string
		want any
	}{
		{"repo", "fr-01"},
		{"if_conditions_summary.gate_strength", "strong"},
		{"missing", nil},
		{"if_conditions_summary.absent", nil},
		{"if_conditions_summary.gate_strength.x", nil}, // descending past a scalar -> nil
		{"missing.deeper.deeper", nil},                 // nil mid-walk short-circuits
	}
	for _, c := range cases {
		if got := getPath(subj, c.path); !reflect.DeepEqual(got, c.want) {
			t.Errorf("getPath(%q) = %#v, want %#v", c.path, got, c.want)
		}
	}
}

func TestGetPathNumericListIndex(t *testing.T) {
	subj := map[string]any{
		"triggers": []any{"pull_request_target", "push"},
	}
	if got := getPath(subj, "triggers.0"); got != "pull_request_target" {
		t.Errorf("triggers.0 = %#v, want %q", got, "pull_request_target")
	}
	if got := getPath(subj, "triggers.1"); got != "push" {
		t.Errorf("triggers.1 = %#v, want %q", got, "push")
	}
	// Out-of-range index returns nil, not a panic.
	if got := getPath(subj, "triggers.5"); got != nil {
		t.Errorf("triggers.5 = %#v, want nil", got)
	}
}

// steps.uses must project each step's `uses` value, not index into the steps list.
func TestGetPathListProjectionStepsUses(t *testing.T) {
	subj := map[string]any{
		"steps": []any{
			map[string]any{"uses": "actions/checkout@v4", "name": "co"},
			map[string]any{"uses": "actions/setup-node@v4"},
			map[string]any{"run": "make build"}, // no `uses` key -> nil for this element
		},
	}
	got := getPath(subj, "steps.uses")
	want := []any{"actions/checkout@v4", "actions/setup-node@v4", nil}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("steps.uses = %#v, want %#v", got, want)
	}
}

// A non-map element projects to nil, and projection consumes all remaining segments at once.
func TestGetPathProjectionNestedAndNonMapElement(t *testing.T) {
	subj := map[string]any{
		"reviewers_required": []any{
			map[string]any{"login": "alice"},
			map[string]any{"login": "dependabot[bot]"},
			"not-a-map",
		},
	}
	got := getPath(subj, "reviewers_required.login")
	want := []any{"alice", "dependabot[bot]", nil}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reviewers_required.login = %#v, want %#v", got, want)
	}
}

func TestGetPathProjectionMultiSegment(t *testing.T) {
	subj := map[string]any{
		"links": []any{
			map[string]any{"meta": map[string]any{"score": float64(3)}},
			map[string]any{"meta": map[string]any{"score": float64(7)}},
			map[string]any{"meta": "scalar"},
			map[string]any{},
		},
	}
	got := getPath(subj, "links.meta.score")
	want := []any{float64(3), float64(7), nil, nil}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("links.meta.score = %#v, want %#v", got, want)
	}
}

func TestGetPathTopLevelListProjection(t *testing.T) {
	subj := []any{
		map[string]any{"x": 1},
		map[string]any{"x": 2},
	}
	got := getPath(subj, "x")
	want := []any{1, 2}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("top-level x projection = %#v, want %#v", got, want)
	}
}

func TestGetPathNilSubjectAndEmptySegment(t *testing.T) {
	if got := getPath(nil, "a.b"); got != nil {
		t.Errorf("getPath(nil, ...) = %#v, want nil", got)
	}
	// An empty path splits to a single "" segment, a missing key on the dict -> nil.
	if got := getPath(map[string]any{"a": 1}, ""); got != nil {
		t.Errorf("getPath(dict, \"\") = %#v, want nil (empty key miss)", got)
	}
}
