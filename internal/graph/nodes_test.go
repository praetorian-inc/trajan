package graph

import (
	"encoding/json"
	"reflect"
	"testing"
)

// A node id is split on unescaped '|', so distinct identity tuples must never
// collide however the values are punctuated.
func TestNodeIDInjective(t *testing.T) {
	tuples := [][2]string{
		{"a", "b"},
		{"a|b", "c"},
		{"a", "b|c"},
		{`a\`, "b"},
		{"a", `\b`},
		{`a\|b`, "c"},
		{"a", `\|b|c`},
		{"ghektestorg/fr-11-05", "sandbox-x"},
		{"ghektestorg/fr-11-05", "sandbox/x"},
	}
	seen := map[string][2]string{}
	for _, tp := range tuples {
		id := nodeID(Branch, map[string]string{"repo": tp[0], "name": tp[1]})
		if prev, dup := seen[id]; dup {
			t.Fatalf("collision %q: %v and %v", id, prev, tp)
		}
		seen[id] = tp
		if again := nodeID(Branch, map[string]string{"repo": tp[0], "name": tp[1]}); again != id {
			t.Fatalf("unstable id for %v: %q then %q", tp, id, again)
		}
	}
}

// fr-11-02 collapses 7 branch-scoped job records onto one job definition: the
// branch set must survive, the default-branch flag must OR, and the differing
// per-branch scalar must be counted rather than hidden.
func TestUpsertMergesBranchScopedJobs(t *testing.T) {
	s := newNodeSet()
	key := map[string]string{
		"repo":     "ghektestorg/fr-11-02",
		"workflow": ".github/workflows/main.yml",
		"job_id":   "deploy",
	}
	branches := []string{"main", "release/1.0", "hotfix/a"}
	for i, b := range branches {
		s.upsert(Job, key, map[string]any{
			"branches":              []any{b},
			"is_default_branch_any": i == 0,
			"branch":                b,
			"workflow_name":         "Deploy",
			"triggers":              []any{"push"},
		}, "jobs/fr-11-02__"+b+".json")
	}

	if got := len(s.byID); got != 1 {
		t.Fatalf("want 1 node, got %d", got)
	}
	n := s.get(nodeID(Job, key))
	if want := []any{"hotfix/a", "main", "release/1.0"}; !reflect.DeepEqual(n.Properties["branches"], want) {
		t.Errorf("branches = %v, want %v", n.Properties["branches"], want)
	}
	if n.Properties["is_default_branch_any"] != true {
		t.Error("is_default_branch_any must OR across merged records")
	}
	if n.Properties["branch"] != "main" {
		t.Errorf("branch = %v, want first writer main", n.Properties["branch"])
	}
	if got := s.conflicts[conflictKey{Job, "branch"}]; got != 2 {
		t.Errorf("discarded branch scalars = %d, want 2", got)
	}
	if _, dup := s.conflicts[conflictKey{Job, "workflow_name"}]; dup {
		t.Error("identical scalars must not count as conflicts")
	}
	if want := []any{"push"}; !reflect.DeepEqual(n.Properties["triggers"], want) {
		t.Errorf("triggers = %v, want deduplicated %v", n.Properties["triggers"], want)
	}
	if got := len(n.Properties["_source"].([]any)); got != 3 {
		t.Errorf("_source has %d entries, want 3", got)
	}
	if m := s.merges(); len(m) != 1 || m[0].SourceRecords != 3 || m[0].Nodes != 1 || m[0].MergedRecords != 2 {
		t.Errorf("merges = %+v", m)
	}
}

// An invented identity value is an invented path, so an incomplete tuple mints
// nothing and is counted.
func TestUpsertDropsIncompleteIdentity(t *testing.T) {
	s := newNodeSet()
	if n := s.upsert(Runner, map[string]string{"scope": "ghektestorg"}, nil, "x"); n != nil {
		t.Fatal("upsert with an empty identity value must return nil")
	}
	if len(s.byID) != 0 {
		t.Fatal("no node may be emitted")
	}
	if s.incompleteIdentities()[Runner] != 1 {
		t.Fatal("the dropped candidate must be counted")
	}
}

func TestRecordPropsFilter(t *testing.T) {
	var fields map[string]any
	if err := json.Unmarshal([]byte(`{
		"_id": "x", "_provenance": {"a": 1},
		"repo": "conf-ci", "name": "main",
		"count": 2, "flag": true, "missing": null,
		"labels": ["ubuntu-latest"],
		"steps": [{"uses": "actions/checkout@v4"}],
		"mixed": ["a", 1],
		"holes": ["a", null],
		"empty": []
	}`), &fields); err != nil {
		t.Fatal(err)
	}
	got := recordProps(Branch, fields)
	want := []string{"count", "flag", "missing", "labels", "empty"}
	if len(got) != len(want) {
		t.Fatalf("kept %v, want exactly %v", got, want)
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("%q was dropped", k)
		}
	}
}
