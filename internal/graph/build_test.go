package graph

import (
	"maps"
	"testing"
)

// backfillObserved rebuilds an endpoint's identity from its node id, so the
// inverse must recover exactly what nodeID escaped — including values that
// contain the separator itself.
func TestParseNodeIDInvertsNodeID(t *testing.T) {
	for _, key := range []map[string]string{
		{"repo": "ghektestorg/conf-ci", "name": "main"},
		{"repo": "ghektestorg/fr-11-05", "name": "sandbox/y/z"},
		{"repo": "o/x", "name": `a|b`},
		{"repo": `o/x|a`, "name": "b"},
		{"repo": `o\x`, "name": `\|b`},
	} {
		label, got, ok := parseNodeID(nodeID(Branch, key))
		if !ok {
			t.Fatalf("%v: not parseable", key)
		}
		if label != Branch || !maps.Equal(got, key) {
			t.Errorf("round trip of %v gave %s %v", key, label, got)
		}
	}

	if _, _, ok := parseNodeID("Branch|only-one-value"); ok {
		t.Error("a tuple of the wrong arity must not parse")
	}
	if _, _, ok := parseNodeID("NotALabel|a|b"); ok {
		t.Error("an unknown label must not parse")
	}
}

// A reusable workflow in an uncollected repo has a complete identity and no
// backing record: it is emitted as observed_only rather than dropped, and the
// dangling sweep then finds nothing.
func TestBackfillEmitsIdentifiedEndpointsWithoutRecords(t *testing.T) {
	c, n := fixture(t, map[string]any{
		"org/ghektestorg.json": map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
		"repos/conf-web.json":  map[string]any{"_id": "conf-web", "repo": "conf-web"},
		"jobs/conf-web__pr-check__integration.json": map[string]any{
			"_id": "conf-web__pr-check__integration", "repo": "conf-web",
			"workflow_filename": "pr-check.yml", "job_id": "integration",
		},
		"chains/reusable-callgraph.json": map[string]any{
			"chain": "reusable-callgraph",
			"edges": []any{map[string]any{
				"_id":    "conf-web__pr-check__integration__calls__?",
				"caller": map[string]any{"repo": "conf-web", "workflow_filename": "pr-check.yml", "job_id": "integration"},
				"callee": map[string]any{"repo": "shared-ci", "path": ".github/workflows/build.yml", "is_local": false},
			}},
		},
	})

	s, err := buildEdges(t.Context(), c, n)
	if err != nil {
		t.Fatal(err)
	}
	callee := nodeID(Workflow, map[string]string{"repo": "ghektestorg/shared-ci", "path": ".github/workflows/build.yml"})
	if n.has(callee) {
		t.Fatal("the callee must not exist before the backfill")
	}
	if minted := backfillObserved(n, s); minted != 1 {
		t.Fatalf("minted %d nodes, want 1", minted)
	}

	got := n.get(callee)
	if got == nil {
		t.Fatal("the callee workflow was not emitted")
	}
	if got.Properties["observed_only"] != true {
		t.Errorf("observed_only = %v, want true", got.Properties["observed_only"])
	}
	// The callee's repository was never observed, so it must stay parentless
	// rather than drag in a synthesized Repository.
	if n.has(nodeID(Repository, map[string]string{"full_name": "ghektestorg/shared-ci"})) {
		t.Error("a Repository node was invented for an uncollected repo")
	}
	if dropped := dropDangling(n, s); len(dropped) != 0 {
		t.Errorf("dropped_dangling = %v, want empty after the backfill", dropped)
	}
}

// info has no bucket, buckets carry deduplicated rule ids, and an empty bucket
// is omitted rather than written as [].
func TestFinalizeFindingsBucketsBySeverity(t *testing.T) {
	props := map[string]any{}
	fs := finalizeFindings([]findingRef{
		{RuleID: "b/low", Severity: "low", Confidence: "low", Fingerprint: "2"},
		{RuleID: "a/high", Severity: "high", Confidence: "medium", Fingerprint: "3"},
		{RuleID: "a/high", Severity: "high", Confidence: "high", Fingerprint: "1"},
		{RuleID: "c/info", Severity: "info", Confidence: "high", Fingerprint: "4"},
	}, props)

	if got := []string{fs[0].Fingerprint, fs[1].Fingerprint, fs[2].Fingerprint, fs[3].Fingerprint}; got[0] != "1" || got[1] != "3" || got[2] != "2" || got[3] != "4" {
		t.Errorf("order = %v, want severity then confidence descending", got)
	}
	if props["findings_count"] != 4 {
		t.Errorf("findings_count = %v, want 4 including the info finding", props["findings_count"])
	}
	if got, ok := props[FindingsHigh].([]string); !ok || len(got) != 1 || got[0] != "a/high" {
		t.Errorf("%s = %v, want one deduplicated rule id", FindingsHigh, props[FindingsHigh])
	}
	if _, present := props[FindingsCritical]; present {
		t.Errorf("%s must be omitted when empty", FindingsCritical)
	}
}
