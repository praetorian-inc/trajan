package graph

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
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
	if props["findings_count_high"] != 2 {
		t.Errorf("findings_count_high = %v, want 2 findings from the 1 deduplicated rule",
			props["findings_count_high"])
	}
	if _, present := props[FindingsCritical]; present {
		t.Errorf("%s must be omitted when empty", FindingsCritical)
	}
	if _, present := props["findings_count_critical"]; present {
		t.Error("findings_count_critical must be omitted alongside its empty bucket")
	}
}

// A subject like "RUNS_ON{Job,Runner|RunnerGroup}" names both declared pairs.
// Rows whose subject is not a relation (a label, a property, an identity key)
// name none.
func subjectTriples(subject string) []string {
	head, rest, ok := strings.Cut(subject, "{")
	if !ok {
		return nil
	}
	rest, ok = strings.CutSuffix(rest, "}")
	if !ok {
		return nil
	}
	from, to, ok := strings.Cut(rest, ",")
	if !ok {
		return nil
	}
	var out []string
	for _, f := range strings.Split(from, "|") {
		for _, t := range strings.Split(to, "|") {
			out = append(out, edgeKey(EdgeType(head), NodeLabel(f), NodeLabel(t)))
		}
	}
	return out
}

// A row naming a relation the schema does not declare is stale — the failure mode after
// a triple is deleted from edgeEndpoints. represented_elsewhere is the one legitimate
// case: it says the pair is undeclared because the fact lives on another edge.
func TestRegisterSubjectsNameDeclaredTriples(t *testing.T) {
	declared := map[string]bool{}
	for _, et := range EdgeTypes() {
		for _, p := range edgeEndpoints[et] {
			declared[edgeKey(et, p[0], p[1])] = true
		}
	}
	for _, row := range gapRegister {
		for _, tr := range subjectTriples(row.Subject) {
			if !declared[tr] && row.Status != "represented_elsewhere" {
				t.Errorf("row %q is %s and names %s, which edgeEndpoints does not declare",
					row.Subject, row.Status, tr)
			}
		}
	}
}

// findings_blocked sums byTarget per row, so a target claimed twice inflates the
// column past findings.unattached and stops it partitioning the unattached set.
func TestRegisterClaimsEachTargetOnce(t *testing.T) {
	by := map[string]string{}
	for _, row := range gapRegister {
		for _, tgt := range row.Targets {
			if _, err := ParseTarget(tgt); err != nil {
				t.Errorf("%s: target %q never matches a finding: %v", row.Subject, tgt, err)
			}
			if prev, dup := by[tgt]; dup {
				t.Errorf("%q is claimed by both %q and %q, so its findings are counted twice",
					tgt, prev, row.Subject)
			}
			by[tgt] = row.Subject
		}
	}
}

// No register row may report a label or edge type absent that this same run builds.
// fr-06-01 is the oracle: a job assuming an AWS role through OIDC must reach the graph
// as a CloudRole and a CAN_ASSUME edge.
func TestRegisterDoesNotDisclaimWhatTheRunBuilds(t *testing.T) {
	c, n := fixture(t, map[string]any{
		"org/ghektestorg.json": map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
		"repos/fr-06-01-aws-org-wildcard-sub.json": map[string]any{
			"_id": "fr-06-01-aws-org-wildcard-sub", "repo": "fr-06-01-aws-org-wildcard-sub",
		},
		"jobs/fr-06-01-aws-org-wildcard-sub__main__pwn.json": map[string]any{
			"_id": "fr-06-01-aws-org-wildcard-sub__main__pwn", "repo": "fr-06-01-aws-org-wildcard-sub",
			"workflow_filename": "main.yml", "job_id": "pwn", "branch": "main",
			"oidc_sub_template": "repo:<owner>/<repo>:ref:<ref>",
			"cloud_roles": []any{map[string]any{
				"provider": "aws", "identifier": "arn:aws:iam::000000000000:role/fr-06-01-role",
			}},
		},
	})
	s, err := buildEdges(t.Context(), c, n)
	if err != nil {
		t.Fatal(err)
	}
	sum := summarize(t.TempDir(), inputsSummary{}, n.all(), s.all(), s, n, 0, nil, &attachResult{})

	if sum.Nodes.ByLabel[CloudRole] == 0 || sum.Edges.ByType[CanAssume] == 0 {
		t.Fatalf("the oracle never reached the graph: CloudRole=%d CAN_ASSUME=%d",
			sum.Nodes.ByLabel[CloudRole], sum.Edges.ByType[CanAssume])
	}
	for _, row := range sum.Gaps.Register {
		if row.Status != "empty" && row.Status != "not_collected" {
			continue
		}
		head, _, _ := strings.Cut(row.Subject, "{")
		if got := sum.Nodes.ByLabel[NodeLabel(head)]; got > 0 {
			t.Errorf("row %q reports %s, but the run built %d %s nodes", row.Subject, row.Status, got, head)
		}
		if got := sum.Edges.ByType[EdgeType(head)]; got > 0 {
			t.Errorf("row %q reports %s, but the run built %d %s edges", row.Subject, row.Status, got, head)
		}
	}
}

func runDirWith(t *testing.T, files map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	for rel, v := range files {
		if err := engine.WriteJSON(filepath.Join(dir, filepath.FromSlash(rel)), v); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func readSummary(t *testing.T, runDir string) summary {
	t.Helper()
	var s summary
	if err := engine.ReadJSON(filepath.Join(runDir, engine.GraphSummary()), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func buildInto(t *testing.T, runDir string) error {
	t.Helper()
	timer := engine.StartPhaseTimer(engine.PhaseGraph, "graph")
	return runBuild(t.Context(), &engine.Config{Concurrency: 2}, runDir, nil, timer)
}

// A record that fails to parse is dropped and the phase continues, so the count of what
// was offered has to reach the summary: without it a graph built on part of its inputs
// is indistinguishable from a complete one.
func TestBuildReportsDroppedInputs(t *testing.T) {
	dir := runDirWith(t, map[string]any{
		normalizeDir + "/org/ghektestorg.json": map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
		normalizeDir + "/repos/conf-ci.json":   map[string]any{"_id": "conf-ci", "repo": "conf-ci"},
		scanDir + "/findings/aaaa.json":        mkFinding("aaaa", "cat-01/x", "repo", "conf-ci"),
	})
	for _, rel := range []string{normalizeDir + "/repos/broken.json", scanDir + "/findings/bbbb.json"} {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(rel)), []byte("{not json"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := buildInto(t, dir); err != nil {
		t.Fatalf("a dropped record must not fail the phase: %v", err)
	}
	got := readSummary(t, dir).Inputs
	want := inputsSummary{NormalizeSeen: 3, NormalizeDropped: 1, FindingsSeen: 2, FindingsDropped: 1}
	if got != want {
		t.Errorf("inputs = %+v, want %+v", got, want)
	}
}

// Every consumer of 30-graph reads a directory that is either the current build
// or the last good one. A phase that cannot read its inputs must leave the last
// good one alone, and must not present an unscanned run as a clean one.
func TestBuildKeepsThePriorGraphWhenInputsAreUnreadable(t *testing.T) {
	dir := runDirWith(t, map[string]any{
		normalizeDir + "/org/ghektestorg.json": map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
		normalizeDir + "/repos/conf-ci.json":   map[string]any{"_id": "conf-ci", "repo": "conf-ci"},
	})

	if err := buildInto(t, dir); err == nil {
		t.Fatal("a run with no 20-scan must fail rather than report zero findings")
	}
	if _, err := os.Stat(filepath.Join(dir, graphDir)); !os.IsNotExist(err) {
		t.Fatalf("a failed build wrote %s: %v", graphDir, err)
	}

	if err := engine.WriteJSON(filepath.Join(dir, scanDir, "findings", "aaaa.json"),
		mkFinding("aaaa", "cat-01/x", "repo", "conf-ci")); err != nil {
		t.Fatal(err)
	}
	if err := buildInto(t, dir); err != nil {
		t.Fatal(err)
	}
	good := readSummary(t, dir)

	if err := os.RemoveAll(filepath.Join(dir, normalizeDir)); err != nil {
		t.Fatal(err)
	}
	if err := buildInto(t, dir); err == nil {
		t.Fatal("a run with no 10-normalize must fail")
	}
	if _, err := os.Stat(filepath.Join(dir, engine.GraphSummary())); err != nil {
		t.Fatalf("the failed build destroyed the last good graph: %v", err)
	}
	if got := readSummary(t, dir); got.Nodes.Total != good.Nodes.Total {
		t.Errorf("the failed build replaced the good graph: nodes %d -> %d", good.Nodes.Total, got.Nodes.Total)
	}
}
