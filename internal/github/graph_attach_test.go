package github

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/pkg/finding"

	"github.com/praetorian-inc/trajan/internal/graph"
)

func attachFixture(t *testing.T, files map[string]any, findings []finding.Finding,
	targets map[string]graph.Target) (*nodeIndex, *edgeIndex, *graph.AttachResult) {
	t.Helper()
	dir := t.TempDir()
	for rel, v := range files {
		if err := engine.WriteJSON(filepath.Join(dir, engine.DirNormalize, filepath.FromSlash(rel)), v); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range findings {
		if err := engine.WriteJSON(filepath.Join(dir, engine.DirScan, "findings", f.Fingerprint+".json"), f); err != nil {
			t.Fatal(err)
		}
	}

	cfg := &engine.Config{Concurrency: 2}
	fail := func(e error) { t.Fatalf("load: %v", e) }
	src, err := graph.LoadCorpus(t.Context(), cfg, dir, []string{"chains/indices/"}, fail)
	if err != nil {
		t.Fatal(err)
	}
	c, err := indexCorpus(src)
	if err != nil {
		t.Fatal(err)
	}
	n, err := buildNodes(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	s, err := buildEdges(t.Context(), c, n)
	if err != nil {
		t.Fatal(err)
	}
	graph.BackfillObserved(n.NodeSet, s)
	loaded, _, err := engine.LoadFindings(t.Context(), cfg, dir, fail)
	if err != nil {
		t.Fatal(err)
	}
	a := newAttacher(c, n, s, targets)
	if err := a.run(t.Context(), loaded); err != nil {
		t.Fatal(err)
	}
	return n, s, a.res
}

func mkFinding(fp, rule, kind, subject string) finding.Finding {
	return finding.Finding{
		Fingerprint: fp, Severity: "high", Confidence: "high", Title: rule,
		Rule:    &finding.Rule{ID: rule},
		Subject: finding.Subject{Kind: kind, ID: subject},
	}
}

func mustTarget(t *testing.T, s string) graph.Target {
	t.Helper()
	tg, err := graph.ParseTarget(GraphProvider(), s)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

// fr-05-02 pairs an upstream test job with a downstream publish job over workflow_run.
// attack() names no endpoint side, and the victim is the downstream job — it runs the
// PR code. Its two trigger-class lists differ and both must survive onto the edge.
func TestAttackEdgeVictimizesTheDownstreamJob(t *testing.T) {
	const repo = "fr-05-02-checkout-head-sha-execute"
	up := map[string]any{
		"_id": repo + "__upstream__test", "repo": repo,
		"workflow_filename": "upstream.yml", "job_id": "test",
		"trigger_class_summary": map[string]any{"low_trust": []any{"pull_request"}, "medium": []any{}},
	}
	down := map[string]any{
		"_id": repo + "__downstream__publish", "repo": repo,
		"workflow_filename": "downstream.yml", "job_id": "publish",
		"trigger_class_summary": map[string]any{"low_trust": []any{}, "medium": []any{"workflow_run"}},
	}
	pairID := "wfrun__" + str(up["_id"]) + "__" + str(down["_id"])

	_, s, res := attachFixture(t,
		map[string]any{
			"org/ghektestorg.json":               map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
			"jobs/" + str(up["_id"]) + ".json":   up,
			"jobs/" + str(down["_id"]) + ".json": down,
			"chains/trigger-channels.json": map[string]any{
				"chain": "trigger-channels",
				"workflow_run_pairs": []any{map[string]any{
					"_id": pairID, "upstream": up, "downstream": down,
					"event_types": []any{"completed"},
				}},
			},
		},
		[]finding.Finding{mkFinding("aaaa", "cat-05/workflow-run-checkout-execute", "chain", pairID)},
		map[string]graph.Target{"cat-05/workflow-run-checkout-execute": mustTarget(t, "attack(PWN_REQUEST)")},
	)

	got := edgesOfType(s, PwnRequest)
	if len(got) != 1 {
		t.Fatalf("got %d PWN_REQUEST edges, want 1", len(got))
	}
	wantTo := jobEndpointFor(repo, "downstream.yml", "publish")
	if got[0].To != wantTo {
		t.Errorf("victim = %q, want the downstream job %q", got[0].To, wantTo)
	}
	if got[0].From != graphNodeID(ExternalActor, map[string]string{"kind": "external"}) {
		t.Errorf("from = %q, want the ExternalActor singleton", got[0].From)
	}
	if want := []any{}; !reflect.DeepEqual(got[0].Properties["trigger_classes_low_trust"], want) {
		t.Errorf("trigger_classes_low_trust = %v, want %v: the victim has no low-trust trigger",
			got[0].Properties["trigger_classes_low_trust"], want)
	}
	if want := []any{"workflow_run"}; !reflect.DeepEqual(got[0].Properties["trigger_classes_medium"], want) {
		t.Errorf("trigger_classes_medium = %v, want %v", got[0].Properties["trigger_classes_medium"], want)
	}
	if res.Attached != 1 || len(res.Unattached) != 0 {
		t.Errorf("attached=%d unattached=%d, want 1/0", res.Attached, len(res.Unattached))
	}
}

func jobEndpointFor(repo, workflow, jobID string) string {
	return graphNodeID(Job, map[string]string{
		"repo": "ghektestorg/" + repo, "workflow": ".github/workflows/" + workflow, "job_id": jobID,
	})
}

// A chain subject.id is a slugged composite: BranchSlug turns "release/1.0" into
// "release__1.0" and "__" is also the field separator, so the id cannot be parsed.
// fr-11-05's "sandbox-x" and "sandbox/x" must stay distinct under lookup.
func TestChainBranchAnchorNeverParsesTheSubjectID(t *testing.T) {
	rows := []any{}
	want := map[string]string{}
	for _, tc := range []struct{ repo, branch, id string }{
		{"fr-11-02-protection", "release/1.0", "fr-11-02-protection__release__1.0"},
		{"fr-11-05-islands", "sandbox-x", "fr-11-05-islands__sandbox-x"},
		{"fr-11-05-islands", "sandbox/x", "fr-11-05-islands__sandbox__x"},
	} {
		rows = append(rows, map[string]any{"_id": tc.id, "repo": tc.repo, "branch": tc.branch})
		want[tc.id] = graphNodeID(Branch, map[string]string{"repo": "ghektestorg/" + tc.repo, "name": tc.branch})
	}

	findings := []finding.Finding{}
	for id := range want {
		findings = append(findings, mkFinding("fp"+id, "cat-11/ruleset-no-deletion-restriction", "chain", id))
	}

	n, _, res := attachFixture(t,
		map[string]any{
			"org/ghektestorg.json": map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
			"chains/effective-ruleset.json": map[string]any{
				"chain": "effective-ruleset", "effective_per_branch": rows,
			},
		},
		findings,
		map[string]graph.Target{"cat-11/ruleset-no-deletion-restriction": mustTarget(t, "node(Branch)")},
	)

	if res.Attached != len(want) {
		t.Fatalf("attached %d of %d: %+v", res.Attached, len(want), res.Unattached)
	}
	for id, nodeID := range want {
		nd := n.Get(nodeID)
		if nd == nil {
			t.Fatalf("no Branch node %q", nodeID)
		}
		if len(nd.Findings) != 1 || nd.Findings[0].SubjectID != id {
			t.Errorf("branch %q carries %v, want the finding for %q", nodeID, nd.Findings, id)
		}
	}
}

// edge(READS, Job, Secret) fans over the job's secret reads and must ignore the
// artifact reads that share the READS type.
func TestEdgeTargetFiltersOnEndpointLabels(t *testing.T) {
	const repo = "fr-02-04-org-secret-visible-to-all"
	job := map[string]any{
		"_id": repo + "__main__build", "repo": repo,
		"workflow_filename": "main.yml", "job_id": "build",
		"secrets_referenced": []any{map[string]any{"name": "NPM_TOKEN", "scope": "repo", "scope_key": repo}},
		"artifact_reads":     []any{map[string]any{"name": "dist"}},
	}

	_, s, res := attachFixture(t,
		map[string]any{
			"org/ghektestorg.json":    map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
			"repos/" + repo + ".json": map[string]any{"_id": repo, "repo": repo},
			"secrets/" + repo + "__actions__NPM_TOKEN.json": map[string]any{
				"_id": repo + "__actions__NPM_TOKEN", "scope": "repo",
				"scope_key": repo, "repo": repo, "name": "NPM_TOKEN",
			},
			"jobs/" + str(job["_id"]) + ".json": job,
		},
		[]finding.Finding{mkFinding("bbbb", "cat-02/secret-isolation-repo-secret-any-push", "job", str(job["_id"]))},
		map[string]graph.Target{"cat-02/secret-isolation-repo-secret-any-push": mustTarget(t, "edge(READS, Job, Secret)")},
	)

	if res.Attached != 1 {
		t.Fatalf("attached=%d, unattached=%+v", res.Attached, res.Unattached)
	}
	for _, e := range edgesOfType(s, Reads) {
		want := 0
		if e.ToLabel == Secret {
			want = 1
		}
		if len(e.Findings) != want {
			t.Errorf("READS -> %s carries %d findings, want %d", e.ToLabel, len(e.Findings), want)
		}
	}
}

// A finding that cannot be attached is counted and described, never dropped.
func TestUnattachedFindingsAreRegistered(t *testing.T) {
	const repo = "fr-07-01-fork-pr-on-non-ephemeral-runner"
	job := map[string]any{
		"_id": repo + "__main__build", "repo": repo,
		"workflow_filename": "main.yml", "job_id": "build",
		"self_hosted": true, "runner_labels": []any{"self-hosted", "linux"},
	}

	_, _, res := attachFixture(t,
		map[string]any{
			"org/ghektestorg.json":              map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
			"jobs/" + str(job["_id"]) + ".json": job,
		},
		[]finding.Finding{
			mkFinding("cccc", "cat-07/self-hosted-non-ephemeral", "job", str(job["_id"])),
			mkFinding("dddd", "cat-99/retired-rule", "job", str(job["_id"])),
			mkFinding("eeee", "cat-07/self-hosted-non-ephemeral", "job", "no-such-job"),
		},
		map[string]graph.Target{"cat-07/self-hosted-non-ephemeral": mustTarget(t, "edge(RUNS_ON, Job, Runner)")},
	)

	if res.Total != 3 || res.Attached != 0 || len(res.Unattached) != 3 {
		t.Fatalf("total=%d attached=%d unattached=%d, want 3/0/3", res.Total, res.Attached, len(res.Unattached))
	}
	want := map[string]int{
		graph.ReasonEndpointUnresolved: 1,
		graph.ReasonNoTarget:           1,
		graph.ReasonSubjectUnresolved:  1,
	}
	for reason, n := range want {
		if res.ByReason[reason] != n {
			t.Errorf("byReason[%s] = %d, want %d (all: %v)", reason, res.ByReason[reason], n, res.ByReason)
		}
	}
	for _, r := range unattachedReasons {
		if _, listed := res.ByReason[r]; !listed {
			t.Errorf("reason %q missing: every code must be reported, including zeros", r)
		}
	}
	for _, u := range res.Unattached {
		if u.SubjectID == "" || u.Detail == "" {
			t.Errorf("unattached entry is not auditable: %+v", u)
		}
	}
}
