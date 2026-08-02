package graph

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func fixture(t *testing.T, files map[string]any) (*corpus, *nodeSet) {
	t.Helper()
	dir := t.TempDir()
	for rel, v := range files {
		if err := engine.WriteJSON(filepath.Join(dir, normalizeDir, filepath.FromSlash(rel)), v); err != nil {
			t.Fatal(err)
		}
	}
	c, err := loadCorpus(t.Context(), &engine.Config{Concurrency: 2}, dir, func(e error) { t.Fatalf("load: %v", e) })
	if err != nil {
		t.Fatal(err)
	}
	n, err := buildNodes(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	return c, n
}

func build(t *testing.T, files map[string]any) *edgeSet {
	t.Helper()
	c, n := fixture(t, files)
	s, err := buildEdges(t.Context(), c, n)
	if err != nil {
		t.Fatalf("buildEdges: %v", err)
	}
	return s
}

func edgesOfType(s *edgeSet, want EdgeType) []edge {
	out := []edge{}
	for _, e := range s.all() {
		if e.Type == want {
			out = append(out, e)
		}
	}
	return out
}

// A branch literally named "a|b" must not forge an identity boundary against a
// branch "b" in a repo named "x/a", and the same must hold one level up where
// edgeID escapes node ids a second time.
func TestIDsAreInjectiveAcrossSeparators(t *testing.T) {
	left := nd(Branch, "repo", "o/x", "name", `a|b`)
	right := nd(Branch, "repo", `o/x|a`, "name", "b")
	if left.id == right.id {
		t.Fatalf("distinct identities collided: %q", left.id)
	}

	esc1 := nd(Branch, "repo", "o/x", "name", `a\|b`)
	if esc1.id == left.id {
		t.Fatalf("backslash not escaped: %q collides with %q", esc1.id, left.id)
	}

	a := edgeID(ProtectedBy, left.id, "Ruleset|repo|1")
	b := edgeID(ProtectedBy, right.id, "Ruleset|repo|1")
	if a == b {
		t.Fatalf("distinct edges collided: %q", a)
	}
}

// fr-11-05 puts "sandbox-x", "sandbox/x" and "sandbox/y/z" on one repo. The
// chain carries true, unslugged branch names; BranchSlug is not injective, so
// resolving these by splitting a slugged _id would merge them.
func TestCanLandCodeKeepsSlashBearingBranchesDistinct(t *testing.T) {
	const repo = "fr-11-05-include-all-branches-with-exclusion-list-creates-trust-islan"
	branches := []string{"main", "sandbox-x", "sandbox/x", "sandbox/y/z"}
	rows := []any{}
	for _, b := range branches {
		rows = append(rows, map[string]any{
			"repo": repo, "branch": b,
			"principal_kind": "user", "principal_id": "user__ghektest", "principal_name": "ghektest",
			"permission": "admin", "write_via": "direct_collaborator",
			"is_admin": true, "is_default_branch": b == "main",
			"circumvents": []any{}, "routes_open": []any{"pull_request"}, "routes_blocked": []any{"direct_push"},
		})
	}

	s := build(t, map[string]any{
		"org/ghektestorg.json":           map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
		"principals/user__ghektest.json": map[string]any{"_id": "user__ghektest", "kind": "user", "login": "ghektest"},
		"chains/capability-edges.json":   map[string]any{"chain": "capability-edges", "edges": rows},
	})

	got := edgesOfType(s, CanLandCode)
	if len(got) != len(branches) {
		t.Fatalf("got %d CAN_LAND_CODE edges, want %d", len(got), len(branches))
	}
	seen := map[string]bool{}
	for _, e := range got {
		seen[e.To] = true
	}
	for _, b := range branches {
		want := nd(Branch, "repo", "ghektestorg/"+repo, "name", b).id
		if !seen[want] {
			t.Errorf("no CAN_LAND_CODE edge to branch %q", b)
		}
	}
}

// capability-edges names a deploy key by title; the fingerprint that identifies
// it exists only on the deploy-keys record principal_id points at. The three
// capability arrays must survive as arrays and serialize as [] when empty.
func TestCanLandCodeResolvesDeployKeyAndKeepsEmptyArrays(t *testing.T) {
	const repo = "fr-03-02-workflow-on-unprotected-branch"
	const fp = "SHA256:/5l4GKjJtw/8uGy78q+QRJYyAjbfLppVtwgVTig5SQ0"

	s := build(t, map[string]any{
		"org/ghektestorg.json": map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
		"deploy-keys/" + repo + "__159015069.json": map[string]any{
			"_id": repo + "__159015069", "repo": repo, "key_id": 159015069,
			"title": "trajan-fx-fr03-02-rw", "fingerprint": fp, "read_only": false, "can_push": true,
		},
		"chains/capability-edges.json": map[string]any{"chain": "capability-edges", "edges": []any{
			map[string]any{
				"repo": repo, "branch": "main",
				"principal_kind": "deploy_key",
				"principal_id":   repo + "__159015069",
				"principal_name": "trajan-fx-fr03-02-rw",
				"permission":     nil, "write_via": "deploy_key",
				"is_admin": false, "is_default_branch": true,
				"circumvents": []any{}, "routes_open": []any{}, "routes_blocked": []any{"direct_push", "pull_request"},
			},
		}},
	})

	got := edgesOfType(s, CanLandCode)
	if len(got) != 1 {
		t.Fatalf("got %d CAN_LAND_CODE edges, want 1", len(got))
	}
	if want := nd(DeployKey, "fingerprint", fp).id; got[0].From != want {
		t.Errorf("from = %q, want the fingerprint-keyed node %q", got[0].From, want)
	}

	b, err := json.Marshal(got[0].Properties)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"circumvents":[]`, `"routes_open":[]`, `"routes_blocked":["direct_push","pull_request"]`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("properties missing %s: %s", want, b)
		}
	}
}

// fr-11-02 deploys the same job definition from 7 branches. Job identity omits
// branch, so the 7 deploy records are one TARGETS edge; an environment named by
// a runtime expression has no identity and is counted, not invented.
func TestTargetsMergesBranchesAndCountsExpressionEnvironments(t *testing.T) {
	const repo = "fr-11-02-protection-targets-default-branch-only-but-deploy-fires-from"
	deploys := []any{}
	for _, b := range []string{"main", "deploy", "hotfix/a", "hotfix/b/c", "release/1.0", "release/2.0/hotfix", "releases/1.0"} {
		deploys = append(deploys, map[string]any{
			"_id": "deploy__" + repo + "__" + b, "env_name": "production", "env_record_present": true,
			"job": map[string]any{"repo": repo, "workflow_filename": "main.yml", "job_id": "deploy"},
		})
	}
	deploys = append(deploys, map[string]any{
		"_id": "deploy__other", "env_name": "${{ inputs.target }}", "env_record_present": false,
		"job": map[string]any{"repo": "fr-03-06", "workflow_filename": "release.yml", "job_id": "release"},
	})

	s := build(t, map[string]any{
		"org/ghektestorg.json":        map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
		"chains/env-deployments.json": map[string]any{"chain": "env-deployments", "deploys": deploys},
	})

	got := edgesOfType(s, Targets)
	if len(got) != 1 {
		t.Fatalf("got %d TARGETS edges, want 1 (7 branch variants of one job definition)", len(got))
	}
	if want := nd(Environment, "repo", "ghektestorg/"+repo, "name", "production").id; got[0].To != want {
		t.Errorf("to = %q, want %q", got[0].To, want)
	}
	if s.unbuilt[Targets] != 1 {
		t.Errorf("unbuilt[TARGETS] = %d, want 1 for the expression-named environment", s.unbuilt[Targets])
	}
}

func TestAddRejectsIllegalEndpointPair(t *testing.T) {
	s := newEdgeSet()
	s.add(Reads, nd(Job, "repo", "o/r", "workflow", "w", "job_id", "j"), nd(Repository, "full_name", "o/r"), nil)
	if len(s.byID) != 0 {
		t.Errorf("wrote an edge the schema forbids: %v", s.byID)
	}
	if s.illegal["READS{Job,Repository}"] != 1 {
		t.Errorf("illegal = %v, want READS{Job,Repository}:1", s.illegal)
	}
	if s.err() == nil {
		t.Error("err() = nil; an illegal endpoint pair is a contract violation and must abort the phase")
	}
}

func TestAddDropsIncompleteIdentity(t *testing.T) {
	s := newEdgeSet()
	from := nd(Job, "repo", "o/r", "workflow", "w", "job_id", "j")
	s.add(RunsOn, from, nd(Runner, "scope", "", "id", ""), nil)
	if len(s.byID) != 0 {
		t.Errorf("minted an edge to an unidentified endpoint: %v", s.byID)
	}
	if s.unbuilt[RunsOn] != 1 {
		t.Errorf("unbuilt[RUNS_ON] = %d, want 1", s.unbuilt[RunsOn])
	}
}
