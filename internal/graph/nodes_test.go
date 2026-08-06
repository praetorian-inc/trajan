package graph

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
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
// branch set must survive, the default-branch flag must OR, and a scalar that
// differs between the branches must be counted rather than hidden.
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
			"token_source":          []string{"job", "repo_default", "repo_default"}[i],
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
	if got := s.conflicts[conflictKey{Job, "token_source"}]; got != 2 {
		t.Errorf("discarded token_source scalars = %d, want 2", got)
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

// A Neo4j property is a scalar or a homogeneous null-free array of scalars. Legality is
// per value, so an array of objects passes whenever it is empty; the key must be
// registered, not merely skipped, or the property survives only where it says nothing.
func TestRecordPropsRegistersIllegalKeys(t *testing.T) {
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
	s := newNodeSet()
	got := s.recordProps(Branch, fields)

	want := []string{"count", "flag", "missing", "labels", "empty"}
	if len(got) != len(want) {
		t.Fatalf("kept %v, want exactly %v", got, want)
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("%q was dropped", k)
		}
		if s.illegal[conflictKey{Branch, k}] {
			t.Errorf("%q is storable and must not be registered", k)
		}
	}
	for _, k := range []string{"steps", "mixed", "holes"} {
		if !s.illegal[conflictKey{Branch, k}] {
			t.Errorf("%q was skipped without registering the key for the sweep", k)
		}
	}
	for _, k := range []string{"_id", "_provenance", "repo", "name"} {
		if s.illegal[conflictKey{Branch, k}] {
			t.Errorf("%q is excluded by name, not by shape", k)
		}
	}
}

// fr-11-02's ruleset gates its default branch on "ci/build"; fr-11-03's carries none.
// required_status_checks is an array of objects, storable exactly when empty, so only the
// ruleset requiring nothing keeps it — the check name has to be projected out instead.
func TestRulesetStatusChecksAreProjectedNotInverted(t *testing.T) {
	_, n := fixture(t, map[string]any{
		"org/ghektestorg.json": map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
		"rulesets/gated.json": map[string]any{
			"_id": "gated", "scope": "repo", "owner": "ghektestorg",
			"repo":       "fr-11-02-protection-targets-default-branch-only-but-deploy-fires-from",
			"ruleset_id": 20204729, "name": "trajan-fx-fr11-02-default-only",
			"enforcement": "active", "rule_types": []any{"pull_request", "required_status_checks"},
			"required_status_checks": []any{map[string]any{"context": "ci/build"}},
		},
		"rulesets/decorative.json": map[string]any{
			"_id": "decorative", "scope": "repo", "owner": "ghektestorg",
			"repo":       "fr-11-03-required-status-check-name-is-attacker-creatable",
			"ruleset_id": 20204724, "name": "trajan-fx-fr11-03-decorative-status-check",
			"enforcement": "active", "rule_types": []any{"pull_request"},
			"required_status_checks": nil,
		},
	})

	for _, tc := range []struct {
		id       string
		repo     string
		contexts []any
	}{
		{"20204729", "ghektestorg/fr-11-02-protection-targets-default-branch-only-but-deploy-fires-from", []any{"ci/build"}},
		{"20204724", "ghektestorg/fr-11-03-required-status-check-name-is-attacker-creatable", []any{}},
	} {
		node := n.get(nodeID(Ruleset, map[string]string{"scope": "repo", "id": tc.id}))
		if node == nil {
			t.Fatalf("ruleset %s was not emitted", tc.id)
		}
		if _, kept := node.Properties["required_status_checks"]; kept {
			t.Errorf("ruleset %s kept the nested required_status_checks", tc.id)
		}
		if got := node.Properties["required_status_check_contexts"]; !reflect.DeepEqual(got, tc.contexts) {
			t.Errorf("ruleset %s contexts = %v, want %v", tc.id, got, tc.contexts)
		}
		if got := node.Properties["repo"]; got != tc.repo {
			t.Errorf("ruleset %s repo = %v, want the owner-qualified %q", tc.id, got, tc.repo)
		}
	}
}

// fr-11-02 fires one deploy job from 7 branches and declares permissions: {contents:
// read, id-token: write}. The 7 records merge, so a per-branch scalar would be whichever
// record sorted first; the branch set and the token the job holds are what survive.
func TestEmitJobsResolvesBranchesAndProjectsTheToken(t *testing.T) {
	const repo = "fr-11-02-protection-targets-default-branch-only-but-deploy-fires-from"
	branches := []string{"main", "deploy", "hotfix/a", "hotfix/b/c", "release/1.0", "release/2.0/hotfix", "releases/1.0"}

	rows, files := []any{}, map[string]any{
		"org/ghektestorg.json": map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
	}
	for _, b := range branches {
		rows = append(rows, map[string]any{"repo": repo, "branch": b})
		slug := strings.ReplaceAll(b, "/", "__")
		files["jobs/"+repo+"@"+slug+".json"] = map[string]any{
			"_id": repo + "@" + slug, "repo": repo,
			"workflow_filename": "main.yml", "job_id": "deploy",
			"branch": slug, "is_default_branch": b == "main",
			"sinks": []any{"local_script_invocation"},
			"steps": []any{map[string]any{"uses": "actions/checkout@v4"}},
			"permissions": map[string]any{
				"_source": "job", "_chain": []any{map[string]any{"source": "org_default", "value": "write"}},
				"contents": "read", "id-token": "write", "packages": "none",
			},
		}
	}
	files["chains/effective-ruleset.json"] = map[string]any{"chain": "effective-ruleset", "effective_per_branch": rows}

	_, n := fixture(t, files)
	node := n.get(nodeID(Job, map[string]string{
		"repo": "ghektestorg/" + repo, "workflow": ".github/workflows/main.yml", "job_id": "deploy",
	}))
	if node == nil {
		t.Fatal("the merged job was not emitted")
	}

	want := []any{"deploy", "hotfix/a", "hotfix/b/c", "main", "release/1.0", "release/2.0/hotfix", "releases/1.0"}
	if got := node.Properties["branches"]; !reflect.DeepEqual(got, want) {
		t.Errorf("branches = %v, want the 7 unslugged names %v", got, want)
	}
	if node.Properties["is_default_branch_any"] != true {
		t.Error("the job fires from the default branch and must say so")
	}
	for _, k := range []string{"branch", "is_default_branch", "steps"} {
		if _, kept := node.Properties[k]; kept {
			t.Errorf("%q survived on the merged job", k)
		}
	}
	if got, want := node.Properties["token_write_scopes"], ([]any{"id-token"}); !reflect.DeepEqual(got, want) {
		t.Errorf("token_write_scopes = %v, want %v", got, want)
	}
	if got := node.Properties["token_source"]; got != "job" {
		t.Errorf("token_source = %v, want job", got)
	}
	if got, want := node.Properties["sinks"], ([]any{"local_script_invocation"}); !reflect.DeepEqual(got, want) {
		t.Errorf("sinks = %v, want %v", got, want)
	}
}

// BranchSlug maps "feat/a" and "feat__a" onto one key, so a job recorded against that
// slug belongs to neither: naming one ships the other branch's name as fact. fr-11-05's
// near miss ("sandbox-x" against "sandbox/x") slugs distinctly and must still resolve.
func TestJobBranchDegradesOnSlugCollision(t *testing.T) {
	const repo = "fr-11-05-include-all-branches-with-exclusion-list-creates-trust-islan"
	for _, order := range [][]string{{"feat/a", "feat__a"}, {"feat__a", "feat/a"}} {
		t.Run(strings.Join(order, "+"), func(t *testing.T) {
			rows := []any{}
			for _, b := range []string{order[0], order[1], "sandbox-x", "sandbox/x"} {
				rows = append(rows, map[string]any{"repo": repo, "branch": b})
			}
			files := map[string]any{
				"org/ghektestorg.json":          map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
				"chains/effective-ruleset.json": map[string]any{"chain": "effective-ruleset", "effective_per_branch": rows},
			}
			for _, slug := range []string{"feat__a", "sandbox__x"} {
				files["jobs/"+repo+"@"+slug+".json"] = map[string]any{
					"_id": repo + "@" + slug, "repo": repo,
					"workflow_filename": "ci.yml", "job_id": slug, "branch": slug,
				}
			}

			_, n := fixture(t, files)
			for _, tc := range []struct {
				jobID    string
				branches []any
				slugged  bool
			}{
				{"feat__a", []any{"feat__a"}, true},
				{"sandbox__x", []any{"sandbox/x"}, false},
			} {
				node := n.get(nodeID(Job, map[string]string{
					"repo": "ghektestorg/" + repo, "workflow": ".github/workflows/ci.yml", "job_id": tc.jobID,
				}))
				if node == nil {
					t.Fatalf("job %s was not emitted", tc.jobID)
				}
				if got := node.Properties["branches"]; !reflect.DeepEqual(got, tc.branches) {
					t.Errorf("job %s branches = %v, want %v", tc.jobID, got, tc.branches)
				}
				if got := truthy(node.Properties["branches_slugged"]); got != tc.slugged {
					t.Errorf("job %s branches_slugged = %v, want %v", tc.jobID, got, tc.slugged)
				}
			}
		})
	}
}

// fr-05-09: upstream.yml's fork-PR job writes "build-out" and the callee downloads the
// "${{ inputs.artifact-name }}" downstream.yml forwards. Both jobs must land on one
// Artifact node — an unresolved expression splits it and the writer -> reader path is gone.
func TestCalleeArtifactResolvesToTheCallSiteInput(t *testing.T) {
	const repo = "fr-05-09-reusable-workflow-laundering"
	job := func(workflow, id string, fields map[string]any) map[string]any {
		m := map[string]any{"_id": repo + "__" + id, "repo": repo,
			"workflow_filename": workflow, "job_id": id}
		for k, v := range fields {
			m[k] = v
		}
		return m
	}
	c, n := fixture(t, map[string]any{
		"org/ghektestorg.json": map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
		"jobs/upstream.json": job("upstream.yml", "build", map[string]any{
			"artifact_writes": []any{map[string]any{"name": "build-out"}}}),
		"jobs/callee.json": job("_reusable.yml", "release", map[string]any{
			"artifact_reads": []any{map[string]any{"name": "${{ inputs.artifact-name }}"}}}),
		"chains/reusable-callgraph.json": map[string]any{
			"chain": "reusable-callgraph",
			"edges": []any{map[string]any{
				"caller": map[string]any{"repo": repo, "workflow_filename": "downstream.yml", "job_id": "release"},
				"callee": map[string]any{"path": ".github/workflows/_reusable.yml", "is_local": true,
					"inputs": map[string]any{"artifact-name": "build-out"}},
			}},
		},
	})
	s, err := buildEdges(t.Context(), c, n)
	if err != nil {
		t.Fatalf("buildEdges: %v", err)
	}

	art := nd(Artifact, "repo", "ghektestorg/"+repo, "name", "build-out").id
	if !n.has(art) {
		t.Fatalf("no %s node; have %v", art, slices.Sorted(maps.Keys(n.byID)))
	}
	for _, want := range []struct {
		t   EdgeType
		job string
	}{{Writes, "upstream.yml|build"}, {Reads, "_reusable.yml|release"}} {
		from := "Job|ghektestorg/" + repo + `|.github/workflows/` + want.job
		if _, ok := s.byID[edgeID(want.t, from, art)]; !ok {
			t.Errorf("no %s from %s to the shared artifact", want.t, from)
		}
	}
}

// fr-01-03 templates a uses: ref from the PR branch name, so the action resolved at run
// time is whatever the attacker names. There is no identity to point at: no node may be
// minted, and both halves have to be counted rather than silently dropped.
func TestUnresolvableExpressionIdentityIsCountedNotMinted(t *testing.T) {
	const repo = "fr-01-03-action-ref-templated-from-pr"
	const ref = "my-org/build-tools@${{ github.event.pull_request.head.ref }}"
	c, n := fixture(t, map[string]any{
		"org/ghektestorg.json": map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
		"jobs/build.json": map[string]any{
			"_id": repo + "__main__build", "repo": repo,
			"workflow_filename": "main.yml", "job_id": "build",
			"action_refs": []any{map[string]any{"uses": ref}},
		},
	})
	s, err := buildEdges(t.Context(), c, n)
	if err != nil {
		t.Fatalf("buildEdges: %v", err)
	}

	for id := range n.byID {
		if strings.Contains(id, "${{") {
			t.Errorf("minted a node for an unevaluated expression: %q", id)
		}
	}
	if got := n.incompleteIdentities()[Action]; got != 1 {
		t.Errorf("incomplete_identities[Action] = %d, want 1", got)
	}
	if k := edgeKey(UsesAction, Job, Action); s.unbuilt[k] != 1 {
		t.Errorf("unbuilt[%s] = %d, want 1", k, s.unbuilt[k])
	}
}
