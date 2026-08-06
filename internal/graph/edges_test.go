package graph

import (
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
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
	if k := edgeKey(Targets, Job, Environment); s.unbuilt[k] != 1 {
		t.Errorf("unbuilt[%s] = %d, want 1 for the expression-named environment", k, s.unbuilt[k])
	}
}

// Approving a PR from a workflow needs the repo's "allow Actions to create and approve
// pull requests" toggle AND pull-requests:write on the job token. The three rows below
// hold one, the other and both; fr-03-11's toggle is off and only an App token passes.
func TestCanApproveNeedsBothTheRepoToggleAndTheJobToken(t *testing.T) {
	files := map[string]any{"org/ghektestorg.json": map[string]any{"_id": "ghektestorg", "org": "ghektestorg"}}
	for _, tc := range []struct {
		repo, workflow, job, pullRequests string
		canApprove                        bool
	}{
		{"fr-03-01-self-pr-approve-via-actions", "approve.yml", "approve", "write", true},
		{"fr-03-04-tag-push-triggers-release-workflow", "release.yml", "publish", "none", true},
		{"fr-03-11-app-token-bypass-actions-approval-toggle", "approve.yml", "approve", "write", false},
	} {
		files["repos/"+tc.repo+".json"] = map[string]any{
			"_id": tc.repo, "repo": tc.repo, "can_approve_pull_request_reviews": tc.canApprove,
		}
		id := tc.repo + "__" + tc.job
		files["jobs/"+id+".json"] = map[string]any{
			"_id": id, "repo": tc.repo, "workflow_filename": tc.workflow, "job_id": tc.job,
			"permissions": map[string]any{"pull-requests": tc.pullRequests},
		}
	}

	got := edgesOfType(build(t, files), CanApprove)
	if len(got) != 1 {
		t.Fatalf("got %d CAN_APPROVE edges, want 1: %+v", len(got), got)
	}
	want := nodeID(Job, map[string]string{
		"repo":     "ghektestorg/fr-03-01-self-pr-approve-via-actions",
		"workflow": ".github/workflows/approve.yml",
		"job_id":   "approve",
	})
	if got[0].From != want {
		t.Errorf("from = %q, want the only job holding both halves %q", got[0].From, want)
	}
}

// conf-ci mints one app token from reusable-build.yml's build job, observed on
// four branches. Job identity omits branch, so the ceiling on the edges this
// would build is job definitions, not chain rows.
func TestUnbuildableMintsCountsJobDefinitionsNotBranchVariants(t *testing.T) {
	mints := []any{}
	for _, id := range []string{
		"mint__conf-ci@chore__build-token-perms__reusable-build__build__actions/create-github-app-token@v1",
		"mint__conf-ci@chore__preview-cache-fix__reusable-build__build__actions/create-github-app-token@v1",
		"mint__conf-ci@release__reusable-build__build__actions/create-github-app-token@v1",
		"mint__conf-ci__reusable-build__build__actions/create-github-app-token@v1",
	} {
		mints = append(mints, map[string]any{
			"_id":            id,
			"app_id_literal": "${{ secrets.CONF_CI_APP_ID }}",
			"minter":         map[string]any{"repo": "conf-ci", "workflow_filename": "reusable-build.yml", "job_id": "build"},
		})
	}
	mints = append(mints, map[string]any{
		"_id":            "mint__fr-03-11-app-token-bypass-actions-approval-toggle__approve__approve__actions/create-github-app-token@v1",
		"app_id_literal": "${{ secrets.APP_ID }}",
		"minter": map[string]any{
			"repo":              "fr-03-11-app-token-bypass-actions-approval-toggle",
			"workflow_filename": "approve.yml", "job_id": "approve",
		},
	})

	s := build(t, map[string]any{
		"org/ghektestorg.json":     map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
		"chains/app-mintable.json": map[string]any{"chain": "app-mintable", "mints": mints},
	})
	if k := edgeKey(MintsTokenAs, Job, App); s.unbuilt[k] != 2 {
		t.Errorf("unbuilt[%s] = %d, want 2 minting job definitions from 5 chain rows", k, s.unbuilt[k])
	}
}

// TARGETS declares {Job,Environment} and {Workflow,Branch}; only the first has a
// writer. by_type reports TARGETS as populated, so the pair with no code behind
// it is invisible unless the gap is accounted per declared pair.
func TestEmptyEdgeTriplesSeesPastAPopulatedSiblingPair(t *testing.T) {
	s := build(t, map[string]any{
		"org/ghektestorg.json": map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
		"chains/env-deployments.json": map[string]any{"chain": "env-deployments", "deploys": []any{
			map[string]any{
				"_id": "deploy__fr-11-02", "env_name": "production", "env_record_present": true,
				"job": map[string]any{"repo": "fr-11-02", "workflow_filename": "main.yml", "job_id": "deploy"},
			},
		}},
	})

	got := emptyEdgeTriples(s.all())
	if slices.Contains(got, edgeKey(Targets, Job, Environment)) {
		t.Error("TARGETS{Job,Environment} was emitted and must not be reported empty")
	}
	if !slices.Contains(got, edgeKey(Targets, Workflow, Branch)) {
		t.Errorf("TARGETS{Workflow,Branch} has no writer and must be reported empty: %v", got)
	}
}

// fr-11-02 deploys one job definition from 7 branches, so its TARGETS edge is
// written repeatedly. A scalar the records disagree on is first-wins and must be
// counted; identical scalars are not conflicts and arrays still union.
func TestAddCountsDiscardedScalarsAndUnionsArrays(t *testing.T) {
	s := newEdgeSet()
	from := nd(Job, "repo", "ghektestorg/fr-11-02", "workflow", ".github/workflows/main.yml", "job_id", "deploy")
	to := nd(Environment, "repo", "ghektestorg/fr-11-02", "name", "production")
	for i, noReviewers := range []bool{false, true} {
		s.add(Targets, from, to, map[string]any{
			"env_no_reviewers":   noReviewers,
			"env_record_present": true,
			"_source":            []any{fmt.Sprintf("chains/env-deployments.json#deploys[%d]", i)},
		})
	}

	e := s.byID[edgeID(Targets, from.id, to.id)]
	if e == nil {
		t.Fatalf("no TARGETS edge: %v", s.byID)
	}
	if e.Properties["env_no_reviewers"] != false {
		t.Errorf("env_no_reviewers = %v, want the first writer's false", e.Properties["env_no_reviewers"])
	}
	if got := s.conflicts[edgeConflictKey{Targets, "env_no_reviewers"}]; got != 1 {
		t.Errorf("discarded env_no_reviewers scalars = %d, want 1", got)
	}
	if _, dup := s.conflicts[edgeConflictKey{Targets, "env_record_present"}]; dup {
		t.Error("identical scalars must not count as conflicts")
	}
	if _, dup := s.conflicts[edgeConflictKey{Targets, "_source"}]; dup {
		t.Error("a merged array must not count as a conflict")
	}
	if got := len(e.Properties["_source"].([]any)); got != 2 {
		t.Errorf("_source has %d entries, want both writers", got)
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
	if k := edgeKey(RunsOn, Job, Runner); s.unbuilt[k] != 1 {
		t.Errorf("unbuilt[%s] = %d, want 1", k, s.unbuilt[k])
	}
}

// GitHub caches are repo-scoped. fr-09-01 and fr-09-03 are unrelated scenarios that both
// cache "npm-${{ runner.os }}-...", so a Cache keyed on the prefix alone puts one repo's
// writer on the other's reader and answers the poisoning query with a fabrication.
func TestCacheIOStaysInsideOneRepo(t *testing.T) {
	row := func(repo, workflow, job string) any {
		return map[string]any{
			"job": map[string]any{
				"_id": repo + "__" + job, "repo": repo,
				"workflow_filename": workflow, "job_id": job,
			},
			"key": "npm-${{ runner.os }}-${{ hashFiles('package-lock.json') }}",
		}
	}
	const a, b = "fr-09-01-restore-keys-prefix-match-bypass", "fr-09-03-runtime-token-exfiltration"
	c, n := fixture(t, map[string]any{
		"org/ghektestorg.json": map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
		"chains/cache-keyspace.json": map[string]any{
			"chain":            "cache-keyspace",
			"writes_by_prefix": map[string]any{"npm": []any{row(a, "writer.yml", "build"), row(b, "release.yml", "release")}},
			"reads_by_prefix":  map[string]any{"npm": []any{row(a, "release.yml", "release"), row(b, "release.yml", "release")}},
			"prefix_overlaps":  []any{},
		},
	})
	s, err := buildEdges(t.Context(), c, n)
	if err != nil {
		t.Fatalf("buildEdges: %v", err)
	}

	caches := 0
	for _, node := range n.byID {
		if node.Labels[0] == Cache {
			caches++
		}
	}
	if caches != 2 {
		t.Errorf("got %d Cache nodes, want one per repo", caches)
	}
	jobRepo := func(id string) string { return strings.Split(id, "|")[1] }
	for _, w := range edgesOfType(s, Writes) {
		for _, r := range edgesOfType(s, Reads) {
			if w.To == r.To && jobRepo(w.From) != jobRepo(r.From) {
				t.Errorf("cross-repo poisoning pair on %s: %s writes, %s reads", w.To, w.From, r.From)
			}
		}
	}
}

// A branch filter is a glob: it resolves against the branches that exist and never mints
// one. GitHub's "*" stops at a path separator and "**" does not — the difference between
// fr-11-02's release/1.0 and release/2.0/hotfix. fr-03-02's "attacker-dev" does not exist.
func TestTargetsBranchResolvesOnlyRefsThatExist(t *testing.T) {
	const glob = "fr-11-02-protection-targets-default-branch-only-but-deploy-fires-from"
	const absent = "fr-03-02-workflow-on-unprotected-branch"
	branches := []any{}
	for _, b := range [][2]string{{glob, "main"}, {glob, "release/1.0"}, {glob, "release/2.0/hotfix"}, {absent, "main"}} {
		branches = append(branches, map[string]any{"repo": b[0], "branch": b[1]})
	}
	job := func(repo, wf string, filters ...string) map[string]any {
		branchList := make([]any, len(filters))
		for i, f := range filters {
			branchList[i] = f
		}
		return map[string]any{
			"_id": repo + "__" + wf, "repo": repo, "workflow_filename": wf, "job_id": "deploy",
			"trigger_filters": map[string]any{"push": map[string]any{"branches": branchList}},
		}
	}

	c, n := fixture(t, map[string]any{
		"org/ghektestorg.json":          map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
		"jobs/glob.json":                job(glob, "main.yml", "release/*"),
		"jobs/deep.json":                job(glob, "deep.yml", "release/**"),
		"jobs/absent.json":              job(absent, "ci.yml", "main", "attacker-dev"),
		"chains/effective-ruleset.json": map[string]any{"chain": "effective-ruleset", "effective_per_branch": branches},
	})
	s, err := buildEdges(t.Context(), c, n)
	if err != nil {
		t.Fatalf("buildEdges: %v", err)
	}

	got := map[string][]string{}
	for _, e := range edgesOfType(s, Targets) {
		got[str(e.Properties["branch_filter"])] = append(got[str(e.Properties["branch_filter"])], e.To)
	}
	want := map[string][]string{
		"release/*":  {nd(Branch, "repo", "ghektestorg/"+glob, "name", "release/1.0").id},
		"release/**": {nd(Branch, "repo", "ghektestorg/"+glob, "name", "release/1.0").id, nd(Branch, "repo", "ghektestorg/"+glob, "name", "release/2.0/hotfix").id},
		"main":       {nd(Branch, "repo", "ghektestorg/"+absent, "name", "main").id},
	}
	for f, ids := range want {
		slices.Sort(got[f])
		slices.Sort(ids)
		if !slices.Equal(got[f], ids) {
			t.Errorf("filter %q resolved to %v, want %v", f, got[f], ids)
		}
	}
	if len(got) != len(want) {
		t.Errorf("resolved filters %v, want exactly %v", slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(want)))
	}
	if k := edgeKey(Targets, Workflow, Branch); s.unbuilt[k] != 1 {
		t.Errorf("unbuilt[%s] = %d, want 1 (attacker-dev, which does not exist)", k, s.unbuilt[k])
	}
	for _, name := range []string{"release/*", "release/**", "attacker-dev"} {
		for _, repo := range []string{glob, absent} {
			if id := nd(Branch, "repo", "ghektestorg/"+repo, "name", name).id; n.has(id) {
				t.Errorf("minted a Branch node for a ref that does not exist: %q", id)
			}
		}
	}
}

// step_index -1 marks a job-env-level secret reference, which is what fr-02-11 is built
// on: the composite action reads the caller's secrets through job env, not a step's
// `with`. Indexing steps[-1] would credit the last step. fr-05-06 is the control.
func TestPassesSecretIgnoresJobLevelSecretReferences(t *testing.T) {
	job := func(repo, wf string, uses []any, refs []any) map[string]any {
		steps := make([]any, len(uses))
		for i, u := range uses {
			steps[i] = map[string]any{"step_index": float64(i), "uses": u}
		}
		return map[string]any{
			"_id": repo, "repo": repo, "workflow_filename": wf, "job_id": "build",
			"steps": steps, "secrets_referenced": refs,
		}
	}
	ref := func(name string, idx int) any {
		return map[string]any{"name": name, "step_index": float64(idx), "scope": "repo"}
	}

	s := build(t, map[string]any{
		"org/ghektestorg.json": map[string]any{"_id": "ghektestorg", "org": "ghektestorg"},
		"jobs/env.json": job("fr-02-11-composite-action-reads-caller-secrets-via-env", "deploy.yml",
			[]any{"actions/checkout@v4", "./.github/actions/deploy"},
			[]any{ref("AWS_DEPLOY_ROLE", -1), ref("DOCKERHUB_TOKEN", -1)}),
		"jobs/step.json": job("fr-05-06-third-party-action-receives-secret", "main.yml",
			[]any{"actions/checkout@v4", "third-party/publish@v1"},
			[]any{ref("NPM_TOKEN", 1)}),
	})

	got := edgesOfType(s, PassesSecret)
	if len(got) != 1 {
		t.Fatalf("got %d PASSES_SECRET edges, want only the step-level reference: %+v", len(got), got)
	}
	if want := nd(Action, "ref", "third-party/publish@v1").id; got[0].To != want {
		t.Errorf("to = %q, want %q", got[0].To, want)
	}
}
