package gitlab

import "testing"

// TestChainForEachKeys is the hard for_each contract, guarded without a corpus:
// each of the nine joins must expose its tuple list under exactly the key the
// rules' chain_of.for_each reads (an unset/mismatched key makes iterChainItems
// default to "links" and iterate nothing). The key set is the contract table in
// docs/gitlab/gitlab-normalized-fields.md, not what the code returns.
func TestChainForEachKeys(t *testing.T) {
	c := &correlator{
		instance: map[string]any{},
		projects: map[string]map[string]any{},
		groups:   map[string]map[string]any{},
	}
	cases := []struct {
		name string
		fn   func() map[string]any
		key  string
	}{
		{"job-token-allowlist", c.jobTokenAllowlist, "edges"},
		{"protected-var-reachability", c.protectedVarReachability, "reachable_vars"},
		{"dotenv-flow", c.dotenvFlow, "edges"},
		{"cache-keyspace", c.cacheKeyspace, "prefix_overlaps"},
		{"cross-project-artifact", c.crossProjectArtifact, "edges"},
		{"deploy-key-reuse", c.deployKeyReuse, "reused_keys"},
		{"agent-ci-access", c.agentCIAccess, "grants"},
		{"runner-reachability", c.runnerReachability, "reachable_runners"},
		{"group-runner-reachability", c.groupRunnerReachability, "reachable_runners"},
	}
	for _, tc := range cases {
		out := tc.fn()
		if out["chain"] != tc.name {
			t.Errorf("%s: chain=%v", tc.name, out["chain"])
		}
		v, present := out[tc.key]
		if !present {
			t.Errorf("%s: missing for_each key %q", tc.name, tc.key)
			continue
		}
		// Even an empty join must emit the key as a (possibly empty) tuple list,
		// never nil — a null list serializes to JSON null and iterates nothing.
		tuples, ok := v.([]map[string]any)
		if !ok {
			t.Errorf("%s: key %q is %T, want []map[string]any", tc.name, tc.key, v)
			continue
		}
		if tuples == nil {
			t.Errorf("%s: key %q is nil slice (must be non-nil empty)", tc.name, tc.key)
		}
	}
}

// TestDotenvFlowTupleShape asserts the producer/consumer role nesting a cat-09
// chain_of.where resolves by role prefix. The edge exists only within a project.
func TestDotenvFlowTupleShape(t *testing.T) {
	c := &correlator{
		jobs: []map[string]any{
			{"_id": "grp/a:build", "produces_dotenv": true, "runs_on_untrusted_ref": true},
			{"_id": "grp/a:deploy", "consumes_dotenv": true, "image_from_variable": true},
			{"_id": "grp/b:deploy", "consumes_dotenv": true}, // different project: no edge
		},
	}
	edges := c.dotenvFlow()["edges"].([]map[string]any)
	if len(edges) != 1 {
		t.Fatalf("dotenv edges=%d want 1 (same-project producer→consumer only)", len(edges))
	}
	e := edges[0]
	prod := e["producer"].(map[string]any)
	cons := e["consumer"].(map[string]any)
	if prod["produces_dotenv"] != true || prod["runs_on_untrusted_ref"] != true {
		t.Errorf("producer participant fields wrong: %v", prod)
	}
	if cons["consumes_dotenv"] != true || cons["image_from_variable"] != true {
		t.Errorf("consumer participant fields wrong: %v", cons)
	}
}

// TestCrossProjectArtifactEdge asserts the consumer→producer edge carries the
// producer's trust posture keyed off the needs:project target, and that a bare
// (non-cross-project) need produces no edge.
func TestCrossProjectArtifactEdge(t *testing.T) {
	c := &correlator{
		jobs: []map[string]any{
			{"_id": "grp/consumer:gen", "cross_project_needs": []any{
				map[string]any{"project": "grp/producer", "artifacts": true},
			}},
			{"_id": "grp/other:x", "cross_project_needs": []any{}},
		},
		projects: map[string]map[string]any{
			"grp/producer": {"_id": "grp/producer", "visibility": "private", "has_developer_reachable_secret": true},
		},
	}
	edges := c.crossProjectArtifact()["edges"].([]map[string]any)
	if len(edges) != 1 {
		t.Fatalf("cross-project edges=%d want 1", len(edges))
	}
	e := edges[0]
	prod := e["producer"].(map[string]any)
	if prod["present"] != true || prod["visibility"] != "private" || prod["has_developer_reachable_secret"] != true {
		t.Errorf("producer trust posture not folded onto edge: %v", prod)
	}
	if e["need"].(map[string]any)["project"] != "grp/producer" {
		t.Errorf("need not carried on edge: %v", e["need"])
	}
	// An absent producer project is marked present:false, never dropped.
	c2 := &correlator{
		jobs: []map[string]any{{"_id": "grp/c:g", "cross_project_needs": []any{
			map[string]any{"project": "missing/proj"},
		}}},
		projects: map[string]map[string]any{},
	}
	e2 := c2.crossProjectArtifact()["edges"].([]map[string]any)[0]
	if e2["producer"].(map[string]any)["present"] != false {
		t.Error("missing producer must be present:false, not omitted")
	}
}

// TestGroupRunnerReachabilityOwningGroup asserts the group-scoped runner tuple
// resolves its owning group from _provenance scope and folds the group's
// creation-governance posture, and that the group participant is marked present.
func TestGroupRunnerReachabilityOwningGroup(t *testing.T) {
	c := &correlator{
		runners: []map[string]any{
			{"_id": "9", "runner_type": "group_type", "_provenance": []any{
				map[string]any{"scope": "group:grp/sub"},
			}},
		},
		groups: map[string]map[string]any{
			"grp/sub": {"_id": "grp/sub", "group_open_project_creation": true, "project_creation_role": "developer"},
		},
	}
	tuples := c.groupRunnerReachability()["reachable_runners"].([]map[string]any)
	if len(tuples) != 1 {
		t.Fatalf("group-runner tuples=%d want 1", len(tuples))
	}
	g := tuples[0]["group"].(map[string]any)
	if g["present"] != true || g["_id"] != "grp/sub" || g["group_open_project_creation"] != true {
		t.Errorf("owning-group posture not folded: %v", g)
	}
}

func TestCacheKeyPrefix(t *testing.T) {
	cases := []struct{ key, want string }{
		{"build-cache", "build-cache"},
		{"deps-$CI_COMMIT_REF_SLUG", "deps"}, // per-ref suffix stripped
		{"$CI_COMMIT_REF_SLUG", ""},          // fully interpolated: no static prefix
		{"", ""},                             // files:-derived key (no literal)
		{"node-modules-", "node-modules"},    // trailing delimiter trimmed
		{"-leading", "leading"},              // leading delimiter trimmed
	}
	for _, c := range cases {
		if got := cacheKeyPrefix(c.key); got != c.want {
			t.Errorf("cacheKeyPrefix(%q)=%q want %q", c.key, got, c.want)
		}
	}
}

func TestAllowlistAdmits(t *testing.T) {
	src := "grp/consumer"
	cases := []struct {
		mode    string
		entries []any
		want    bool
	}{
		{"open", nil, true},     // no inbound scoping: admits all
		{"disabled", nil, true}, // scope off: admits all
		{"project_scoped", []any{"grp/consumer"}, true},
		{"project_scoped", []any{"grp/other"}, false}, // scoped and source not listed
		{"group_scoped", []any{}, false},
	}
	for _, c := range cases {
		al := map[string]any{"mode": c.mode, "entries": c.entries}
		if got := allowlistAdmits(al, src); got != c.want {
			t.Errorf("allowlistAdmits(mode=%s,entries=%v)=%v want %v", c.mode, c.entries, got, c.want)
		}
	}
}

func TestCachePolicyWrites(t *testing.T) {
	if cachePolicyWritesGL(map[string]any{"policy": "pull"}) {
		t.Error("pull-only cache must not count as a writer")
	}
	for _, p := range []string{"", "push", "pull-push"} {
		if !cachePolicyWritesGL(map[string]any{"policy": p}) {
			t.Errorf("policy %q must count as a writer (default is read-write)", p)
		}
	}
}

func TestJobTokenTargets(t *testing.T) {
	// needs:project: targets are collected; a CI_JOB_TOKEN script use with no
	// nameable target still yields the source project so token posture is seen.
	job := map[string]any{
		"_id": "grp/a:build",
		"cross_project_needs": []any{
			map[string]any{"project": "grp/b"},
			map[string]any{"project": "grp/c"},
		},
		"job_token_cross_project_use": "git_push",
	}
	got := jobTokenTargets(job)
	want := map[string]bool{"grp/a": true, "grp/b": true, "grp/c": true}
	if len(got) != len(want) {
		t.Fatalf("jobTokenTargets=%v want keys %v", got, want)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected target %q", g)
		}
	}
	// No cross-project use and no needs → no edge.
	none := map[string]any{"_id": "grp/a:x", "job_token_cross_project_use": "none"}
	if got := jobTokenTargets(none); len(got) != 0 {
		t.Errorf("jobTokenTargets(no-use)=%v want empty", got)
	}
}

// TestProtectedVarReachabilitySelfResolving asserts the two correlations the
// join must resolve so the rules stay literal-only: (1) only protected vars are
// emitted; (2) every emitted member belongs to the same project as the ref, and
// every emitted branch/tag is that project's. It also checks a group-scoped var
// reaches a descendant project but not a non-descendant.
func TestProtectedVarReachabilitySelfResolving(t *testing.T) {
	proj := map[string]any{
		"_id": "grp/p1",
		"cicd_variables": []any{
			map[string]any{"key": "SECRET", "protected": true},
			map[string]any{"key": "PUBLIC", "protected": false},
		},
		"protected_branches": []any{map[string]any{"pattern": "main", "push_access_levels": []any{int64(30)}}},
		"protected_tags":     []any{},
		"members":            []any{map[string]any{"access_level": int64(30)}},
	}
	nonDescendant := map[string]any{
		"_id":                "other/p2",
		"cicd_variables":     []any{},
		"protected_branches": []any{map[string]any{"pattern": "main"}},
		"members":            []any{map[string]any{"access_level": int64(40)}},
	}
	group := map[string]any{
		"_id":         "grp",
		"descendants": []any{"grp/p1"}, // p1 is a descendant; other/p2 is not
		"cicd_variables": []any{
			map[string]any{"key": "GROUP_SECRET", "protected": true},
		},
	}
	c := &correlator{
		projList:  []map[string]any{proj, nonDescendant},
		groupList: []map[string]any{group},
		projects:  indexByID([]map[string]any{proj, nonDescendant}),
		groups:    indexByID([]map[string]any{group}),
	}
	out := c.protectedVarReachability()
	tuples, _ := out["reachable_vars"].([]map[string]any)

	seenKeys := map[string]bool{}
	for _, tp := range tuples {
		v := tp["var"].(map[string]any)
		key := v["key"].(string)
		seenKeys[key] = true
		if v["protected"] != true {
			t.Errorf("emitted non-protected var %q", key)
		}
		// correlation (b): member's tuple project == ref project.
		if tp["project"] != v["project"] {
			t.Errorf("var %q: tuple project %v != var project %v", key, tp["project"], v["project"])
		}
	}
	if !seenKeys["SECRET"] {
		t.Error("project-scoped protected var SECRET not emitted")
	}
	if seenKeys["PUBLIC"] {
		t.Error("non-protected var PUBLIC must not be emitted")
	}
	if !seenKeys["GROUP_SECRET"] {
		t.Error("group-scoped protected var must reach descendant project")
	}
	// correlation (a): the group var must reach ONLY the descendant (grp/p1),
	// never the non-descendant (other/p2).
	for _, tp := range tuples {
		v := tp["var"].(map[string]any)
		if v["key"] == "GROUP_SECRET" && tp["project"] == "other/p2" {
			t.Error("group var reached a non-descendant project")
		}
	}
}

// TestInstanceScopedVarReachability: an instance-scoped protected CI/CD variable
// reaches every project on the instance, with scope_level=="instance" (cat-03).
func TestInstanceScopedVarReachability(t *testing.T) {
	p1 := map[string]any{
		"_id":                "grp/p1",
		"cicd_variables":     []any{},
		"protected_branches": []any{map[string]any{"pattern": "main", "push_access_levels": []any{int64(30)}}},
		"members":            []any{map[string]any{"access_level": int64(30)}},
	}
	p2 := map[string]any{
		"_id":                "other/p2",
		"cicd_variables":     []any{},
		"protected_branches": []any{map[string]any{"pattern": "main"}},
		"members":            []any{map[string]any{"access_level": int64(40)}},
	}
	c := &correlator{
		projList: []map[string]any{p1, p2},
		projects: indexByID([]map[string]any{p1, p2}),
		groups:   map[string]map[string]any{},
		instance: map[string]any{
			"cicd_variables": []any{
				map[string]any{"key": "INSTANCE_SECRET", "protected": true},
				map[string]any{"key": "INSTANCE_PLAIN", "protected": false},
			},
		},
	}
	tuples := c.protectedVarReachability()["reachable_vars"].([]map[string]any)
	reachedProjects := map[string]bool{}
	for _, tp := range tuples {
		v := tp["var"].(map[string]any)
		if v["key"] != "INSTANCE_SECRET" {
			continue
		}
		if v["scope_level"] != "instance" {
			t.Errorf("instance var scope_level=%v want instance", v["scope_level"])
		}
		reachedProjects[tp["project"].(string)] = true
	}
	if !reachedProjects["grp/p1"] || !reachedProjects["other/p2"] {
		t.Errorf("instance-scoped protected var must reach every project, reached %v", reachedProjects)
	}
	// The unprotected instance var must never be emitted.
	for _, tp := range tuples {
		if tp["var"].(map[string]any)["key"] == "INSTANCE_PLAIN" {
			t.Error("unprotected instance var must not be emitted")
		}
	}
}

// TestProtectedVarParticipantProvenance: the branch/tag and member participants
// carry _provenance{project_path} for evidence templating (MUST-FIX 13).
func TestProtectedVarParticipantProvenance(t *testing.T) {
	proj := map[string]any{
		"_id":                "grp/p1",
		"cicd_variables":     []any{map[string]any{"key": "SECRET", "protected": true}},
		"protected_branches": []any{map[string]any{"pattern": "main", "push_access_levels": []any{int64(30)}}},
		"members":            []any{map[string]any{"access_level": int64(30)}},
	}
	c := &correlator{
		projList: []map[string]any{proj},
		projects: indexByID([]map[string]any{proj}),
		groups:   map[string]map[string]any{},
		instance: map[string]any{},
	}
	tuples := c.protectedVarReachability()["reachable_vars"].([]map[string]any)
	if len(tuples) == 0 {
		t.Fatal("expected at least one tuple")
	}
	tp := tuples[0]
	for _, role := range []string{"branch", "member"} {
		part := tp[role].(map[string]any)
		prov, ok := part["_provenance"].([]provenance)
		if !ok || len(prov) == 0 || prov[0]["project_path"] != "grp/p1" {
			t.Errorf("%s participant missing _provenance{project_path}: %v", role, part["_provenance"])
		}
	}
}

// TestJobTokenTargetParticipant: cat-04 reads target.job_token_allowlist.trusts_source
// plus the target's terraform/push/writable-branch posture. All must be emitted.
func TestJobTokenTargetParticipant(t *testing.T) {
	c := &correlator{
		jobs: []map[string]any{
			{"_id": "grp/src:build", "job_token_cross_project_use": "none", "cross_project_needs": []any{map[string]any{"project": "grp/tgt"}}},
		},
		projects: map[string]map[string]any{
			"grp/src": {"_id": "grp/src", "members": []any{}},
			"grp/tgt": {
				"_id":                                    "grp/tgt",
				"job_token_allowlist":                    map[string]any{"mode": "open", "entries": []any{}},
				"uses_managed_terraform_state":           true,
				"job_token_push_allowed":                 true,
				"job_token_cross_project_push_allowed":   true,
				"developer_writable_protected_branch":    true,
				"has_developer_pushable_unprotected_ref": true,
			},
		},
	}
	edges := c.jobTokenAllowlist()["edges"].([]map[string]any)
	if len(edges) != 1 {
		t.Fatalf("edges=%d want 1", len(edges))
	}
	tgt := edges[0]["target"].(map[string]any)
	al := tgt["job_token_allowlist"].(map[string]any)
	if al["trusts_source"] != true {
		t.Errorf("open allowlist must set target.job_token_allowlist.trusts_source=true, got %v", al["trusts_source"])
	}
	for _, k := range []string{"uses_managed_terraform_state", "job_token_push_allowed", "job_token_cross_project_push_allowed", "developer_writable_protected_branch", "has_developer_pushable_unprotected_ref"} {
		if tgt[k] != true {
			t.Errorf("target.%s=%v want true", k, tgt[k])
		}
	}
	// A missing target project must default these to false, never omit them.
	c2 := &correlator{
		jobs:     []map[string]any{{"_id": "grp/src:b", "job_token_cross_project_use": "none", "cross_project_needs": []any{map[string]any{"project": "missing/p"}}}},
		projects: map[string]map[string]any{"grp/src": {"_id": "grp/src", "members": []any{}}},
	}
	tgt2 := c2.jobTokenAllowlist()["edges"].([]map[string]any)[0]["target"].(map[string]any)
	if tgt2["uses_managed_terraform_state"] != false {
		t.Error("absent target must set uses_managed_terraform_state=false, not omit it")
	}
}

func TestRunnerReachabilityTypeFilter(t *testing.T) {
	runners := []map[string]any{
		{"_id": "1", "runner_type": "instance_type", "is_shared": true},
		{"_id": "2", "runner_type": "group_type", "is_shared": false},
		{"_id": "3", "runner_type": "project_type", "is_shared": false},
		{"_id": "4", "runner_type": "project_type", "is_shared": true}, // shared project runner still instance-reachable
	}
	c := &correlator{runners: runners, instance: map[string]any{"open_project_creation": true}}

	inst := c.runnerReachability()["reachable_runners"].([]map[string]any)
	if len(inst) != 2 { // ids 1 and 4 (instance_type OR is_shared)
		t.Errorf("runner-reachability=%d want 2", len(inst))
	}
	grp := c.groupRunnerReachability()["reachable_runners"].([]map[string]any)
	if len(grp) != 1 { // only id 2 (group_type)
		t.Errorf("group-runner-reachability=%d want 1", len(grp))
	}
}

func TestDeployKeyReuseSpansProjects(t *testing.T) {
	creds := []map[string]any{
		{"kind": "deploy_key", "deploy_key_fingerprint": "AAAA", "can_push": true, "_provenance": []any{map[string]any{"scope": "project:grp/a"}}},
		{"kind": "deploy_key", "deploy_key_fingerprint": "AAAA", "can_push": false, "_provenance": []any{map[string]any{"scope": "project:grp/b"}}},
		{"kind": "deploy_key", "deploy_key_fingerprint": "BBBB", "can_push": true, "_provenance": []any{map[string]any{"scope": "project:grp/a"}}}, // single project: not reuse
		{"kind": "deploy_token", "deploy_key_fingerprint": "AAAA", "_provenance": []any{map[string]any{"scope": "project:grp/c"}}},                 // not a deploy_key
	}
	c := &correlator{creds: creds, projects: map[string]map[string]any{}}
	reused := c.deployKeyReuse()["reused_keys"].([]map[string]any)
	if len(reused) != 1 {
		t.Fatalf("reused_keys=%d want 1 (only AAAA spans two projects)", len(reused))
	}
	r := reused[0]
	if r["project_count"].(int) != 2 {
		t.Errorf("project_count=%v want 2", r["project_count"])
	}
	if r["any_write_capable"] != true {
		t.Error("any_write_capable must be true (grp/a key can_push)")
	}
}
