package ado

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func writeCollect(t *testing.T, dir, rel string, data any) {
	t.Helper()
	if err := engine.WriteJSON(filepath.Join(dir, rel), map[string]any{"_meta": map[string]any{}, "data": data}); err != nil {
		t.Fatal(err)
	}
}

// A service connection shared into a second project must collapse to ONE
// canonical node (keyed under the owner) that retains per-project authorization.
func TestServiceConnectionDedup(t *testing.T) {
	dir := t.TempDir()
	cp, prior := engineCP(dir), engine.PriorPhase{RunDir: dir}
	ref := func(n string) any { return map[string]any{"projectReference": map[string]any{"name": n}} }
	sc := map[string]any{
		"id": "conn-1", "name": "shared-sc", "type": "generic", "isShared": true,
		"authorization":                    map[string]any{"scheme": "Token", "parameters": map[string]any{}},
		"data":                             map[string]any{},
		"serviceEndpointProjectReferences": []any{ref("Owner"), ref("ConsumerB")}, // owner listed first
	}
	writeCollect(t, dir, engine.CollectADOServiceConnections("Owner"), []any{sc})
	writeCollect(t, dir, engine.CollectADOServiceConnections("ConsumerB"), []any{sc})

	projs := []projectMeta{{ID: "o", Name: "Owner"}, {ID: "b", Name: "ConsumerB"}}
	if err := normalizeServiceConnectionsShared(prior, cp, "org", projs, normTimer()); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "10-normalize/service-connections/*.json"))
	if len(files) != 1 {
		t.Fatalf("want 1 deduped node, got %d: %v", len(files), files)
	}
	rec := readRec(t, dir, engine.NormalizeADOServiceConnection("Owner", "conn-1"))
	if rec["owner_project"] != "Owner" {
		t.Errorf("owner_project = %v", rec["owner_project"])
	}
	ppa, _ := rec["per_project_authorization"].(map[string]any)
	if _, ok := ppa["Owner"]; !ok {
		t.Error("per_project_authorization missing Owner")
	}
	if _, ok := ppa["ConsumerB"]; !ok {
		t.Error("per_project_authorization missing ConsumerB (shared-into project)")
	}
	if si, _ := rec["shared_into"].([]any); len(si) != 1 || si[0] != "ConsumerB" {
		t.Errorf("shared_into = %v, want [ConsumerB]", rec["shared_into"])
	}
	// resolution: the connection is referable by name from BOTH projects
	vp := map[string]bool{}
	for _, p := range visibleProjects(rec) {
		vp[p] = true
	}
	if !vp["Owner"] || !vp["ConsumerB"] {
		t.Errorf("visibleProjects = %v, want Owner+ConsumerB", visibleProjects(rec))
	}
}

// The VG dedup path mirrors the SC one. ADO does not currently permit
// cross-project VG sharing (the endpoint returns "Sharing of variable group is
// not allowed"), so this exercises the collapse logic against synthetic shared
// input the same way TestServiceConnectionDedup does — proving the machinery is
// correct if such data ever appears.
func TestVariableGroupDedup(t *testing.T) {
	dir := t.TempDir()
	cp, prior := engineCP(dir), engine.PriorPhase{RunDir: dir}
	ref := func(n string) any { return map[string]any{"projectReference": map[string]any{"name": n}} }
	vg := map[string]any{
		"id": float64(42), "name": "shared-vg", "type": "Vsts",
		"variables":                      map[string]any{"TOKEN": map[string]any{"isSecret": true}},
		"variableGroupProjectReferences": []any{ref("Owner"), ref("ConsumerB")},
	}
	writeCollect(t, dir, engine.CollectADOVariableGroups("Owner"), []any{vg})
	writeCollect(t, dir, engine.CollectADOVariableGroups("ConsumerB"), []any{vg})

	projs := []projectMeta{{ID: "o", Name: "Owner"}, {ID: "b", Name: "ConsumerB"}}
	if err := normalizeVariableGroupsShared(prior, cp, "org", projs, normTimer()); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "10-normalize/variable-groups/*.json"))
	if len(files) != 1 {
		t.Fatalf("want 1 deduped VG node, got %d: %v", len(files), files)
	}
	rec := readRec(t, dir, engine.NormalizeADOVariableGroup("Owner", 42))
	if rec["owner_project"] != "Owner" || rec["owner_collected"] != true {
		t.Errorf("owner fields wrong: %v", rec)
	}
	ppa, _ := rec["per_project_authorization"].(map[string]any)
	if _, ok := ppa["Owner"]; !ok {
		t.Error("per_project_authorization missing Owner")
	}
	if _, ok := ppa["ConsumerB"]; !ok {
		t.Error("per_project_authorization missing ConsumerB")
	}
	if si, _ := rec["shared_into"].([]any); len(si) != 1 || si[0] != "ConsumerB" {
		t.Errorf("shared_into = %v, want [ConsumerB]", rec["shared_into"])
	}
	// the secret variable folds out to its own node + DEFINES edge
	if _, err := filepath.Glob(filepath.Join(dir, "10-normalize/secret-variables/*.json")); err != nil {
		t.Fatal(err)
	}
}

// ownerAuth returns the owner's authorization, or the deterministic
// first-collected project's when the owner project was not itself collected.
func TestOwnerAuthFallback(t *testing.T) {
	ownerA := map[string]any{"checks": []any{"owner-check"}}
	consB := map[string]any{"checks": []any{"b-check"}}
	consC := map[string]any{"checks": []any{"c-check"}}

	perProj := map[string]any{"Owner": ownerA, "ConsumerB": consB}
	if got := ownerAuth(perProj, "Owner", map[string]bool{"Owner": true, "ConsumerB": true}); got["checks"].([]any)[0] != "owner-check" {
		t.Errorf("owner present: got %v, want owner-check", got)
	}
	// owner not collected: fall back to the first (sorted) collected project.
	perProj2 := map[string]any{"ConsumerC": consC, "ConsumerB": consB}
	if got := ownerAuth(perProj2, "Owner", map[string]bool{"ConsumerC": true, "ConsumerB": true}); got["checks"].([]any)[0] != "b-check" {
		t.Errorf("owner absent: got %v, want b-check (ConsumerB sorts first)", got)
	}
	if got := ownerAuth(map[string]any{}, "Owner", map[string]bool{}); got["pipeline_permissions"] == nil {
		t.Errorf("empty default should carry pipeline_permissions: %v", got)
	}
}

// TARGETS resolves a resource-scoped environment ("env.resource") to the
// Environment node; RUNS_ON resolves a named pool to its ProjectAgentPool.
func TestTargetsRunsOnResolution(t *testing.T) {
	dir := t.TempDir()
	cp, prior := engineCP(dir), engine.PriorPhase{RunDir: dir}
	write := func(rel string, rec any) {
		if err := engine.WriteJSON(filepath.Join(dir, rel), rec); err != nil {
			t.Fatal(err)
		}
	}
	write(engine.NormalizeADOEnvironment("Mordor", "prod"), map[string]any{"project": "Mordor", "id": float64(5), "name": "prod"})
	write(engine.NormalizeADOProjectAgentPool("Gondor", 12), map[string]any{"project": "Gondor", "id": float64(12), "name": "SelfHosted"})

	jobs := []map[string]any{
		{"project": "Mordor", "pipeline_id": float64(1), "stage": "deploy", "job": "ship", "targets_environment": "prod.bookings"},
		{"project": "Gondor", "pipeline_id": float64(2), "stage": "build", "job": "b", "pool": map[string]any{"name": "SelfHosted"}},
		{"project": "Gondor", "pipeline_id": float64(3), "stage": "build", "job": "h", "pool": map[string]any{"vm_image": "ubuntu-latest"}},
	}
	if err := deriveJobResourceEdges(prior, cp, normTimer(), jobs); err != nil {
		t.Fatal(err)
	}
	tf, _ := filepath.Glob(filepath.Join(dir, "10-normalize/edges/targets/*.json"))
	if len(tf) != 1 {
		t.Fatalf("want 1 targets edge, got %d", len(tf))
	}
	var tgt map[string]any
	if err := engine.ReadJSON(tf[0], &tgt); err != nil {
		t.Fatal(err)
	}
	if tgt["environment"] != "prod" || tgt["resource"] != "bookings" || tgt["resolved"] != true || int64(tgt["environment_id"].(float64)) != 5 {
		t.Errorf("targets resolution wrong: %v", tgt)
	}
	named := readRunsOn(t, dir, "Gondor", 2, "build", "b")
	if named["pool_name"] != "SelfHosted" || named["resolved"] != true || int64(named["project_agent_pool_id"].(float64)) != 12 {
		t.Errorf("named pool RUNS_ON not resolved: %v", named)
	}
	hosted := readRunsOn(t, dir, "Gondor", 3, "build", "h")
	if hosted["is_hosted"] != true || hosted["resolved"] != false {
		t.Errorf("vmImage pool should be hosted/unresolved: %v", hosted)
	}
}

func readRunsOn(t *testing.T, dir, project string, pipelineID int64, stage, job string) map[string]any {
	t.Helper()
	key := fmt.Sprintf("%s__%d__%s__%s", project, pipelineID, stage, job)
	return readRec(t, dir, engine.NormalizeADOEdges("runs-on", key))
}

func normTimer() *engine.PhaseTimer { return engine.StartPhaseTimer(engine.PhaseNormalize, "test") }

func readRec(t *testing.T, dir, rel string) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := engine.ReadJSON(dir+"/"+rel, &rec); err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return rec
}

// JOIN #1: the job-auth clamp. projectCollection is clamped to project when the
// project enforces; passes through otherwise.
func TestDeriveRunsAs_Clamp(t *testing.T) {
	cp := engineCP(t.TempDir())
	pipelines := []map[string]any{
		{"id": float64(189), "project": "Gondor", "job_authorization_scope": "projectCollection"},
		{"id": float64(200), "project": "Rohan", "job_authorization_scope": "projectCollection"},
	}
	pipelines = append(pipelines, map[string]any{"id": float64(300), "project": "Mirkwood", "job_authorization_scope": "projectCollection"})
	projectsRec := []map[string]any{
		{"project": "Gondor", "limit_job_auth_scope_to_current_project": true, "settings_observed": true},
		{"project": "Rohan", "limit_job_auth_scope_to_current_project": false, "settings_observed": true},
		// Mirkwood's general-settings soft-failed: enforcement is unobserved.
		{"project": "Mirkwood", "limit_job_auth_scope_to_current_project": false, "settings_observed": false},
	}
	if err := deriveRunsAs(cp, normTimer(), pipelines, projectsRec); err != nil {
		t.Fatal(err)
	}
	enforced := readRec(t, cp.RunDir, engine.NormalizeADOEdges("runs-as", "Gondor__189"))
	if enforced["effective_scope"] != "project" || enforced["identity_scope"] != "project" {
		t.Errorf("enforced pipeline not clamped: %v", enforced)
	}
	if enforced["enforce_provenance"] != "observed" {
		t.Errorf("observed enforcement mis-tagged: %v", enforced["enforce_provenance"])
	}
	free := readRec(t, cp.RunDir, engine.NormalizeADOEdges("runs-as", "Rohan__200"))
	if free["effective_scope"] != "projectCollection" || free["identity_scope"] != "collection" {
		t.Errorf("unenforced pipeline wrongly clamped: %v", free)
	}
	// unobserved enforcement must fail CLOSED (clamp to project), not read false.
	unk := readRec(t, cp.RunDir, engine.NormalizeADOEdges("runs-as", "Mirkwood__300"))
	if unk["effective_scope"] != "project" || unk["identity_scope"] != "project" {
		t.Errorf("unobserved enforcement failed open (should clamp to project): %v", unk)
	}
	if unk["enforce_provenance"] != "unknown" || unk["enforced_by_project"] != false {
		t.Errorf("unobserved clamp mis-tagged: %v", unk)
	}
}

// effectiveAllowMask: a PRESENT effectiveAllow of 0 is a real deny; only an
// ABSENT effectiveAllow falls back to the local allow bits.
func TestEffectiveAllowMask(t *testing.T) {
	denied := map[string]any{"allow": float64(7), "extendedInfo": map[string]any{"effectiveAllow": float64(0)}}
	if m := effectiveAllowMask(denied); m != 0 {
		t.Errorf("present effectiveAllow=0 should deny (0), got %d", m)
	}
	absent := map[string]any{"allow": float64(7), "extendedInfo": map[string]any{}}
	if m := effectiveAllowMask(absent); m != 7 {
		t.Errorf("absent effectiveAllow should fall back to allow=7, got %d", m)
	}
	granted := map[string]any{"allow": float64(1), "extendedInfo": map[string]any{"effectiveAllow": float64(5)}}
	if m := effectiveAllowMask(granted); m != 5 {
		t.Errorf("present effectiveAllow=5 should win over allow=1, got %d", m)
	}
}

// JOIN #2: policy-by-scope. A repositoryId scope attributes to that repo only; a
// null repositoryId attributes to every repo in the project.
func TestDerivePolicyAttribution(t *testing.T) {
	cp := engineCP(t.TempDir())
	repos := []map[string]any{
		{"project": "P", "id": "repo-A", "name": "A"},
		{"project": "P", "id": "repo-B", "name": "B"},
	}
	policies := []map[string]any{
		{"project": "P", "config_id": float64(1), "policy_type": "Build", "is_blocking": true,
			"settings": map[string]any{"buildDefinitionId": float64(247)},
			"scope":    []any{map[string]any{"repositoryId": "repo-A", "refName": "refs/heads/main", "matchKind": "Exact"}}},
		{"project": "P", "config_id": float64(2), "policy_type": "Minimum number of reviewers",
			"scope": []any{map[string]any{"repositoryId": nil, "refName": "refs/heads/main", "matchKind": "Exact"}}},
		// a Prefix-scoped policy protecting the whole refs/heads/release/* subtree
		{"project": "P", "config_id": float64(3), "policy_type": "Build",
			"scope": []any{map[string]any{"repositoryId": "repo-A", "refName": "refs/heads/release", "matchKind": "Prefix"}}},
	}
	if err := derivePolicyAttribution(cp, normTimer(), policies, repos); err != nil {
		t.Fatal(err)
	}
	// repo-scoped policy → only repo A; config_id present on both records
	a := readRec(t, cp.RunDir, engine.NormalizeADOEdges("has-policy", "P__A__1__refs-heads-main__Exact__repo-A"))
	if a["repo"] != "A" || a["policy_type"] != "Build" || a["project_wide"] != false || a["is_prefix"] != false {
		t.Errorf("repo-scoped attribution wrong: %v", a)
	}
	bv := readRec(t, cp.RunDir, engine.NormalizeADOEdges("build-validates", "P__A__1__refs-heads-main__Exact__repo-A"))
	if int64(bv["build_definition_id"].(float64)) != 247 || int64(bv["config_id"].(float64)) != 1 {
		t.Errorf("build-validates edge wrong: %v", bv)
	}
	// project-wide policy → both repos, keyed with the "all" scope discriminator
	for _, r := range []string{"A", "B"} {
		rec := readRec(t, cp.RunDir, engine.NormalizeADOEdges("has-policy", "P__"+r+"__2__refs-heads-main__Exact__all"))
		if rec["project_wide"] != true {
			t.Errorf("project-wide attribution missing for repo %s: %v", r, rec)
		}
	}
	// Prefix scope → is_prefix true, match_kind Prefix
	pre := readRec(t, cp.RunDir, engine.NormalizeADOEdges("has-policy", "P__A__3__refs-heads-release__Prefix__repo-A"))
	if pre["is_prefix"] != true || pre["match_kind"] != "Prefix" {
		t.Errorf("prefix attribution wrong: %v", pre)
	}
}

// JOIN #3: effectiveAllow bit-decode (sorted, deterministic) + the SID bridge
// that translates ACL identity descriptors to graph descriptors so nested-group
// expansion actually resolves against real-shaped data.
func TestDecodeActions(t *testing.T) {
	actions := map[int64]string{1: "ViewBuilds", 128: "QueueBuilds", 32768: "CreateBuildDefinition", 2048: "EditBuildDefinition"}
	got := decodeActions(1|128|32768, actions)
	want := []any{"CreateBuildDefinition", "QueueBuilds", "ViewBuilds"} // sorted
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("decodeActions = %v, want sorted %v", got, want)
	}
}

func TestSIDBridgeAndExpand(t *testing.T) {
	// A graph group descriptor base64-encodes the SID the ACL ACE references.
	sid := "S-1-9-1551374245-1032024721-2055204681-2363593361-0-0-0-1-2"
	gdesc := "vssgp." + base64.RawStdEncoding.EncodeToString([]byte(sid))
	if got := decodeGraphSID(gdesc); got != sid {
		t.Fatalf("decodeGraphSID = %q, want %q", got, sid)
	}
	// A build-service graph user descriptor base64url-encodes "<org>:Build:<guid>",
	// exactly the id a ServiceIdentity ACE references.
	svcInner := "acfa0224-cf5c-4ffc-a9ed-df7dfbda07f2:Build:ab33fd1e-fa76-441d-be28-1dff80b1c239"
	svcDesc := "svc." + base64.RawURLEncoding.EncodeToString([]byte(svcInner))
	if got := decodeSubjectDescriptor(svcDesc); got != svcInner {
		t.Fatalf("decodeSubjectDescriptor = %q, want %q", got, svcInner)
	}
	idIndex := map[string]string{sid: gdesc, svcInner: svcDesc}

	// group-form ACE (TeamFoundation.Identity;S-1-…) bridges to the group desc
	if got := aceGraphDescriptor("Microsoft.TeamFoundation.Identity;"+sid, idIndex); got != gdesc {
		t.Fatalf("aceGraphDescriptor(group) = %q, want %q", got, gdesc)
	}
	// ServiceIdentity ACE bridges to the emitted svc. build-service node — the
	// principal node exists, so this must resolve (was previously dropped).
	if got := aceGraphDescriptor("Microsoft.TeamFoundation.ServiceIdentity;"+svcInner, idIndex); got != svcDesc {
		t.Fatalf("aceGraphDescriptor(service identity) = %q, want %q", got, svcDesc)
	}
	// a built-in server SID not present in the graph resolves to "" (unexpanded).
	if got := aceGraphDescriptor("Microsoft.TeamFoundation.Identity;S-1-9-0-0-0-0-0", idIndex); got != "" {
		t.Fatalf("aceGraphDescriptor(unknown) = %q, want empty", got)
	}

	// group → {subgroup, user1}; subgroup → {user2}; cycle back must not loop.
	sub, u1, u2 := "vssgp.SUB", "aad.U1", "aad.U2"
	memberships := map[string][]string{gdesc: {sub, u1}, sub: {u2, gdesc}}
	leaves := expandMembers(gdesc, memberships)
	if len(leaves) != 2 || leaves[0] != u1 || leaves[1] != u2 { // sorted leaves
		t.Fatalf("expandMembers = %v, want sorted [%s %s]", leaves, u1, u2)
	}
	// an unbridged (empty) descriptor expands to nothing
	if len(expandMembers("", memberships)) != 0 {
		t.Error("empty descriptor should expand to []")
	}
}
