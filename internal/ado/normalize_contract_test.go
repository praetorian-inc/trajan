package ado

import (
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// clampScope is fail-closed: an unobserved enforce flag clamps to project, and an
// observed non-enforcing project passes the requested collection scope through.
func TestClampScope(t *testing.T) {
	cases := []struct {
		requested                    string
		enforced, observed           bool
		wantEff, wantScope, wantProv string
	}{
		{"projectCollection", false, true, "projectCollection", "collection", "observed"},
		{"projectCollection", true, true, "project", "project", "observed"},
		{"projectCollection", false, false, "project", "project", "unknown"}, // fail closed
		{"project", false, true, "project", "project", "observed"},
	}
	for _, c := range cases {
		eff, scope, prov := clampScope(c.requested, c.enforced, c.observed)
		if eff != c.wantEff || scope != c.wantScope || prov != c.wantProv {
			t.Errorf("clampScope(%q,%v,%v) = %q/%q/%q, want %q/%q/%q",
				c.requested, c.enforced, c.observed, eff, scope, prov, c.wantEff, c.wantScope, c.wantProv)
		}
	}
}

// resolveRoleToken maps ACL namespace tokens to the emitted node they scope.
func TestResolveRoleToken(t *testing.T) {
	repoIdx := map[string]string{"repo-guid": "org/P/myrepo"}
	scIdx := map[string]string{"conn-1": "Owner/conn-1"}
	projIdx := map[string]string{"proj-guid": "org/P"}
	cases := []struct{ token, wantKind, wantID string }{
		{"repoV2/proj-guid/repo-guid", "Repository", "org/P/myrepo"},
		{"endpoints/proj-guid/conn-1", "ServiceConnection", "Owner/conn-1"},
		{"proj-guid", "Project", "org/P"},
		{"repoV2/proj-guid/unknown-repo", "Repository", ""}, // repo not indexed -> unresolved
		{"$PROJECT:vstfs:///unknown", "", ""},               // not a recognized shape
	}
	for _, c := range cases {
		k, id := resolveRoleToken(c.token, repoIdx, scIdx, projIdx)
		if k != c.wantKind || id != c.wantID {
			t.Errorf("resolveRoleToken(%q) = %q/%q, want %q/%q", c.token, k, id, c.wantKind, c.wantID)
		}
	}
}

// policySettings projects raw camelCase branch-policy settings to schema snake_case.
func TestPolicySettings(t *testing.T) {
	got := policySettings(map[string]any{
		"creatorVoteCounts": true, "minimumApproverCount": float64(2),
		"blockLastPusherVote": true, "buildDefinitionId": float64(9), "manualQueueOnly": true,
	})
	if got["creator_vote_counts"] != true || got["block_last_pusher_vote"] != true || got["manual_queue_only"] != true {
		t.Errorf("bool mapping wrong: %v", got)
	}
	if got["minimum_approver_count"] != int64(2) || got["build_definition_id"] != int64(9) {
		t.Errorf("int mapping wrong: %v", got)
	}
	if _, ok := got["creatorVoteCounts"]; ok {
		t.Error("raw camelCase key leaked into output")
	}
}

// CONSUMES_GROUP is emitted at each declaration level (pipeline/stage/job) with the
// level property and the group's owner_project (so a shared group binds to owner/id).
func TestConsumesGroupLevels(t *testing.T) {
	dir := t.TempDir()
	cp, prior := engineCP(dir), engine.PriorPhase{RunDir: dir}
	write := func(rel string, rec any) {
		if err := engine.WriteJSON(filepath.Join(dir, rel), rec); err != nil {
			t.Fatal(err)
		}
	}
	write(engine.NormalizeADOVariableGroup("Owner", 7), map[string]any{
		"_id": "Owner/7", "kind": "VariableGroup", "id": float64(7), "name": "prod-secrets",
		"owner_project": "Owner", "visible_in_projects": []any{"Owner"},
	})
	write(engine.NormalizeADOPipeline("Owner", 1), map[string]any{
		"project": "Owner", "id": float64(1), "variable_groups": []any{"prod-secrets"},
	})
	write(engine.NormalizeADOStage("Owner", 1, "deploy"), map[string]any{
		"project": "Owner", "pipeline_id": float64(1), "stage": "deploy", "variable_groups": []any{"prod-secrets"},
	})
	jobs := []map[string]any{
		{"project": "Owner", "pipeline_id": float64(1), "stage": "deploy", "job": "ship", "variable_groups": []any{"prod-secrets"}},
	}
	if err := deriveJobResourceEdges(prior, cp, normTimer(), jobs); err != nil {
		t.Fatal(err)
	}
	byLevel := map[string]map[string]any{}
	for _, f := range mustGlob(t, dir, "10-normalize/edges/consumes-group/*.json") {
		var e map[string]any
		if err := engine.ReadJSON(f, &e); err != nil {
			t.Fatal(err)
		}
		byLevel[e["level"].(string)] = e
	}
	for _, lvl := range []string{"pipeline", "stage", "job"} {
		e, ok := byLevel[lvl]
		if !ok {
			t.Fatalf("missing CONSUMES_GROUP at level %s", lvl)
		}
		if e["owner_project"] != "Owner" || e["resolved"] != true || int64(e["variable_group_id"].(float64)) != 7 {
			t.Errorf("level %s edge wrong: %v", lvl, e)
		}
	}
}

// resolveTemplateSources resolves a resources.repositories alias to its source
// repo, flagging cross-project and unpinned (default-branch) sources — the cat-08
// poisoned-template surface that was previously an opaque alias string.
func TestResolveTemplateSources(t *testing.T) {
	root := map[string]any{
		"resources": map[string]any{
			"repositories": []any{
				map[string]any{"repository": "templates", "type": "git", "name": "BuildTemplates"},                                         // same project, unpinned
				map[string]any{"repository": "shared", "type": "git", "name": "PlatformProject/SharedTemplates", "ref": "refs/heads/main"}, // cross-project, pinned
			},
		},
	}
	list, byAlias := resolveTemplateSources(root, "MyProject")
	if len(list) != 2 {
		t.Fatalf("want 2 sources, got %d", len(list))
	}
	same := byAlias["templates"]
	if same["repository"] != "BuildTemplates" || same["source_project"] != "MyProject" || same["is_cross_project"] != false || same["ref_pinned"] != false {
		t.Errorf("same-project source wrong: %v", same)
	}
	cross := byAlias["shared"]
	if cross["repository"] != "SharedTemplates" || cross["source_project"] != "PlatformProject" || cross["is_cross_project"] != true || cross["ref_pinned"] != true {
		t.Errorf("cross-project source wrong: %v", cross)
	}
}

// normalizeParameters flags a queue-time-settable string/number/object param with
// no values allowlist as freeform — the cat-02 injection surface.
func TestNormalizeParameters(t *testing.T) {
	got := normalizeParameters([]any{
		map[string]any{"name": "tag", "type": "string"},                                 // freeform
		map[string]any{"name": "env", "type": "string", "values": []any{"dev", "prod"}}, // allowlisted
		map[string]any{"name": "extraSteps", "type": "stepList"},                        // not injectable text
		map[string]any{"name": "count", "type": "number"},                               // freeform
	})
	want := map[string]bool{"tag": true, "env": false, "extraSteps": false, "count": true}
	if len(got) != 4 {
		t.Fatalf("want 4 params, got %d", len(got))
	}
	for _, raw := range got {
		p := raw.(map[string]any)
		if p["is_freeform"] != want[p["name"].(string)] {
			t.Errorf("%s is_freeform = %v, want %v", p["name"], p["is_freeform"], want[p["name"].(string)])
		}
	}
}

func mustGlob(t *testing.T, dir, pat string) []string {
	t.Helper()
	fs, err := filepath.Glob(filepath.Join(dir, pat))
	if err != nil {
		t.Fatal(err)
	}
	return fs
}
