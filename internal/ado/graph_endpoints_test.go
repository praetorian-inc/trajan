package ado

import "testing"

var testCtx = graphCtx{
	Org: "org",
	Principal: func(d string) (NodeLabel, bool) {
		l, ok := map[string]NodeLabel{
			"aad.user":  User,
			"vssgp.grp": SecurityGroup,
		}[d]
		return l, ok
	},
}

func keyString(e endpoint) string {
	out := ""
	for i, k := range IdentityKey(e.Label) {
		if i > 0 {
			out += "/"
		}
		out += e.Key[k]
	}
	return out
}

func TestConsumesGroupSourceFollowsLevel(t *testing.T) {
	rec := map[string]any{
		"kind": "CONSUMES_GROUP", "project": "proj", "pipeline_id": int64(1),
		"stage": "s", "job": "b",
		"owner_project": "owner", "variable_group_id": int64(4),
	}
	for _, tc := range []struct {
		level string
		label NodeLabel
		from  string
	}{
		{"pipeline", Pipeline, "org/proj/1"},
		{"stage", Stage, "org/proj/1/s"},
		{"job", Job, "org/proj/1/s/b"},
	} {
		rec["level"] = tc.level
		rs := resolveEndpoints(testCtx, rec)
		if len(rs) != 1 {
			t.Fatalf("%s: resolved %d edges, want 1", tc.level, len(rs))
		}
		if rs[0].From.Label != tc.label || keyString(rs[0].From) != tc.from {
			t.Errorf("%s: from = %s %q, want %s %q",
				tc.level, rs[0].From.Label, keyString(rs[0].From), tc.label, tc.from)
		}
		if got := keyString(rs[0].To); got != "org/owner/4" {
			t.Errorf("%s: a group consumed across projects resolved to %q, not its owner", tc.level, got)
		}
	}

	rec["level"] = "unknown"
	if rs := resolveEndpoints(testCtx, rec); len(rs) != 0 {
		t.Errorf("an unrecognized level resolved %d edges, want 0", len(rs))
	}
}

func TestHasRoleTargetFollowsResourceKind(t *testing.T) {
	for _, tc := range []struct {
		kind     string
		id       string
		resolved bool
		label    NodeLabel
		to       string
	}{
		{"Project", "org/proj", true, Project, "org/proj"},
		{"Repository", "org/proj/r", true, Repository, "org/proj/r"},
		{"ServiceConnection", "owner/c1", true, ServiceConnection, "org/owner/c1"},
		{"Project", "org", true, "", ""},
		{"Project", "org/proj", false, "", ""},
		{"DeploymentGroup", "org/proj", true, "", ""},
	} {
		rs := resolveEndpoints(testCtx, map[string]any{
			"kind": "HAS_ROLE", "resource_kind": tc.kind, "resource_id": tc.id,
			"resource_resolved": tc.resolved, "graph_descriptor": "vssgp.grp",
		})
		if !tc.resolved || tc.label == "" {
			if len(rs) != 0 {
				t.Errorf("%s %q resolved=%v: got %d edges, want 0", tc.kind, tc.id, tc.resolved, len(rs))
			}
			continue
		}
		if len(rs) != 1 {
			t.Fatalf("%s: resolved %d edges, want 1", tc.kind, len(rs))
		}
		if rs[0].To.Label != tc.label || keyString(rs[0].To) != tc.to {
			t.Errorf("%s: to = %s %q, want %s %q", tc.kind, rs[0].To.Label, keyString(rs[0].To), tc.label, tc.to)
		}
	}
}

func TestAttackEdgeFansOutOverSourcePrincipals(t *testing.T) {
	rs := resolveEndpoints(testCtx, map[string]any{
		"kind": "PIPELINE_POISONING", "project": "proj", "pipeline_id": int64(1),
		"stage": "s", "job": "b",
		"source_principals": []any{
			map[string]any{"descriptor": "aad.user"},
			map[string]any{"descriptor": "vssgp.grp"},
			map[string]any{"descriptor": "aad.uncollected"},
		},
	})
	if len(rs) != 2 {
		t.Fatalf("resolved %d edges, want 2: an uncollected principal has no label to point at", len(rs))
	}
	for i, want := range []NodeLabel{User, SecurityGroup} {
		if rs[i].From.Label != want {
			t.Errorf("[%d] from = %s, want %s", i, rs[i].From.Label, want)
		}
		if got := keyString(rs[i].To); got != "org/proj/1/s/b" {
			t.Errorf("[%d] to = %q", i, got)
		}
	}
}

func TestIncompleteIdentityDoesNotResolve(t *testing.T) {
	for _, rec := range []map[string]any{
		{"kind": "DEFINED_BY", "project": "proj", "repo": "r", "pipeline_id": int64(1)},
		{"kind": "RUNS_ON", "project": "proj", "pipeline_id": int64(1), "job": "b", "project_agent_pool_id": int64(3)},
		{"kind": "TARGETS", "project": "proj", "pipeline_id": int64(1), "stage": "s", "job": "b"},
		{"kind": "READS", "project": "proj", "pipeline_id": int64(1), "stage": "s", "job": "b", "secret_name": "S"},
	} {
		if rs := resolveEndpoints(testCtx, rec); len(rs) != 0 {
			t.Errorf("%s resolved despite an incomplete identity", rec["kind"])
		}
	}
}
