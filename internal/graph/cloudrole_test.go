package graph

import (
	"slices"
	"testing"
)

// callerEdge is a reusable-callgraph row: caller job -> shared-workflows/deploy.yml
// carrying the inputs that call site passed.
func callerEdge(repo, roleARN string) map[string]any {
	return map[string]any{
		"caller": map[string]any{"_id": repo + "__deploy__deploy", "repo": repo,
			"workflow_filename": "deploy.yml", "job_id": "deploy"},
		"callee": map[string]any{"repo": "shared-workflows", "path": ".github/workflows/deploy.yml",
			"is_local": false, "inputs": map[string]any{"role-arn": roleARN}},
	}
}

func calleeCorpus(t *testing.T, callers ...map[string]any) (*nodeSet, *edgeSet) {
	t.Helper()
	files := map[string]any{
		"org/portus-labs.json": map[string]any{"_id": "portus-labs", "org": "portus-labs"},
		"chains/reusable-callgraph.json": map[string]any{
			"chain": "reusable-callgraph", "edges": anySlice(callers)},
		"jobs/shared-workflows__deploy__deploy.json": map[string]any{
			"_id": "shared-workflows__deploy__deploy", "repo": "shared-workflows",
			"workflow_filename": "deploy.yml", "job_id": "deploy",
			"cloud_roles": []any{map[string]any{
				"provider": "aws", "identifier": "${{ inputs.role-arn }}"}},
		},
	}
	c, n := fixture(t, files)
	s, err := buildEdges(t.Context(), c, n)
	if err != nil {
		t.Fatalf("buildEdges: %v", err)
	}
	return n, s
}

func anySlice(ms []map[string]any) []any {
	out := make([]any, 0, len(ms))
	for _, m := range ms {
		out = append(out, m)
	}
	return out
}

func cloudRoleIDs(n *nodeSet) []string {
	out := []string{}
	for _, node := range n.all() {
		if node.Labels[0] == CloudRole {
			out = append(out, node.Key["identifier"])
		}
	}
	slices.Sort(out)
	return out
}

// A reusable callee names its role "${{ inputs.role-arn }}"; only the call site
// knows the literal. One caller resolves it; two callers passing different
// values leave it unresolvable, because picking either would assert a role the
// other caller's deployment never assumes.
func TestCloudRoleResolvesThroughCallerInputsAndDropsDisputedOnes(t *testing.T) {
	const arn = "arn:aws:iam::929514686768:role/portus-payments-api-deploy"

	t.Run("single caller resolves", func(t *testing.T) {
		n, s := calleeCorpus(t, callerEdge("payments-api", arn))
		if got := cloudRoleIDs(n); !slices.Equal(got, []string{arn}) {
			t.Errorf("CloudRole nodes = %v, want [%s]", got, arn)
		}
		got := edgesOfType(s, CanAssume)
		if len(got) != 1 || got[0].To != nodeID(CloudRole, map[string]string{"identifier": arn}) {
			t.Errorf("CAN_ASSUME = %v, want one edge into the caller's literal ARN", got)
		}
		if miss := s.unbuilt[edgeKey(CanAssume, Job, CloudRole)]; miss != 0 {
			t.Errorf("unbuilt CAN_ASSUME = %d, want 0", miss)
		}
	})

	t.Run("agreeing callers resolve", func(t *testing.T) {
		n, _ := calleeCorpus(t, callerEdge("payments-api", arn), callerEdge("portus-cli", arn))
		if got := cloudRoleIDs(n); !slices.Equal(got, []string{arn}) {
			t.Errorf("CloudRole nodes = %v, want [%s]: the callers agree", got, arn)
		}
	})

	t.Run("disputed input is dropped, not guessed", func(t *testing.T) {
		n, s := calleeCorpus(t,
			callerEdge("payments-api", arn),
			callerEdge("portus-cli", "arn:aws:iam::111122223333:role/other"))
		if got := cloudRoleIDs(n); len(got) != 0 {
			t.Errorf("CloudRole nodes = %v, want none: the callers disagree on role-arn", got)
		}
		if got := edgesOfType(s, CanAssume); len(got) != 0 {
			t.Errorf("CAN_ASSUME = %v, want none", got)
		}
		if miss := s.unbuilt[edgeKey(CanAssume, Job, CloudRole)]; miss != 1 {
			t.Errorf("unbuilt CAN_ASSUME = %d, want 1: the relation is asserted and unresolvable", miss)
		}
	})

	t.Run("no caller leaves the expression unresolved", func(t *testing.T) {
		n, s := calleeCorpus(t)
		if got := cloudRoleIDs(n); len(got) != 0 {
			t.Errorf("CloudRole nodes = %v, want none: ${{ }} is not a role identity", got)
		}
		if miss := s.unbuilt[edgeKey(CanAssume, Job, CloudRole)]; miss != 1 {
			t.Errorf("unbuilt CAN_ASSUME = %d, want 1", miss)
		}
	})
}
