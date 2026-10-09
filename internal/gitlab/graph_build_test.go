package gitlab

import (
	"slices"
	"testing"

	"github.com/praetorian-inc/trajan/internal/graph"
)

func rec(dir, id string, fields map[string]any) graph.Record {
	if fields == nil {
		fields = map[string]any{}
	}
	fields["_id"] = id
	return graph.Record{Rel: dir + "/" + id + ".json", Dir: dir, ID: id, Fields: fields}
}

func projectScoped(path string) map[string]any {
	return map[string]any{"_provenance": []any{map[string]any{"scope": "project:" + path}}}
}

func scopeCorpus() []graph.Record {
	const proj = "acme/platform/api"
	return []graph.Record{
		rec("instance", "instance", nil),
		rec("groups", "acme", nil),
		rec("groups", "acme/platform", nil),
		rec("projects", proj, nil),
		rec("merge-requests", proj, nil),
		rec("jobs", proj+":build", map[string]any{"project": proj}),
		rec("environments", proj+"/production", map[string]any{"name": "production"}),
		rec("environments", proj+"/review/mr-1", map[string]any{"name": "review/mr-1"}),
		rec("agents", proj+"/prod-agent", nil),
		rec("integrations", proj+"/slack:hooks", map[string]any{"kind": "slack"}),
		rec("credentials", "deploy_token:abc", projectScoped(proj)),
		rec("runners", "7", map[string]any{"_provenance": []any{map[string]any{"scope": "group:acme"}}}),
		rec("runners", "8", projectScoped(proj)),
	}
}

func buildScope(t *testing.T) (*glCorpus, *nodeSet, *edgeSet) {
	t.Helper()
	c, err := indexCorpus(&graph.Corpus{Records: scopeCorpus()})
	if err != nil {
		t.Fatalf("indexCorpus: %v", err)
	}
	n, err := buildNodes(t.Context(), c)
	if err != nil {
		t.Fatalf("buildNodes: %v", err)
	}
	s, err := buildEdges(t.Context(), c)
	if err != nil {
		t.Fatalf("buildEdges: %v", err)
	}
	return c, n, s
}

func TestScopeRootIsTheShortestGroupPath(t *testing.T) {
	c, _, _ := buildScope(t)
	if c.org != "acme" {
		t.Errorf("org = %q, want acme", c.org)
	}
}

func TestScopeRootFallsBackToTheProjectNamespace(t *testing.T) {
	c, err := indexCorpus(&graph.Corpus{Records: []graph.Record{rec("projects", "acme/platform/api", nil)}})
	if err != nil {
		t.Fatalf("indexCorpus: %v", err)
	}
	if c.org != "acme/platform" {
		t.Errorf("org = %q, want acme/platform", c.org)
	}
}

func TestEmptyCorpusHasNoScope(t *testing.T) {
	_, err := indexCorpus(&graph.Corpus{Records: []graph.Record{rec("runners", "7", nil)}})
	if err == nil {
		t.Fatal("want ErrNoOrgRecord, got nil")
	}
}

func TestContainmentFollowsTheGitLabHierarchy(t *testing.T) {
	const proj = "acme/platform/api"
	want := [][3]string{
		{"CONTAINS", "Instance|instance", "Group|acme"},
		{"CONTAINS", "Group|acme", "Group|acme/platform"},
		{"CONTAINS", "Group|acme/platform", "Project|" + proj},
		{"CONTAINS", "Group|acme", "Runner|7"},
		{"CONTAINS", "Project|" + proj, "Runner|8"},
		{"CONTAINS", "Project|" + proj, "Job|" + proj + ":build"},
		{"CONTAINS", "Project|" + proj, "MergeRequest|" + proj},
		{"CONTAINS", "Project|" + proj, "Environment|" + proj + "/production"},
		{"CONTAINS", "Project|" + proj, "Environment|" + proj + "/review/mr-1"},
		{"CONTAINS", "Project|" + proj, "Agent|" + proj + "/prod-agent"},
		{"CONTAINS", "Project|" + proj, "Integration|" + proj + "/slack:hooks"},
		{"CONTAINS", "Project|" + proj, "Credential|deploy_token:abc"},
	}
	_, _, s := buildScope(t)
	got := make([][3]string, 0, len(s.All()))
	for _, e := range s.All() {
		got = append(got, [3]string{string(e.Type), e.From, e.To})
	}
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("missing edge %s %s -> %s", w[0], w[1], w[2])
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d edges, want %d:\n%v", len(got), len(want), got)
	}
}

func TestHierarchyNamesTheOwningProject(t *testing.T) {
	const proj = "acme/platform/api"
	want := map[string][]string{
		"Instance|instance":                    {"acme"},
		"Group|acme":                           {"acme"},
		"Group|acme/platform":                  {"acme"},
		"Project|" + proj:                      {"acme", proj},
		"Job|" + proj + ":build":               {"acme", proj},
		"Environment|" + proj + "/production":  {"acme", proj},
		"Environment|" + proj + "/review/mr-1": {"acme", proj},
		"Credential|deploy_token:abc":          {"acme", proj},
		"Runner|7":                             {"acme"},
		"Runner|8":                             {"acme", proj},
		"Agent|" + proj + "/prod-agent":        {"acme", proj},
		"Integration|" + proj + "/slack:hooks": {"acme", proj},
		"MergeRequest|" + proj:                 {"acme", proj},
	}
	c, n, _ := buildScope(t)
	p := GraphProvider()
	for _, node := range n.All() {
		w, ok := want[node.ID]
		if !ok {
			t.Errorf("unexpected node %s", node.ID)
			continue
		}
		if got := p.Hierarchy(c.org, node); !slices.Equal(got, w) {
			t.Errorf("%s hierarchy = %v, want %v", node.ID, got, w)
		}
	}
	if len(n.All()) != len(want) {
		t.Errorf("got %d nodes, want %d", len(n.All()), len(want))
	}
}

func TestChainAnchorsResolveToEmittedNodes(t *testing.T) {
	const proj = "acme/platform/api"
	part := func(id string) map[string]any { return map[string]any{"_id": id} }
	chains := map[string]map[string]any{
		"job-token-allowlist": {"edges": []any{map[string]any{
			"_id": "jtoken", "source": part(proj), "target": part(proj)}}},
		"protected-var-reachability": {"reachable_vars": []any{map[string]any{
			"_id": "pvr", "project": proj}}},
		"dotenv-flow": {"edges": []any{map[string]any{
			"_id": "dotenv", "producer": part(proj + ":build"), "consumer": part(proj + ":build")}}},
		"cache-keyspace": {"prefix_overlaps": []any{map[string]any{
			"_id": "cache", "project": proj}}},
		"cross-project-artifact": {"edges": []any{map[string]any{
			"_id": "xpart", "consumer": part(proj + ":build"), "producer": part(proj)}}},
		"deploy-key-reuse": {"reused_keys": []any{map[string]any{
			"_id": "dkey", "projects": []any{proj}}}},
		"agent-ci-access": {"grants": []any{map[string]any{
			"_id": "agentci", "agent": part(proj + "/prod-agent"), "project": part(proj)}}},
		"runner-reachability": {"reachable_runners": []any{map[string]any{
			"_id": "runreach", "runner": part("7")}}},
		"group-runner-reachability": {"reachable_runners": []any{map[string]any{
			"_id": "grpreach", "runner": part("7"), "group": part("acme")}}},
	}

	c, n, _ := buildScope(t)
	c.chains = chains
	a := newAttacher(c, n, map[string]graph.Target{})
	if len(a.chain) != len(chains) {
		t.Fatalf("indexed %d tuples, want %d", len(a.chain), len(chains))
	}
	for id, anchors := range a.chain {
		if len(anchors) == 0 {
			t.Errorf("tuple %s anchored nothing", id)
			continue
		}
		for _, an := range anchors {
			if n.Get(an.id) == nil {
				t.Errorf("tuple %s anchors %s, which no record emitted", id, an.id)
			}
		}
	}
}
