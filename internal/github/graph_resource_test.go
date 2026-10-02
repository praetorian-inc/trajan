package github

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"testing"

	"github.com/praetorian-inc/trajan/internal/graph"
)

func TestResourceHierarchyDegradesToTheOrgWhenNoRepoIsOwned(t *testing.T) {
	const org = "ghektestorg"
	cases := []struct {
		name string
		node graph.Node[NodeLabel]
		want []string
	}{
		{"repository names itself",
			graph.Node[NodeLabel]{Key: map[string]string{"full_name": org + "/conf-ci"}},
			[]string{org, org + "/conf-ci"}},
		{"branch carries a qualified repo key",
			graph.Node[NodeLabel]{Key: map[string]string{"repo": org + "/conf-ci", "name": "main"}},
			[]string{org, org + "/conf-ci"}},
		{"ruleset carries the repo only as a property",
			graph.Node[NodeLabel]{Key: map[string]string{"scope": "repo", "scope_key": org + "/conf-ci", "id": "1"},
				Properties: map[string]any{"repo": org + "/conf-ci"}},
			[]string{org, org + "/conf-ci"}},
		{"organization owns no repo",
			graph.Node[NodeLabel]{Key: map[string]string{"login": org}},
			[]string{org}},
		{"unqualified repo is not a path",
			graph.Node[NodeLabel]{Key: map[string]string{"repo": "conf-ci", "name": "main"}},
			[]string{org}},
		{"foreign org repo is not this org's",
			graph.Node[NodeLabel]{Key: map[string]string{"repo": "otherorg/shared-ci", "name": "main"}},
			[]string{org}},
		{"an org whose name only prefixes the owner",
			graph.Node[NodeLabel]{Key: map[string]string{"repo": org + "2/conf-ci", "name": "main"}},
			[]string{org}},
		{"org-scoped runner group",
			graph.Node[NodeLabel]{Key: map[string]string{"org": org, "id": "3"}},
			[]string{org}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := GraphProvider().Hierarchy(org, tc.node); !slices.Equal(got, tc.want) {
				t.Errorf("resourceHierarchy = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResourceNameAndURLDerivation(t *testing.T) {
	cases := []struct {
		name     string
		label    NodeLabel
		node     graph.Node[NodeLabel]
		wantName string
		wantURL  string
	}{
		{"named property wins", Repository,
			graph.Node[NodeLabel]{Key: map[string]string{"full_name": "ghektestorg/conf-ci"},
				Properties: map[string]any{"name": "conf-ci", "html_url": "https://github.com/ghektestorg/conf-ci"}},
			"conf-ci", "https://github.com/ghektestorg/conf-ci"},
		{"last identity value stands in", Branch,
			graph.Node[NodeLabel]{Key: map[string]string{"repo": "ghektestorg/conf-ci", "name": "main"}},
			"main", ""},
		{"a job is named by its job id, not its repo", Job,
			graph.Node[NodeLabel]{Key: map[string]string{"repo": "ghektestorg/conf-ci",
				"workflow": ".github/workflows/main.yml", "job_id": "deploy"}},
			"deploy", ""},
		{"an api path is not a url", Repository,
			graph.Node[NodeLabel]{Key: map[string]string{"full_name": "ghektestorg/conf-ci"},
				Properties: map[string]any{"url": "/repos/ghektestorg/conf-ci"}},
			"ghektestorg/conf-ci", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.node.Labels = []NodeLabel{tc.label}
			got := graph.ToResources(GraphProvider(), "ghektestorg", []graph.Node[NodeLabel]{tc.node})
			if len(got) != 1 {
				t.Fatalf("ToResources returned %d resources, want 1", len(got))
			}
			if got[0].Name != tc.wantName {
				t.Errorf("Name = %q, want %q", got[0].Name, tc.wantName)
			}
			if got[0].URL != tc.wantURL {
				t.Errorf("URL = %q, want %q", got[0].URL, tc.wantURL)
			}
		})
	}
}

func TestEveryBuiltNodeAndEdgeConverts(t *testing.T) {
	const repo = "fr-06-01-aws-org-wildcard-sub"
	c, n := fixture(t, map[string]any{
		"org/ghektestorg.json": map[string]any{"_id": "ghektestorg", "org": "ghektestorg",
			"html_url": "https://github.com/ghektestorg"},
		"repos/" + repo + ".json": map[string]any{"_id": repo, "repo": repo,
			"name": repo, "html_url": "https://github.com/ghektestorg/" + repo},
		"principals/attacker.json": map[string]any{"_id": "attacker", "kind": "user", "login": "attacker"},
		"environments/prod.json": map[string]any{"_id": repo + "__prod", "repo": repo, "name": "prod",
			"reviewers_required":       []any{map[string]any{"type": "User", "login": "attacker"}},
			"deployment_branch_policy": map[string]any{"patterns": []any{"main"}}},
		"tags/v1.json":     map[string]any{"_id": repo + "@v1", "repo": repo, "name": "v1"},
		"secrets/aws.json": map[string]any{"_id": repo + "__AWS", "scope": "repo", "repo": repo, "name": "AWS_KEY"},
		"rulesets/main.json": map[string]any{"_id": "main", "scope": "repo", "owner": "ghektestorg",
			"repo": repo, "ruleset_id": 1, "name": "default", "enforcement": "active"},
		"jobs/" + repo + "__main__pwn.json": map[string]any{
			"_id": repo + "__main__pwn", "repo": repo,
			"workflow_filename": "main.yml", "job_id": "pwn", "branch": "main",
			"oidc_sub_template": "repo:<owner>/<repo>:ref:<ref>",
			"secret_reads":      []any{"AWS_KEY"},
			"cloud_roles": []any{map[string]any{
				"provider": "aws", "identifier": "arn:aws:iam::000000000000:role/fr-06-01-role"}},
		},
		"chains/effective-ruleset.json": map[string]any{"chain": "effective-ruleset",
			"effective_per_branch": []any{map[string]any{"repo": repo, "branch": "main"}}},
	})
	s, err := buildEdges(t.Context(), c, n)
	if err != nil {
		t.Fatalf("buildEdges: %v", err)
	}
	nodes, edges := n.All(), s.All()
	if len(nodes) == 0 || len(edges) == 0 {
		t.Fatalf("the fixture built %d nodes and %d edges", len(nodes), len(edges))
	}

	before := make([]map[string]any, len(nodes))
	for i := range nodes {
		before[i] = maps.Clone(nodes[i].Properties)
	}

	resources := graph.ToResources(GraphProvider(), c.org, nodes)
	if len(resources) != len(nodes) {
		t.Errorf("converted %d of %d nodes", len(resources), len(nodes))
	}
	labels := map[NodeLabel]bool{}
	for i, r := range resources {
		labels[nodes[i].Labels[0]] = true
		if r.Type == "" {
			t.Errorf("node %s (%s) converted with no type", r.ID, nodes[i].Labels[0])
		}
		if r.ID == "" || r.Name == "" {
			t.Errorf("node %s converted with id %q name %q", nodes[i].ID, r.ID, r.Name)
		}
		if r.Hierarchy[0] != c.org {
			t.Errorf("node %s hierarchy = %v, want it rooted at %s", r.ID, r.Hierarchy, c.org)
		}
		for k, v := range nodes[i].Key {
			if r.Props[k] != v {
				t.Errorf("node %s props[%q] = %v, want the identity value %q", r.ID, k, r.Props[k], v)
			}
		}
	}
	if len(labels) < 8 {
		t.Errorf("the fixture exercised only %d labels: %v", len(labels), labels)
	}
	for i := range nodes {
		if !reflect.DeepEqual(before[i], nodes[i].Properties) {
			t.Errorf("node %s properties were mutated by the conversion", nodes[i].ID)
		}
	}

	rels := graph.ToRelationships(GraphProvider(), edges)
	if len(rels) != len(edges) {
		t.Errorf("converted %d of %d edges", len(rels), len(edges))
	}
	types := map[EdgeType]bool{}
	for i, rel := range rels {
		types[edges[i].Type] = true
		if rel.Type == "" {
			t.Errorf("edge %s (%s) converted with no type", edges[i].ID, edges[i].Type)
		}
		if rel.From != edges[i].From || rel.To != edges[i].To {
			t.Errorf("edge %s endpoints = %s -> %s, want %s -> %s", edges[i].ID, rel.From, rel.To, edges[i].From, edges[i].To)
		}
	}
	if len(types) < 4 {
		t.Errorf("the fixture exercised only %d edge types: %v", len(types), types)
	}
}

func TestFindingRefsSerializeAsAnEmptyArrayWhenUnattached(t *testing.T) {
	attached := graph.Node[NodeLabel]{ID: "x", Labels: []NodeLabel{Repository},
		Key: map[string]string{"full_name": "ghektestorg/conf-ci"},
		Findings: []graph.FindingRef{
			{RuleID: "cat-01/a", Fingerprint: "1", Severity: "high", Confidence: "high"},
			{RuleID: "cat-02/b", Fingerprint: "2", Severity: "low", Confidence: "medium"},
		}}
	if got := graph.ToResources(GraphProvider(), "ghektestorg", []graph.Node[NodeLabel]{attached})[0].Findings; len(got) != 2 {
		t.Fatalf("converted %d of 2 findings", len(got))
	}

	bare := graph.Node[NodeLabel]{ID: "y", Labels: []NodeLabel{Repository}, Key: map[string]string{"full_name": "ghektestorg/x"}}
	got := graph.ToResources(GraphProvider(), "ghektestorg", []graph.Node[NodeLabel]{bare})[0].Findings
	if got == nil || len(got) != 0 {
		t.Fatalf("findings = %v, want an empty slice", got)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "[]" {
		t.Errorf("marshaled %s, want []", b)
	}
}
