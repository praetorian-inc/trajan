package ado

import (
	"slices"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/graph"
)

func adoNode(l NodeLabel, key map[string]string, props map[string]any) node {
	if props == nil {
		props = map[string]any{}
	}
	return node{
		ID:         graph.NodeID(adoSchema{}, l, key),
		Labels:     []NodeLabel{l},
		Key:        key,
		Properties: props,
	}
}

func TestHierarchyNamesProjectThenRepo(t *testing.T) {
	cases := []struct {
		name string
		n    node
		want []string
	}{
		{"organization", adoNode(Organization, map[string]string{"org": "org"}, nil),
			[]string{"org"}},
		{"project", adoNode(Project, map[string]string{"org": "org", "project": "proj"}, nil),
			[]string{"org", "proj"}},
		{"repository", adoNode(Repository,
			map[string]string{"org": "org", "project": "proj", "repo": "r"}, nil),
			[]string{"org", "proj", "r"}},
		{"branch", adoNode(Branch,
			map[string]string{"org": "org", "project": "proj", "repo": "r", "name": "b"}, nil),
			[]string{"org", "proj", "r"}},
		{"pipeline on azure repos", adoNode(Pipeline,
			map[string]string{"org": "org", "project": "proj", "pipeline_id": "12"},
			map[string]any{"repo": "r"}),
			[]string{"org", "proj", "r"}},
		{"pipeline on a foreign repo", adoNode(Pipeline,
			map[string]string{"org": "org", "project": "proj", "pipeline_id": "13"}, nil),
			[]string{"org", "proj"}},
		{"job", adoNode(Job, map[string]string{
			"org": "org", "project": "proj", "pipeline_id": "12", "stage": "build", "job": "test"},
			map[string]any{"repo": "r"}),
			[]string{"org", "proj", "r"}},
		{"service connection", adoNode(ServiceConnection,
			map[string]string{"org": "org", "owner_project": "proj", "connection_id": "abc"}, nil),
			[]string{"org", "proj"}},
		{"key vault", adoNode(KeyVault, map[string]string{"name": "kv"}, nil),
			[]string{"org"}},
	}
	p := GraphProvider()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := p.Hierarchy("org", c.n); !slices.Equal(got, c.want) {
				t.Errorf("Hierarchy = %v, want %v", got, c.want)
			}
		})
	}
}

func TestRepoContainmentSkipsPipelinesWithNoAzureRepo(t *testing.T) {
	n := newNodeSet()
	n.Upsert(Pipeline, map[string]string{"org": "org", "project": "proj", "pipeline_id": "12"},
		map[string]any{"repo": "r"}, "")
	n.Upsert(Pipeline, map[string]string{"org": "org", "project": "proj", "pipeline_id": "13"},
		map[string]any{"repo": ""}, "")
	n.Upsert(Repository, map[string]string{"org": "org", "project": "proj", "repo": "r"}, nil, "")

	s := newEdgeSet()
	emitRepoContainment(n, s)

	want := []string{"HAS_PIPELINE|Repository\\|org\\|proj\\|r|Pipeline\\|org\\|proj\\|12"}
	got := s.IDs()
	if !slices.Equal(got, want) {
		t.Errorf("edges = %v, want %v", got, want)
	}
}

func TestWIFCredentialResolvesWithAndWithoutASubject(t *testing.T) {
	for _, tc := range []struct{ name, spn, subject, credential string }{
		{"automatic", "spn-1", "sc://org/proj/c1", "spn-1"},
		{"manual", "spn-1", "", "spn-1"},
		{"no app registration", "", "sc://org/proj/c1", "sc://org/proj/c1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			conn := map[string]any{"authorization": map[string]any{
				"scheme": "WorkloadIdentityFederation",
				"parameters": map[string]any{
					"serviceprincipalid":                tc.spn,
					"workloadIdentityFederationSubject": tc.subject,
				},
			}}
			if err := emitWIFCredential(engineCP(dir), normTimer(), conn, "c1", "proj"); err != nil {
				t.Fatal(err)
			}

			c := &corpus{org: "org"}
			n := newNodeSet()
			rec := readRec(t, dir, engine.NormalizeADOWIFCredential("c1", tc.credential))
			cred := n.Upsert(WIFCredential, c.identityOf(WIFCredential, rec), nil, "")
			if cred == nil {
				t.Fatalf("no WIFCredential node from %v", c.identityOf(WIFCredential, rec))
			}

			fed := readRec(t, dir, engine.NormalizeADOEdges("federates-to", "c1"))
			rs := resolveEndpoints(testCtx, fed)
			if len(rs) != 1 {
				t.Fatalf("FEDERATES_TO resolved %d edges, want 1", len(rs))
			}
			if got := n.NodeID(WIFCredential, rs[0].To.Key); got != cred.ID {
				t.Errorf("edge targets %q, the node is %q", got, cred.ID)
			}
		})
	}
}
