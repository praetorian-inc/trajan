package ado

import (
	"context"

	"github.com/praetorian-inc/trajan/internal/graph"
	"github.com/praetorian-inc/trajan/pkg/finding"
)

var identityFields = map[NodeLabel]map[string]string{
	Repository:              {"repo": "name"},
	Pipeline:                {"pipeline_id": "id"},
	ServiceConnection:       {"connection_id": "id"},
	VariableGroup:           {"group_id": "id"},
	SecretVariable:          {"owner_project": "project"},
	SecureFile:              {"file_id": "id"},
	ArtifactsFeed:           {"feed_id": "id"},
	OrgAgentPool:            {"pool_id": "id"},
	ProjectAgentPool:        {"queue_id": "id"},
	ServiceHookSubscription: {"subscription_id": "id"},
}

func (c *corpus) identityOf(l NodeLabel, f map[string]any) map[string]string {
	alias := identityFields[l]
	key := make(map[string]string, len(IdentityKey(l)))
	for _, k := range IdentityKey(l) {
		if k == "org" {
			key[k] = c.org
			continue
		}
		src := k
		if a, ok := alias[k]; ok {
			src = a
		}
		key[k] = str(f[src])
	}
	return key
}

func buildNodes(c *corpus) *nodeSet {
	s := newNodeSet()
	for _, l := range NodeLabels() {
		for _, r := range c.byKind[string(l)] {
			n := s.Upsert(l, c.identityOf(l, r.fields), s.RecordProps(l, r.fields), r.rel)
			s.Index(r.dir, r.id, n)
		}
	}
	s.SweepIllegal()
	return s
}

var containment = []struct {
	edge   EdgeType
	parent NodeLabel
	child  NodeLabel
}{
	{HasProject, Organization, Project},
	{HasRepository, Project, Repository},
	{HasBranch, Repository, Branch},
	{HasPipeline, Project, Pipeline},
	{HasStage, Pipeline, Stage},
	{HasJob, Stage, Job},
}

type recordRef struct{ dir, id string }

func buildEdges(c *corpus, n *nodeSet) (*edgeSet, map[recordRef][]string, error) {
	s := newEdgeSet()
	emitContainment(n, s)

	fromRecord := map[recordRef][]string{}
	gc := graphCtx{Org: c.org, Principal: principalLabels(c), BuildService: buildServices(c)}
	for _, t := range EdgeTypes() {
		for _, r := range c.byKind[string(t)] {
			rs := resolveEndpoints(gc, r.fields)
			if len(rs) == 0 {
				s.Miss(t, "", "", 1)
				continue
			}
			props := edgeProps(r.fields)
			for _, e := range rs {
				id := s.Add(e.Type, e.From, e.To, props)
				if id == "" || r.id == "" {
					continue
				}
				ref := recordRef{r.dir, r.id}
				fromRecord[ref] = append(fromRecord[ref], id)
			}
		}
	}
	return s, fromRecord, s.Err()
}

func emitContainment(n *nodeSet, s *edgeSet) {
	for _, ct := range containment {
		for _, child := range n.All() {
			if child.Labels[0] != ct.child {
				continue
			}
			parent := endpoint{Label: ct.parent, Key: map[string]string{}}
			for _, k := range IdentityKey(ct.parent) {
				parent.Key[k] = child.Key[k]
			}
			s.Add(ct.edge, parent, endpoint{Label: ct.child, Key: child.Key}, nil)
		}
	}
}

func principalLabels(c *corpus) func(string) (NodeLabel, bool) {
	index := map[string]NodeLabel{}
	for _, l := range []NodeLabel{User, SecurityGroup, BuildServiceIdentity} {
		for _, r := range c.byKind[string(l)] {
			if d := str(r.fields["descriptor"]); d != "" {
				index[d] = l
			}
		}
	}
	return func(d string) (NodeLabel, bool) {
		l, ok := index[d]
		return l, ok
	}
}

func buildServices(c *corpus) func(project string) (string, bool) {
	byProject := map[string]string{}
	collection := ""
	projectID := map[string]string{}
	for _, r := range c.byKind[string(Project)] {
		if id := str(r.fields["id"]); id != "" {
			projectID[str(r.fields["project"])] = id
		}
	}
	want := "Project Collection Build Service (" + c.org + ")"
	for _, r := range c.byKind[string(BuildServiceIdentity)] {
		d := str(r.fields["descriptor"])
		if d == "" {
			continue
		}
		if str(r.fields["display_name"]) == want {
			collection = d
		}
		byProject[str(r.fields["principal_name"])] = d
	}
	return func(project string) (string, bool) {
		if project == "" {
			return collection, collection != ""
		}
		d, ok := byProject[projectID[project]]
		return d, ok
	}
}

func edgeProps(f map[string]any) map[string]any {
	out := make(map[string]any, len(f))
	for k, v := range f {
		if k == "_id" || k == "kind" || k == "_provenance" || !graph.LegalProp(v) {
			continue
		}
		out[k] = v
	}
	return out
}

func buildGraphNodes(ctx context.Context, c *corpus) (*nodeSet, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return buildNodes(c), nil
}

type graphProvider struct{ adoSchema }

type graphBuild struct {
	c          *corpus
	nodes      *nodeSet
	edges      *edgeSet
	fromRecord map[recordRef][]string
}

func GraphProvider() graph.Provider[NodeLabel, EdgeType] { return &graphProvider{} }

func (p *graphProvider) Name() string        { return "ado" }
func (p *graphProvider) RuleSubtree() string { return "ado" }

// An edge target names only its type: an ADO attack edge starts at whichever
// principal the record resolved to, so no single From/To pair describes it.
func (p *graphProvider) Grammar() graph.Grammar {
	return graph.Grammar{Forms: []graph.TargetKind{graph.TargetNode, graph.TargetEdge}}
}

func (p *graphProvider) SkipRecords() []string { return nil }

func (p *graphProvider) Open(c *graph.Corpus) (graph.Session[NodeLabel, EdgeType], error) {
	ac, err := indexCorpus(c)
	if err != nil {
		return nil, err
	}
	return &graphBuild{c: ac}, nil
}

func (b *graphBuild) Org() string { return b.c.org }

func (b *graphBuild) Nodes(ctx context.Context) (*nodeSet, error) {
	n, err := buildGraphNodes(ctx, b.c)
	if err != nil {
		return nil, err
	}
	b.nodes = n
	return n, nil
}

func (b *graphBuild) Edges(context.Context) (*edgeSet, error) {
	s, fromRecord, err := buildEdges(b.c, b.nodes)
	if err != nil {
		return nil, err
	}
	b.edges, b.fromRecord = s, fromRecord
	return s, nil
}

func (b *graphBuild) Attach(ctx context.Context, targets map[string]graph.Target,
	findings []finding.Finding) (*graph.AttachResult, error) {

	att := newAttacher(b.c, b.nodes, b.edges, b.fromRecord, targets)
	if err := att.run(ctx, findings); err != nil {
		return nil, err
	}
	return att.res, nil
}

func (p *graphProvider) Gaps() []graph.GapEntry { return gapRegister }

func (p *graphProvider) Hierarchy(org string, n node) []string {
	if project := n.Key["project"]; project != "" {
		return []string{org, project}
	}
	return []string{org}
}
