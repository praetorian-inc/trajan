package github

import (
	"context"
	"strings"

	"github.com/praetorian-inc/trajan/internal/graph"
	"github.com/praetorian-inc/trajan/pkg/finding"
)

type graphProvider struct{ ghSchema }

type graphBuild struct {
	c     *ghCorpus
	nodes *nodeIndex
	edges *edgeIndex
}

func GraphProvider() graph.Provider[NodeLabel, EdgeType] { return &graphProvider{} }

func (p *graphProvider) Name() string        { return "github" }
func (p *graphProvider) RuleSubtree() string { return "github" }

func (p *graphProvider) Grammar() graph.Grammar {
	return graph.Grammar{
		Forms:         []graph.TargetKind{graph.TargetNode, graph.TargetEdge, graph.TargetAttack},
		EdgeNamesPair: true,
	}
}

// chains/indices re-keys data the primary records already carry, and its filenames
// embed raw ${{ }} expressions.
func (p *graphProvider) SkipRecords() []string { return []string{"chains/indices/"} }

func (p *graphProvider) Open(c *graph.Corpus) (graph.Session[NodeLabel, EdgeType], error) {
	gc, err := indexCorpus(c)
	if err != nil {
		return nil, err
	}
	return &graphBuild{c: gc}, nil
}

func (b *graphBuild) Org() string { return b.c.org }

func (b *graphBuild) Nodes(ctx context.Context) (*graph.NodeSet[NodeLabel, EdgeType], error) {
	n, err := buildNodes(ctx, b.c)
	if err != nil {
		return nil, err
	}
	b.nodes = n
	return n.NodeSet, nil
}

func (b *graphBuild) Edges(ctx context.Context) (*graph.EdgeSet[NodeLabel, EdgeType], error) {
	s, err := buildEdges(ctx, b.c, b.nodes)
	if err != nil {
		return nil, err
	}
	b.edges = s
	return s, nil
}

func (b *graphBuild) Attach(ctx context.Context, targets map[string]graph.Target,
	findings []finding.Finding) (*graph.AttachResult, error) {

	att := newAttacher(b.c, b.nodes, b.edges, targets)
	if err := att.run(ctx, findings); err != nil {
		return nil, err
	}
	return att.res, nil
}

func (p *graphProvider) Gaps() []graph.GapEntry { return gapRegister }

// An unqualified or foreign-org repo fails the prefix test and must degrade to the org.
func (p *graphProvider) Hierarchy(org string, n graph.Node[NodeLabel]) []string {
	repo := n.Key["full_name"]
	if repo == "" {
		repo = n.Key["repo"]
	}
	if repo == "" {
		repo = str(n.Properties["repo"])
	}
	if !strings.HasPrefix(repo, org+"/") {
		return []string{org}
	}
	return []string{org, repo}
}
