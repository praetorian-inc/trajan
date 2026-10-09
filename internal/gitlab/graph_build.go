package gitlab

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/graph"
	"github.com/praetorian-inc/trajan/pkg/finding"
)

type nodeSet = graph.NodeSet[NodeLabel, EdgeType]
type edgeSet = graph.EdgeSet[NodeLabel, EdgeType]
type endpoint = graph.Endpoint[NodeLabel]

var dirLabels = map[string]NodeLabel{
	"instance":       LabelInstance,
	"groups":         LabelGroup,
	"projects":       LabelProject,
	"jobs":           LabelJob,
	"merge-requests": LabelMergeRequest,
	"environments":   LabelEnvironment,
	"runners":        LabelRunner,
	"agents":         LabelAgent,
	"credentials":    LabelCredential,
	"integrations":   LabelIntegration,
}

type glRecord struct {
	rel, dir, id string
	fields       map[string]any
}

type glCorpus struct {
	org         string
	records     []glRecord
	chains      map[string]map[string]any
	hasInstance bool
}

func indexCorpus(src *graph.Corpus) (*glCorpus, error) {
	c := &glCorpus{chains: map[string]map[string]any{}}
	for _, r := range src.Records {
		if r.Dir == "chains" {
			c.chains[strings.TrimSuffix(path.Base(r.Rel), ".json")] = r.Fields
			continue
		}
		if _, ok := dirLabels[r.Dir]; !ok || r.ID == "" {
			continue
		}
		if r.Dir == "instance" {
			c.hasInstance = true
		}
		c.records = append(c.records, glRecord{rel: r.Rel, dir: r.Dir, id: r.ID, fields: r.Fields})
	}
	c.org = rootScope(c.records)
	if c.org == "" {
		return nil, fmt.Errorf("%s: %w; every node is qualified by it", engine.DirNormalize, graph.ErrNoOrgRecord)
	}
	return c, nil
}

// A subgroup's full path extends its parent's, so the shortest one is the root.
func rootScope(recs []glRecord) string {
	shortest := func(dir string) string {
		out := ""
		for _, r := range recs {
			if r.dir == dir {
				if out == "" || len(r.id) < len(out) {
					out = r.id
				}
			}
		}
		return out
	}
	if g := shortest("groups"); g != "" {
		return g
	}
	p := shortest("projects")
	if ns := namespace(p); ns != "" {
		return ns
	}
	return p
}

func namespace(fullPath string) string {
	if i := strings.LastIndex(fullPath, "/"); i >= 0 {
		return fullPath[:i]
	}
	return ""
}

func nodeAt(l NodeLabel, id string) endpoint {
	return endpoint{Label: l, Key: map[string]string{"_id": id}}
}

func recordScope(r glRecord) string {
	for _, p := range graph.Objects(r.fields["_provenance"]) {
		if s := graph.Str(p["scope"]); s != "" {
			return s
		}
	}
	return ""
}

func projectScope(l NodeLabel, r glRecord) string {
	switch l {
	case LabelProject, LabelMergeRequest:
		return r.id
	case LabelJob:
		return graph.Str(r.fields["project"])
	case LabelEnvironment:
		name := graph.Str(r.fields["name"])
		if name == "" {
			return ""
		}
		return strings.TrimSuffix(r.id, "/"+name)
	case LabelAgent, LabelIntegration:
		return namespace(r.id)
	case LabelCredential, LabelRunner:
		if p, ok := strings.CutPrefix(recordScope(r), "project:"); ok {
			return p
		}
	}
	return ""
}

func (c *glCorpus) instanceParent() []endpoint {
	if !c.hasInstance {
		return nil
	}
	return []endpoint{nodeAt(LabelInstance, "instance")}
}

func (c *glCorpus) parentsOf(l NodeLabel, r glRecord) []endpoint {
	switch l {
	case LabelInstance:
		return nil
	case LabelGroup, LabelProject:
		if ns := namespace(r.id); ns != "" {
			return []endpoint{nodeAt(LabelGroup, ns)}
		}
		return c.instanceParent()
	case LabelCredential, LabelRunner:
		scope := recordScope(r)
		switch {
		case scope == "instance":
			return c.instanceParent()
		case strings.HasPrefix(scope, "group:"):
			return []endpoint{nodeAt(LabelGroup, strings.TrimPrefix(scope, "group:"))}
		case strings.HasPrefix(scope, "project:"):
			return []endpoint{nodeAt(LabelProject, strings.TrimPrefix(scope, "project:"))}
		}
		return nil
	}
	if p := projectScope(l, r); p != "" {
		return []endpoint{nodeAt(LabelProject, p)}
	}
	return nil
}

func buildNodes(ctx context.Context, c *glCorpus) (*nodeSet, error) {
	s := graph.NewNodeSet[NodeLabel, EdgeType](glSchema{}, graph.SetOptions[NodeLabel]{})
	for _, r := range c.records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		l := dirLabels[r.dir]
		props := s.RecordProps(l, r.fields)
		if p := projectScope(l, r); p != "" {
			props["project"] = p
		}
		n := s.Upsert(l, map[string]string{"_id": r.id}, props, r.rel)
		s.Index(r.dir, r.id, n)
	}
	s.SweepIllegal()
	return s, nil
}

func buildEdges(ctx context.Context, c *glCorpus) (*edgeSet, error) {
	s := graph.NewEdgeSet[NodeLabel, EdgeType](glSchema{})
	for _, r := range c.records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		l := dirLabels[r.dir]
		for _, parent := range c.parentsOf(l, r) {
			s.Add(Contains, parent, nodeAt(l, r.id), nil)
		}
	}
	return s, s.Err()
}

type graphProvider struct{ glSchema }

type graphBuild struct {
	c     *glCorpus
	nodes *nodeSet
}

func GraphProvider() graph.Provider[NodeLabel, EdgeType] { return &graphProvider{} }

func (p *graphProvider) Name() string        { return "gitlab" }
func (p *graphProvider) RuleSubtree() string { return "gitlab" }

func (p *graphProvider) Grammar() graph.Grammar {
	return graph.Grammar{Forms: []graph.TargetKind{graph.TargetNode}}
}

func (p *graphProvider) SkipRecords() []string { return nil }

func (p *graphProvider) Gaps() []graph.GapEntry { return []graph.GapEntry{} }

func (p *graphProvider) Open(c *graph.Corpus) (graph.Session[NodeLabel, EdgeType], error) {
	gc, err := indexCorpus(c)
	if err != nil {
		return nil, err
	}
	return &graphBuild{c: gc}, nil
}

func (b *graphBuild) Org() string { return b.c.org }

func (b *graphBuild) Nodes(ctx context.Context) (*nodeSet, error) {
	n, err := buildNodes(ctx, b.c)
	if err != nil {
		return nil, err
	}
	b.nodes = n
	return n, nil
}

func (b *graphBuild) Edges(ctx context.Context) (*edgeSet, error) { return buildEdges(ctx, b.c) }

func (b *graphBuild) Attach(ctx context.Context, targets map[string]graph.Target,
	findings []finding.Finding) (*graph.AttachResult, error) {

	att := newAttacher(b.c, b.nodes, targets)
	if err := att.run(ctx, findings); err != nil {
		return nil, err
	}
	return att.res, nil
}

func (p *graphProvider) Hierarchy(org string, n graph.Node[NodeLabel]) []string {
	project := graph.Str(n.Properties["project"])
	if project == "" || project == org {
		return []string{org}
	}
	return []string{org, project}
}
