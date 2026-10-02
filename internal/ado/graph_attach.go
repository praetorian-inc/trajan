package ado

import (
	"cmp"
	"context"
	"slices"

	"github.com/praetorian-inc/trajan/internal/graph"
	"github.com/praetorian-inc/trajan/pkg/finding"
)

var unattachedReasons = []string{
	graph.ReasonEndpointUnresolved, graph.ReasonLabelMismatch, graph.ReasonNoProjection,
	graph.ReasonNoSubjectDir, graph.ReasonNoTarget, graph.ReasonSubjectUnresolved,
}

type attacher struct {
	c *corpus
	n *nodeSet
	s *edgeSet

	targets    map[string]graph.Target
	fromRecord map[recordRef][]string
	incident   map[string][]string

	res *graph.AttachResult
}

func newAttacher(c *corpus, n *nodeSet, s *edgeSet, fromRecord map[recordRef][]string, targets map[string]graph.Target) *attacher {
	a := &attacher{
		c: c, n: n, s: s, targets: targets, fromRecord: fromRecord,
		incident: map[string][]string{},
		res:      graph.NewAttachResult(unattachedReasons),
	}
	for _, id := range s.IDs() {
		e := s.Get(id)
		a.incident[e.From] = append(a.incident[e.From], id)
		if e.To != e.From {
			a.incident[e.To] = append(a.incident[e.To], id)
		}
	}
	return a
}

func (a *attacher) run(ctx context.Context, findings []finding.Finding) error {
	for i := range findings {
		if err := ctx.Err(); err != nil {
			return err
		}
		a.one(&findings[i])
	}
	slices.SortFunc(a.res.Unattached, func(x, y graph.UnattachedFinding) int {
		return cmp.Or(cmp.Compare(x.RuleID, y.RuleID), cmp.Compare(x.Fingerprint, y.Fingerprint))
	})
	return nil
}

func ruleID(f *finding.Finding) string {
	if f.Rule == nil {
		return ""
	}
	return f.Rule.ID
}

func (a *attacher) one(f *finding.Finding) {
	a.res.Total++
	t, ok := a.targets[ruleID(f)]
	if !ok {
		a.fail(f, t, graph.ReasonNoTarget, "rule id is absent from the loaded rule set; rules and findings are out of sync")
		return
	}
	dir, ok := adoScanProvider.SubjectDirs[f.Subject.Kind]
	if !ok {
		a.fail(f, t, graph.ReasonNoSubjectDir, "subject kind "+f.Subject.Kind+" names no 10-normalize directory")
		return
	}
	if !a.c.byDir[dir][f.Subject.ID] {
		a.fail(f, t, graph.ReasonSubjectUnresolved, "no record in "+dir+" carries this _id")
		return
	}

	ref := findingRef{
		RuleID: ruleID(f), Fingerprint: f.Fingerprint, Severity: f.Severity,
		Confidence: f.Confidence, Target: graph.RenderTarget(t),
		SubjectKind: f.Subject.Kind, SubjectID: f.Subject.ID, Title: f.Title,
	}
	nodeID, hasNode := a.n.Subject(dir, f.Subject.ID)
	edgeIDs := a.fromRecord[recordRef{dir, f.Subject.ID}]
	if !hasNode && len(edgeIDs) == 0 {
		a.fail(f, t, graph.ReasonNoProjection, "the record emitted no node and no edge")
		return
	}

	if t.Kind == graph.TargetNode {
		a.attachNode(f, t, ref, nodeID, hasNode)
		return
	}
	a.attachEdge(f, t, ref, nodeID, edgeIDs)
}

func (a *attacher) attachNode(f *finding.Finding, t graph.Target, ref findingRef, nodeID string, hasNode bool) {
	n := a.n.Get(nodeID)
	if !hasNode || n == nil || n.Labels[0] != NodeLabel(t.Label) {
		a.fail(f, t, graph.ReasonLabelMismatch, "the subject resolves to no "+string(NodeLabel(t.Label))+" node")
		return
	}
	graph.AppendFinding(&n.Findings, ref)
	a.res.Attached++
	a.res.ToNodes++
}

func (a *attacher) attachEdge(f *finding.Finding, t graph.Target, ref findingRef, nodeID string, edgeIDs []string) {
	hits := 0
	for _, id := range slices.Concat(edgeIDs, a.incident[nodeID]) {
		if e := a.s.Get(id); e != nil && e.Type == EdgeType(t.Type) && graph.AppendFinding(&e.Findings, ref) {
			hits++
		}
	}
	if hits == 0 {
		a.fail(f, t, graph.ReasonEndpointUnresolved, "no emitted "+graph.RenderTarget(t)+" belongs to the subject")
		return
	}
	a.res.Attached++
	a.res.ToEdges++
}

func (a *attacher) fail(f *finding.Finding, t graph.Target, reason, detail string) {
	target := graph.RenderTarget(t)
	a.res.ByReason[reason]++
	a.res.ByRule[ruleID(f)]++
	a.res.ByTarget[target]++
	a.res.Unattached = append(a.res.Unattached, graph.UnattachedFinding{
		Fingerprint: f.Fingerprint, RuleID: ruleID(f), Target: target,
		SubjectKind: f.Subject.Kind, SubjectID: f.Subject.ID,
		Reason: reason, Detail: detail,
	})
}
