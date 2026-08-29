package ado

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"strings"

	"github.com/praetorian-inc/trajan/internal/finding"
)

const (
	reasonNoTarget           = "no_target"
	reasonNoSubjectDir       = "no_subject_dir"
	reasonSubjectUnresolved  = "subject_unresolved"
	reasonNoProjection       = "no_projection"
	reasonLabelMismatch      = "label_mismatch"
	reasonEndpointUnresolved = "endpoint_unresolved"
)

func unattachedReasons() []string {
	return []string{reasonEndpointUnresolved, reasonLabelMismatch, reasonNoProjection,
		reasonNoSubjectDir, reasonNoTarget, reasonSubjectUnresolved}
}

type unattachedFinding struct {
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"rule_id"`
	Target      string `json:"target"`
	SubjectKind string `json:"subject_kind"`
	SubjectID   string `json:"subject_id"`
	Reason      string `json:"reason"`
	Detail      string `json:"detail"`
}

type attachResult struct {
	total      int
	attached   int
	toNodes    int
	toEdges    int
	byReason   map[string]int
	byRule     map[string]int
	byTarget   map[string]int
	unattached []unattachedFinding
}

type attacher struct {
	c *corpus
	n *nodeSet
	s *edgeSet

	targets    map[string]Target
	fromRecord map[recordRef][]string
	incident   map[string][]string

	res attachResult
}

func newAttacher(c *corpus, n *nodeSet, s *edgeSet, fromRecord map[recordRef][]string, targets map[string]Target) *attacher {
	a := &attacher{
		c: c, n: n, s: s, targets: targets, fromRecord: fromRecord,
		incident: map[string][]string{},
		res: attachResult{
			byReason: map[string]int{},
			byRule:   map[string]int{},
			byTarget: map[string]int{},
		},
	}
	for _, r := range unattachedReasons() {
		a.res.byReason[r] = 0
	}
	for _, id := range slices.Sorted(maps.Keys(s.byID)) {
		e := s.byID[id]
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
	slices.SortFunc(a.res.unattached, func(x, y unattachedFinding) int {
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
	a.res.total++
	t, ok := a.targets[ruleID(f)]
	if !ok {
		a.fail(f, t, reasonNoTarget, "rule id is absent from the loaded rule set; rules and findings are out of sync")
		return
	}
	dir, ok := adoScanProvider.SubjectDirs[f.Subject.Kind]
	if !ok {
		a.fail(f, t, reasonNoSubjectDir, "subject kind "+f.Subject.Kind+" names no 10-normalize directory")
		return
	}
	if !a.c.byDir[dir][f.Subject.ID] {
		a.fail(f, t, reasonSubjectUnresolved, "no record in "+dir+" carries this _id")
		return
	}

	ref := findingRef{
		RuleID: ruleID(f), Fingerprint: f.Fingerprint, Severity: f.Severity,
		Confidence: f.Confidence, Target: renderTarget(t),
		SubjectKind: f.Subject.Kind, SubjectID: f.Subject.ID, Title: f.Title,
	}
	nodeID, hasNode := a.n.subject(dir, f.Subject.ID)
	edgeIDs := a.fromRecord[recordRef{dir, f.Subject.ID}]
	if !hasNode && len(edgeIDs) == 0 {
		a.fail(f, t, reasonNoProjection, "the record emitted no node and no edge")
		return
	}

	if t.Kind == TargetNode {
		a.attachNode(f, t, ref, nodeID, hasNode)
		return
	}
	a.attachEdge(f, t, ref, nodeID, edgeIDs)
}

func (a *attacher) attachNode(f *finding.Finding, t Target, ref findingRef, nodeID string, hasNode bool) {
	n := a.n.get(nodeID)
	if !hasNode || n == nil || n.Labels[0] != t.Label {
		a.fail(f, t, reasonLabelMismatch, "the subject resolves to no "+string(t.Label)+" node")
		return
	}
	appendFinding(&n.Findings, ref)
	a.res.attached++
	a.res.toNodes++
}

func (a *attacher) attachEdge(f *finding.Finding, t Target, ref findingRef, nodeID string, edgeIDs []string) {
	hits := 0
	for _, id := range slices.Concat(edgeIDs, a.incident[nodeID]) {
		if e := a.s.byID[id]; e != nil && e.Type == t.Type && appendFinding(&e.Findings, ref) {
			hits++
		}
	}
	if hits == 0 {
		a.fail(f, t, reasonEndpointUnresolved, "no emitted "+renderTarget(t)+" belongs to the subject")
		return
	}
	a.res.attached++
	a.res.toEdges++
}

func appendFinding(fs *[]findingRef, ref findingRef) bool {
	if slices.ContainsFunc(*fs, func(x findingRef) bool { return x.Fingerprint == ref.Fingerprint }) {
		return false
	}
	*fs = append(*fs, ref)
	return true
}

func (a *attacher) fail(f *finding.Finding, t Target, reason, detail string) {
	target := renderTarget(t)
	a.res.byReason[reason]++
	a.res.byRule[ruleID(f)]++
	a.res.byTarget[target]++
	a.res.unattached = append(a.res.unattached, unattachedFinding{
		Fingerprint: f.Fingerprint, RuleID: ruleID(f), Target: target,
		SubjectKind: f.Subject.Kind, SubjectID: f.Subject.ID,
		Reason: reason, Detail: detail,
	})
}

func finalizeFindings(fs []findingRef, props map[string]any) []findingRef {
	slices.SortFunc(fs, func(a, b findingRef) int {
		return cmp.Or(
			cmp.Compare(finding.SeverityRank(b.Severity), finding.SeverityRank(a.Severity)),
			cmp.Compare(finding.ConfidenceRank(b.Confidence), finding.ConfidenceRank(a.Confidence)),
			cmp.Compare(a.RuleID, b.RuleID),
			cmp.Compare(a.Fingerprint, b.Fingerprint))
	})
	props["findings_count"] = len(fs)
	buckets := map[string][]string{}
	for _, f := range fs {
		if b := severityBuckets[f.Severity]; b != "" {
			buckets[b] = append(buckets[b], f.RuleID)
		}
	}
	for _, b := range findingBuckets {
		ids := buckets[b]
		if len(ids) == 0 {
			continue
		}
		// findings_<severity> is deduplicated to rule ids, so its length is a rule
		// count and not the number of findings at that severity.
		props["findings_count_"+strings.TrimPrefix(b, "findings_")] = len(ids)
		slices.Sort(ids)
		props[b] = slices.Compact(ids)
	}
	return fs
}
