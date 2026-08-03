package graph

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	"github.com/praetorian-inc/trajan/internal/finding"
)

const (
	reasonNoTarget           = "no_target"
	reasonSubjectUnresolved  = "subject_unresolved"
	reasonLabelMismatch      = "label_mismatch"
	reasonNoProjection       = "no_projection"
	reasonEndpointUnresolved = "endpoint_unresolved"
	reasonNoFanoutValues     = "no_fanout_values"
)

func unattachedReasons() []string {
	return []string{reasonEndpointUnresolved, reasonLabelMismatch, reasonNoFanoutValues,
		reasonNoProjection, reasonNoTarget, reasonSubjectUnresolved}
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

func renderTarget(t Target) string {
	switch t.Kind {
	case TargetNode:
		return fmt.Sprintf("node(%s)", t.Label)
	case TargetEdge:
		return fmt.Sprintf("edge(%s, %s, %s)", t.Type, t.From, t.To)
	case TargetAttack:
		return fmt.Sprintf("attack(%s)", t.Type)
	}
	return ""
}

// anchorNode carries the source payload alongside the node so an attack edge can
// read the victim's trigger classes without re-resolving the record.
type anchorNode struct {
	label NodeLabel
	id    string
	rec   map[string]any
}

// Anchors are ordered downstream-first: where a chain item offers two
// same-labelled candidates the consumer / reader / callee side is the victim, so
// the first match wins. graph.Target has no third argument to say so.
type anchorSet struct {
	nodes []anchorNode
	edges []string
}

func (a *anchorSet) addNode(n *nodeSet, l NodeLabel, id string, rec map[string]any) {
	if n.has(id) {
		a.nodes = append(a.nodes, anchorNode{l, id, rec})
	}
}

func (a *anchorSet) addEdge(s *edgeSet, id string) {
	if _, ok := s.byID[id]; ok {
		a.edges = append(a.edges, id)
	}
}

type chainItem struct {
	idx  int
	item map[string]any
}

// The walk order is a contract, not luck: branch-coverage and effective-ruleset
// share all their _ids, and first write wins.
var chainAnchors = []struct {
	file, key string
	fn        func(*attacher, map[string]any) anchorSet
}{
	{"branch-coverage", "repo_branch_coverage", (*attacher).anchorBranch},
	{"capability-edges", "edges", (*attacher).anchorCapability},
	{"cache-keyspace", "prefix_overlaps", (*attacher).anchorCache},
	{"deploy-key-reuse", "reused_keys", (*attacher).anchorDeployKeyReuse},
	{"effective-ruleset", "effective_per_branch", (*attacher).anchorBranch},
	{"env-deployments", "deploys", (*attacher).anchorDeploy},
	{"app-mintable", "mints", (*attacher).anchorMint},
	{"job-output-flow", "edges", (*attacher).anchorJobFlow},
	{"reusable-callgraph", "edges", (*attacher).anchorCall},
	{"trigger-channels", "artifact_handoffs", (*attacher).anchorArtifactHandoff},
	{"trigger-channels", "workflow_run_pairs", (*attacher).anchorWorkflowRunPair},
}

type attacher struct {
	c *corpus
	n *nodeSet
	s *edgeSet

	targets  map[string]Target
	incident map[string][]*edge
	chain    map[string]chainItem
	jobs     map[string]map[string]any
	deployFP map[string]string
	keyByID  map[string]string

	res attachResult
}

func newAttacher(c *corpus, n *nodeSet, s *edgeSet, targets map[string]Target) *attacher {
	a := &attacher{
		c: c, n: n, s: s, targets: targets,
		incident: map[string][]*edge{},
		chain:    map[string]chainItem{},
		jobs:     map[string]map[string]any{},
		deployFP: deployKeyFingerprints(c),
		keyByID:  map[string]string{},
		res: attachResult{
			byReason: map[string]int{},
			byRule:   map[string]int{},
			byTarget: map[string]int{},
		},
	}
	for _, r := range unattachedReasons() {
		a.res.byReason[r] = 0
	}
	for _, e := range s.byID {
		a.incident[e.From] = append(a.incident[e.From], e)
		if e.To != e.From {
			a.incident[e.To] = append(a.incident[e.To], e)
		}
	}
	for _, r := range c.dirs["jobs"] {
		if _, dup := a.jobs[r.id]; !dup {
			a.jobs[r.id] = r.fields
		}
	}
	for _, r := range c.dirs["deploy-keys"] {
		a.keyByID[str(r.fields["repo"])+"\x00"+decimal(r.fields["key_id"])] = str(r.fields["fingerprint"])
	}
	for i, ca := range chainAnchors {
		for _, item := range c.chainArray(ca.file, ca.key) {
			id := str(item["_id"])
			if _, dup := a.chain[id]; id == "" || dup {
				continue
			}
			a.chain[id] = chainItem{i, item}
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
	ref := findingRef{
		RuleID: ruleID(f), Fingerprint: f.Fingerprint, Severity: f.Severity,
		Confidence: f.Confidence, Target: renderTarget(t),
		SubjectKind: f.Subject.Kind, SubjectID: f.Subject.ID, Title: f.Title,
	}
	anc, ok := a.anchors(f.Subject.Kind, f.Subject.ID)
	if !ok {
		a.fail(f, t, reasonSubjectUnresolved, "subject.id matched no normalized record or chain item")
		return
	}
	if len(anc.nodes) == 0 && len(anc.edges) == 0 {
		a.fail(f, t, reasonNoProjection, "the subject record yields no emitted graph element")
		return
	}
	switch t.Kind {
	case TargetNode:
		a.attachNode(f, t, ref, anc)
	case TargetEdge:
		a.attachEdge(f, t, ref, anc)
	case TargetAttack:
		a.attachAttack(f, t, ref, anc)
	}
}

func (a *attacher) anchors(kind, id string) (anchorSet, bool) {
	if kind == "chain" {
		ci, ok := a.chain[id]
		if !ok {
			return anchorSet{}, false
		}
		return chainAnchors[ci.idx].fn(a, ci.item), true
	}
	nid, ok := a.n.subject(kind, id)
	if !ok {
		return anchorSet{}, false
	}
	var out anchorSet
	out.addNode(a.n, a.n.get(nid).Labels[0], nid, a.jobs[id])
	return out, true
}

func (a *attacher) attachNode(f *finding.Finding, t Target, ref findingRef, anc anchorSet) {
	for _, an := range anc.nodes {
		if an.label == t.Label {
			a.toNode(an.id, ref)
			a.done(1, 0)
			return
		}
	}
	a.project(f, t, ref, anc)
}

// The projection table is a literal, not a mechanism: an org-subject rule names
// its secrets in its own provenance, and a generic "walk one CONTAINS hop" would
// smear each finding across every org secret.
func (a *attacher) project(f *finding.Finding, t Target, ref findingRef, _ anchorSet) {
	if f.Subject.Kind != "org" || t.Label != Secret {
		a.fail(f, t, reasonLabelMismatch,
			"no anchor with label "+string(t.Label)+" and no projection row for subject kind "+f.Subject.Kind)
		return
	}
	names := []string{}
	for _, key := range []string{"org_app_key_secrets", "org_pat_named_secrets"} {
		for _, v := range list(f.Provenance[key]) {
			if s := str(v); s != "" {
				names = append(names, s)
			}
		}
	}
	if len(names) == 0 {
		a.fail(f, t, reasonNoFanoutValues, "provenance carries no org secret names to fan out over")
		return
	}
	hits := 0
	for _, name := range names {
		id, ok := a.n.secretID("org", a.c.org, name)
		if !ok {
			continue
		}
		a.toNode(id, ref)
		hits++
	}
	if hits == 0 {
		a.fail(f, t, reasonEndpointUnresolved, "no org Secret node matches the provenance names")
		return
	}
	a.done(hits, 0)
}

// An anchor edge is exact where the chain item names one; otherwise every
// emitted edge of the target type incident on an anchor node is a hit, which is
// what fans a job-subject READS finding over its secrets while ignoring its
// cache and artifact reads.
func (a *attacher) attachEdge(f *finding.Finding, t Target, ref findingRef, anc anchorSet) {
	hits := 0
	for _, id := range anc.edges {
		if e := a.s.byID[id]; a.matches(e, t) {
			a.toEdge(e, ref)
			hits++
		}
	}
	if hits == 0 {
		for _, an := range anc.nodes {
			for _, e := range a.incident[an.id] {
				if a.matches(e, t) && a.toEdge(e, ref) {
					hits++
				}
			}
		}
	}
	if hits == 0 {
		a.fail(f, t, reasonEndpointUnresolved,
			"no emitted "+renderTarget(t)+" is incident on the subject's anchors")
		return
	}
	a.done(0, hits)
}

func (a *attacher) matches(e *edge, t Target) bool {
	return e != nil && e.Type == t.Type && e.FromLabel == t.From && e.ToLabel == t.To
}

func (a *attacher) attachAttack(f *finding.Finding, t Target, ref findingRef, anc anchorSet) {
	var victim anchorNode
	for _, an := range anc.nodes {
		if an.label == Job {
			victim = an
			break
		}
	}
	if victim.id == "" {
		a.fail(f, t, reasonLabelMismatch, "the subject resolves to no Job to victimize")
		return
	}
	actor := a.n.upsert(ExternalActor, map[string]string{"kind": "external"},
		map[string]any{"synthetic": true}, "")
	// The trigger classes go on the edge, not into ExternalActor's identity: 7
	// victim jobs have an empty low_trust list and a per-class actor node would
	// leave them sourceless. Both lists are emitted because ranking them here
	// discards one. No _source: findings[] already names the rule, fingerprint
	// and subject of every 20-scan file behind this edge.
	tcs := obj(victim.rec["trigger_class_summary"])
	a.s.add(t.Type, resolved(ExternalActor, actor.ID), resolved(Job, victim.id), map[string]any{
		"trigger_classes_low_trust": list(tcs["low_trust"]),
		"trigger_classes_medium":    list(tcs["medium"]),
	})
	e := a.s.byID[edgeID(t.Type, actor.ID, victim.id)]
	if e == nil {
		a.fail(f, t, reasonEndpointUnresolved, "the attack edge was rejected by the schema")
		return
	}
	a.toEdge(e, ref)
	a.done(0, 1)
}

func (a *attacher) toNode(id string, ref findingRef) bool {
	n := a.n.get(id)
	return n != nil && appendFinding(&n.Findings, ref)
}

func (a *attacher) toEdge(e *edge, ref findingRef) bool {
	return appendFinding(&e.Findings, ref)
}

func appendFinding(fs *[]findingRef, ref findingRef) bool {
	if slices.ContainsFunc(*fs, func(x findingRef) bool { return x.Fingerprint == ref.Fingerprint }) {
		return false
	}
	*fs = append(*fs, ref)
	return true
}

func (a *attacher) done(nodes, edges int) {
	a.res.attached++
	if nodes > 0 {
		a.res.toNodes++
	}
	if edges > 0 {
		a.res.toEdges++
	}
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

func (a *attacher) anchorBranch(e map[string]any) anchorSet {
	var out anchorSet
	out.addNode(a.n, Branch, branchEndpoint(a.c, str(e["repo"]), str(e["branch"])).id, e)
	return out
}

func (a *attacher) anchorCapability(e map[string]any) anchorSet {
	var out anchorSet
	from := capabilityPrincipal(a.c, a.deployFP, e)
	to := branchEndpoint(a.c, str(e["repo"]), str(e["branch"]))
	out.addNode(a.n, from.label, from.id, e)
	out.addNode(a.n, Branch, to.id, e)
	out.addEdge(a.s, edgeID(CanLandCode, from.id, to.id))
	return out
}

func (a *attacher) anchorCache(e map[string]any) anchorSet {
	var out anchorSet
	out.addNode(a.n, Cache, cacheEndpoint(a.c, str(e["repo"]), str(e["key_prefix"])).id, e)
	return out
}

func (a *attacher) anchorDeployKeyReuse(e map[string]any) anchorSet {
	var out anchorSet
	for _, inst := range objects(e["instances"]) {
		fp := a.keyByID[str(inst["repo"])+"\x00"+decimal(inst["key_id"])]
		out.addNode(a.n, DeployKey, nd(DeployKey, "fingerprint", fp).id, e)
	}
	return out
}

func (a *attacher) anchorDeploy(d map[string]any) anchorSet {
	var out anchorSet
	job := obj(d["job"])
	from := jobEndpoint(a.c, job)
	to := envEndpoint(a.c, str(job["repo"]), str(d["env_name"]))
	out.addNode(a.n, Job, from.id, job)
	out.addNode(a.n, Environment, to.id, obj(d["env"]))
	out.addEdge(a.s, edgeID(Targets, from.id, to.id))
	return out
}

func (a *attacher) anchorMint(m map[string]any) anchorSet {
	var out anchorSet
	minter := obj(m["minter"])
	out.addNode(a.n, Job, jobEndpoint(a.c, minter).id, minter)
	return out
}

// The chain's producer/consumer payloads carry only an _id, so both ends come
// from the job records that _id names.
func (a *attacher) anchorJobFlow(e map[string]any) anchorSet {
	var out anchorSet
	for _, side := range []string{"consumer", "producer"} {
		rec := a.jobs[str(obj(e[side])["_id"])]
		if rec == nil {
			continue
		}
		out.addNode(a.n, Job, jobEndpoint(a.c, rec).id, rec)
	}
	return out
}

func (a *attacher) anchorCall(e map[string]any) anchorSet {
	var out anchorSet
	caller, callee := obj(e["caller"]), obj(e["callee"])
	repo := str(callee["repo"])
	if truthy(callee["is_local"]) || repo == "" {
		repo = str(caller["repo"])
	}
	from := jobEndpoint(a.c, caller)
	to := nd(Workflow, "repo", a.c.full(repo), "path", str(callee["path"]))
	out.addNode(a.n, Workflow, to.id, nil)
	out.addNode(a.n, Job, from.id, caller)
	out.addEdge(a.s, edgeID(Calls, from.id, to.id))
	return out
}

func (a *attacher) anchorArtifactHandoff(h map[string]any) anchorSet {
	var out anchorSet
	reader, writer := obj(h["reader"]), obj(h["writer"])
	art := nd(Artifact, "repo", a.c.full(str(reader["repo"])), "name", str(h["artifact_name"]))
	out.addNode(a.n, Job, jobEndpoint(a.c, reader).id, reader)
	out.addNode(a.n, Job, jobEndpoint(a.c, writer).id, writer)
	out.addNode(a.n, Artifact, art.id, nil)
	out.addEdge(a.s, edgeID(Reads, jobEndpoint(a.c, reader).id, art.id))
	out.addEdge(a.s, edgeID(Writes, jobEndpoint(a.c, writer).id, art.id))
	return out
}

func (a *attacher) anchorWorkflowRunPair(p map[string]any) anchorSet {
	var out anchorSet
	up, down := obj(p["upstream"]), obj(p["downstream"])
	out.addNode(a.n, Job, jobEndpoint(a.c, down).id, down)
	out.addNode(a.n, Job, jobEndpoint(a.c, up).id, up)
	out.addNode(a.n, Workflow, workflowEndpoint(a.c, down).id, down)
	out.addNode(a.n, Workflow, workflowEndpoint(a.c, up).id, up)
	out.addEdge(a.s, edgeID(Triggers, workflowEndpoint(a.c, up).id, workflowEndpoint(a.c, down).id))
	return out
}
