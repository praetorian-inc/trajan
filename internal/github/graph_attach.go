package github

import (
	"cmp"
	"context"
	"slices"

	"github.com/praetorian-inc/trajan/pkg/finding"

	"github.com/praetorian-inc/trajan/internal/graph"
)

var unattachedReasons = []string{
	graph.ReasonEndpointUnresolved, graph.ReasonLabelMismatch, graph.ReasonNoFanoutValues,
	graph.ReasonNoProjection, graph.ReasonNoTarget, graph.ReasonSubjectUnresolved,
}

// anchorNode carries the source payload alongside the node so an attack edge can
// read the victim's trigger classes without re-resolving the record.
type anchorNode struct {
	label NodeLabel
	id    string
	rec   map[string]any
}

// Anchors are ordered downstream-first: where a chain item offers two
// same-labeled candidates the consumer / reader / callee side is the victim, so
// the first match wins. target has no third argument to say so.
type anchorSet struct {
	nodes []anchorNode
	edges []string
}

func (a *anchorSet) addNode(n *nodeIndex, l NodeLabel, id string, rec map[string]any) {
	if n.Has(id) {
		a.nodes = append(a.nodes, anchorNode{l, id, rec})
	}
}

func (a *anchorSet) addEdge(s *edgeIndex, id string) {
	if s.Get(id) != nil {
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
	c *ghCorpus
	n *nodeIndex
	s *edgeIndex

	targets  map[string]graph.Target
	incident map[string][]*graph.Edge[NodeLabel, EdgeType]
	chain    map[string]chainItem
	jobs     map[string]map[string]any
	deployFP map[string]string
	keyByID  map[string]string

	res *graph.AttachResult
}

func newAttacher(c *ghCorpus, n *nodeIndex, s *edgeIndex, targets map[string]graph.Target) *attacher {
	a := &attacher{
		c: c, n: n, s: s, targets: targets,
		incident: map[string][]*graph.Edge[NodeLabel, EdgeType]{},
		chain:    map[string]chainItem{},
		jobs:     map[string]map[string]any{},
		deployFP: deployKeyFingerprints(c),
		keyByID:  map[string]string{},
		res:      graph.NewAttachResult(unattachedReasons),
	}
	for _, id := range s.IDs() {
		e := s.Get(id)
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
	ref := graph.FindingRef{
		RuleID: ruleID(f), Fingerprint: f.Fingerprint, Severity: f.Severity,
		Confidence: f.Confidence, Target: graph.RenderTarget(t),
		SubjectKind: f.Subject.Kind, SubjectID: f.Subject.ID, Title: f.Title,
	}
	anc, ok := a.anchors(f.Subject.Kind, f.Subject.ID)
	if !ok {
		a.fail(f, t, graph.ReasonSubjectUnresolved, "subject.ID matched no normalized record or chain item")
		return
	}
	if len(anc.nodes) == 0 && len(anc.edges) == 0 {
		a.fail(f, t, graph.ReasonNoProjection, "the subject record yields no emitted graph element")
		return
	}
	switch t.Kind {
	case graph.TargetNode:
		a.attachNode(f, t, ref, anc)
	case graph.TargetEdge:
		a.attachEdge(f, t, ref, anc)
	case graph.TargetAttack:
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
	nid, ok := a.n.Subject(kind, id)
	if !ok {
		return anchorSet{}, false
	}
	var out anchorSet
	out.addNode(a.n, a.n.Get(nid).Labels[0], nid, a.jobs[id])
	return out, true
}

func (a *attacher) attachNode(f *finding.Finding, t graph.Target, ref graph.FindingRef, anc anchorSet) {
	for _, an := range anc.nodes {
		if an.label == NodeLabel(t.Label) {
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
func (a *attacher) project(f *finding.Finding, t graph.Target, ref graph.FindingRef, _ anchorSet) {
	if f.Subject.Kind != "org" || NodeLabel(t.Label) != Secret {
		a.fail(f, t, graph.ReasonLabelMismatch,
			"no anchor with label "+t.Label+" and no projection row for subject kind "+f.Subject.Kind)
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
		a.fail(f, t, graph.ReasonNoFanoutValues, "provenance carries no org secret names to fan out over")
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
		a.fail(f, t, graph.ReasonEndpointUnresolved, "no org Secret node matches the provenance names")
		return
	}
	a.done(hits, 0)
}

// An anchor edge is exact where the chain item names one; otherwise every emitted edge
// of the target type incident on an anchor node is a hit, which fans a job-subject
// READS finding over its secrets while ignoring its cache and artifact reads.
func (a *attacher) attachEdge(f *finding.Finding, t graph.Target, ref graph.FindingRef, anc anchorSet) {
	hits := 0
	for _, id := range anc.edges {
		if e := a.s.Get(id); e != nil && a.matches(e, t) {
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
		a.fail(f, t, graph.ReasonEndpointUnresolved,
			"no emitted "+graph.RenderTarget(t)+" is incident on the subject's anchors")
		return
	}
	a.done(0, hits)
}

func (a *attacher) matches(e *graph.Edge[NodeLabel, EdgeType], t graph.Target) bool {
	return e != nil && e.Type == EdgeType(t.Type) && e.FromLabel == NodeLabel(t.From) && e.ToLabel == NodeLabel(t.To)
}

func (a *attacher) attachAttack(f *finding.Finding, t graph.Target, ref graph.FindingRef, anc anchorSet) {
	var victim anchorNode
	for _, an := range anc.nodes {
		if an.label == Job {
			victim = an
			break
		}
	}
	if victim.id == "" {
		a.fail(f, t, graph.ReasonLabelMismatch, "the subject resolves to no Job to victimize")
		return
	}
	actor := a.n.Upsert(ExternalActor, map[string]string{"kind": "external"},
		map[string]any{"synthetic": true}, "")
	// Trigger classes ride the edge, not ExternalActor's identity: a per-class actor
	// would leave a victim with an empty low_trust list sourceless. Both lists are kept
	// because ranking them here discards one; findings[] stands in for _source.
	tcs := obj(victim.rec["trigger_class_summary"])
	a.s.Add(EdgeType(t.Type), resolved(ExternalActor, actor.ID), resolved(Job, victim.id), map[string]any{
		"trigger_classes_low_trust": list(tcs["low_trust"]),
		"trigger_classes_medium":    list(tcs["medium"]),
	})
	e := a.s.Get(graph.EdgeID(t.Type, actor.ID, victim.id))
	if e == nil {
		a.fail(f, t, graph.ReasonEndpointUnresolved, "the attack edge was rejected by the schema")
		return
	}
	a.toEdge(e, ref)
	a.done(0, 1)
}

func (a *attacher) toNode(id string, ref graph.FindingRef) bool {
	n := a.n.Get(id)
	return n != nil && graph.AppendFinding(&n.Findings, ref)
}

func (a *attacher) toEdge(e *graph.Edge[NodeLabel, EdgeType], ref graph.FindingRef) bool {
	return graph.AppendFinding(&e.Findings, ref)
}

func (a *attacher) done(nodes, edges int) {
	a.res.Attached++
	if nodes > 0 {
		a.res.ToNodes++
	}
	if edges > 0 {
		a.res.ToEdges++
	}
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

func (a *attacher) anchorBranch(e map[string]any) anchorSet {
	var out anchorSet
	out.addNode(a.n, Branch, branchEndpoint(a.c, str(e["repo"]), str(e["branch"])).ID, e)
	return out
}

func (a *attacher) anchorCapability(e map[string]any) anchorSet {
	var out anchorSet
	from := capabilityPrincipal(a.c, a.deployFP, e)
	to := branchEndpoint(a.c, str(e["repo"]), str(e["branch"]))
	out.addNode(a.n, from.Label, from.ID, e)
	out.addNode(a.n, Branch, to.ID, e)
	out.addEdge(a.s, graph.EdgeID(CanLandCode, from.ID, to.ID))
	return out
}

func (a *attacher) anchorCache(e map[string]any) anchorSet {
	var out anchorSet
	out.addNode(a.n, Cache, cacheEndpoint(a.c, str(e["repo"]), str(e["key_prefix"])).ID, e)
	return out
}

func (a *attacher) anchorDeployKeyReuse(e map[string]any) anchorSet {
	var out anchorSet
	for _, inst := range objects(e["instances"]) {
		fp := a.keyByID[str(inst["repo"])+"\x00"+decimal(inst["key_id"])]
		out.addNode(a.n, DeployKey, nd(DeployKey, "fingerprint", fp).ID, e)
	}
	return out
}

func (a *attacher) anchorDeploy(d map[string]any) anchorSet {
	var out anchorSet
	job := obj(d["job"])
	from := jobEndpoint(a.c, job)
	to := envEndpoint(a.c, str(job["repo"]), str(d["env_name"]))
	out.addNode(a.n, Job, from.ID, job)
	out.addNode(a.n, Environment, to.ID, obj(d["env"]))
	out.addEdge(a.s, graph.EdgeID(Targets, from.ID, to.ID))
	return out
}

func (a *attacher) anchorMint(m map[string]any) anchorSet {
	var out anchorSet
	minter := obj(m["minter"])
	out.addNode(a.n, Job, jobEndpoint(a.c, minter).ID, minter)
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
		out.addNode(a.n, Job, jobEndpoint(a.c, rec).ID, rec)
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
	out.addNode(a.n, Workflow, to.ID, nil)
	out.addNode(a.n, Job, from.ID, caller)
	out.addEdge(a.s, graph.EdgeID(Calls, from.ID, to.ID))
	return out
}

func (a *attacher) anchorArtifactHandoff(h map[string]any) anchorSet {
	var out anchorSet
	reader, writer := obj(h["reader"]), obj(h["writer"])
	art := nd(Artifact, "repo", a.c.full(str(reader["repo"])), "name", str(h["artifact_name"]))
	out.addNode(a.n, Job, jobEndpoint(a.c, reader).ID, reader)
	out.addNode(a.n, Job, jobEndpoint(a.c, writer).ID, writer)
	out.addNode(a.n, Artifact, art.ID, nil)
	out.addEdge(a.s, graph.EdgeID(Reads, jobEndpoint(a.c, reader).ID, art.ID))
	out.addEdge(a.s, graph.EdgeID(Writes, jobEndpoint(a.c, writer).ID, art.ID))
	return out
}

func (a *attacher) anchorWorkflowRunPair(p map[string]any) anchorSet {
	var out anchorSet
	up, down := obj(p["upstream"]), obj(p["downstream"])
	out.addNode(a.n, Job, jobEndpoint(a.c, down).ID, down)
	out.addNode(a.n, Job, jobEndpoint(a.c, up).ID, up)
	out.addNode(a.n, Workflow, workflowEndpoint(a.c, down).ID, down)
	out.addNode(a.n, Workflow, workflowEndpoint(a.c, up).ID, up)
	out.addEdge(a.s, graph.EdgeID(Triggers, workflowEndpoint(a.c, up).ID, workflowEndpoint(a.c, down).ID))
	return out
}
