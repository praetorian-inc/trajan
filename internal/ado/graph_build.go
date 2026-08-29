package ado

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/finding"
	"github.com/praetorian-inc/trajan/internal/ui"
)

const (
	scanDir  = "20-scan"
	graphDir = "30-graph"
)

func BuildGraph(ctx context.Context, cfg *engine.Config, runDir string, targets map[string]Target) error {
	state, err := engine.LoadState(runDir)
	if err != nil {
		return err
	}
	if err := state.CheckPhase(engine.PhaseGraph); err != nil {
		return err
	}
	ui.PhaseHeader("Graph")
	timer := engine.StartPhaseTimer(engine.PhaseGraph, "graph")
	stats, buildErr := runBuild(ctx, cfg, runDir, targets, timer)

	rec := timer.Stop(buildErr)
	state.RecordPhase(rec)
	saveErr := state.Save(runDir)
	if buildErr == nil {
		ui.Outcome("Graph complete", []ui.Count{
			{Label: "nodes", N: stats.nodes},
			{Label: "edges", N: stats.edges},
			{Label: "findings attached", N: stats.attached},
		}, engine.Elapsed(rec.DurationS))
	}
	return errors.Join(buildErr, saveErr)
}

type buildStats struct{ nodes, edges, attached int }

type nodesFile struct {
	Nodes []node `json:"nodes"`
}

type edgesFile struct {
	Edges []edge `json:"edges"`
}

func runBuild(ctx context.Context, cfg *engine.Config, runDir string, targets map[string]Target, timer *engine.PhaseTimer) (buildStats, error) {
	var errMu sync.Mutex
	onError := func(e error) {
		errMu.Lock()
		timer.Errors = append(timer.Errors, e.Error())
		errMu.Unlock()
	}

	c, err := loadCorpus(ctx, cfg, runDir, onError)
	if err != nil {
		return buildStats{}, err
	}
	findings, findingsSeen, err := loadFindings(ctx, cfg, runDir, onError)
	if err != nil {
		return buildStats{}, err
	}
	in := inputsSummary{
		NormalizeSeen:    c.seen,
		NormalizeDropped: c.seen - c.files,
		FindingsSeen:     findingsSeen,
		FindingsDropped:  findingsSeen - len(findings),
	}
	timer.InputFiles = in.NormalizeSeen + in.FindingsSeen
	if in.NormalizeDropped+in.FindingsDropped > 0 {
		slog.Warn("graph built on incomplete input", "normalize_dropped", in.NormalizeDropped,
			"findings_dropped", in.FindingsDropped)
	}

	if err := os.RemoveAll(filepath.Join(runDir, graphDir)); err != nil {
		return buildStats{}, fmt.Errorf("clear %s: %w", graphDir, err)
	}

	nodes := buildNodes(c)
	edges, fromRecord, err := buildEdges(c, nodes)
	if err != nil {
		return buildStats{}, err
	}
	observed := backfillObserved(nodes, edges)
	dropped := dropDangling(nodes, edges)
	nodes.sweepIllegal()

	att := newAttacher(c, nodes, edges, fromRecord, targets)
	if err := att.run(ctx, findings); err != nil {
		return buildStats{}, err
	}

	all := nodes.all()
	for i := range all {
		all[i].Findings = finalizeFindings(all[i].Findings, all[i].Properties)
	}
	edgeList := edges.all()
	for i := range edgeList {
		edgeList[i].Findings = finalizeFindings(edgeList[i].Findings, edgeList[i].Properties)
	}
	sum := summarize(runDir, in, all, edgeList, edges, nodes, observed, dropped, &att.res)

	cp := engine.CurrentPhase{RunDir: runDir}
	for _, w := range []struct {
		rel string
		v   any
	}{
		{engine.GraphNodes(), nodesFile{all}},
		{engine.GraphEdges(), edgesFile{edgeList}},
		{engine.GraphSummary(), sum},
	} {
		if err := cp.Write(w.rel, w.v); err != nil {
			return buildStats{}, fmt.Errorf("write %s: %w", w.rel, err)
		}
	}
	timer.OutputFiles = 3
	return buildStats{nodes: len(all), edges: len(edgeList), attached: att.res.attached}, nil
}

func loadFindings(ctx context.Context, cfg *engine.Config, runDir string, onError func(error)) ([]finding.Finding, int, error) {
	pp := engine.PriorPhase{RunDir: runDir}
	if _, err := os.Stat(pp.Abs(scanDir)); err != nil {
		return nil, 0, fmt.Errorf("%s unreadable; run `trajan ado scan` first: %w", scanDir, err)
	}
	files, err := pp.IterJSON(scanDir)
	if err != nil {
		return nil, 0, err
	}
	out := engine.RunPartial(ctx, cfg.Concurrency, files,
		func(_ context.Context, f engine.PhaseFile) (finding.Finding, error) {
			var v finding.Finding
			if err := json.Unmarshal(f.Data, &v); err != nil {
				return v, fmt.Errorf("%s/%s: %w", scanDir, f.Rel, err)
			}
			return v, nil
		},
		func(_ engine.PhaseFile, err error) { onError(err) })
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	slices.SortFunc(out, func(a, b finding.Finding) int { return cmp.Compare(a.Fingerprint, b.Fingerprint) })
	return out, len(files), nil
}

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
			n := s.upsert(l, c.identityOf(l, r.fields), s.recordProps(l, r.fields), r.rel)
			s.index(r.dir, r.id, n)
		}
	}
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
	gc := graphCtx{Org: c.org, Principal: principalLabels(c)}
	for _, t := range EdgeTypes() {
		for _, r := range c.byKind[string(t)] {
			rs := resolveEndpoints(gc, r.fields)
			if len(rs) == 0 {
				s.miss(t, "", "", 1)
				continue
			}
			props := edgeProps(r.fields)
			for _, e := range rs {
				id := s.add(e.Type, e.From, e.To, props)
				if id == "" || r.id == "" {
					continue
				}
				ref := recordRef{r.dir, r.id}
				fromRecord[ref] = append(fromRecord[ref], id)
			}
		}
	}
	return s, fromRecord, s.err()
}

func emitContainment(n *nodeSet, s *edgeSet) {
	for _, ct := range containment {
		for _, child := range n.all() {
			if child.Labels[0] != ct.child {
				continue
			}
			parent := endpoint{ct.parent, map[string]string{}}
			for _, k := range IdentityKey(ct.parent) {
				parent.Key[k] = child.Key[k]
			}
			s.add(ct.edge, parent, endpoint{ct.child, child.Key}, nil)
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

func edgeProps(f map[string]any) map[string]any {
	out := make(map[string]any, len(f))
	for k, v := range f {
		if k == "_id" || k == "kind" || k == "_provenance" || !legalProp(v) {
			continue
		}
		out[k] = v
	}
	return out
}

func backfillObserved(n *nodeSet, s *edgeSet) int {
	minted := 0
	for _, id := range slices.Sorted(maps.Keys(s.byID)) {
		e := s.byID[id]
		for _, ep := range [2]struct {
			id    string
			label NodeLabel
		}{{e.From, e.FromLabel}, {e.To, e.ToLabel}} {
			if n.has(ep.id) {
				continue
			}
			label, key, ok := parseNodeID(ep.id)
			if !ok || label != ep.label {
				continue
			}
			if n.upsert(label, key, map[string]any{"observed_only": true}, "") != nil {
				minted++
			}
		}
	}
	return minted
}

// esc is injective and leaves no unescaped '|', so splitting on unescaped '|' recovers
// the identity tuple exactly.
func parseNodeID(id string) (NodeLabel, map[string]string, bool) {
	parts := []string{}
	var b strings.Builder
	escaped := false
	for _, r := range id {
		switch {
		case escaped:
			b.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '|':
			parts = append(parts, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	parts = append(parts, b.String())

	label := NodeLabel(parts[0])
	want := IdentityKey(label)
	if len(want) == 0 || len(parts)-1 != len(want) {
		return "", nil, false
	}
	key := make(map[string]string, len(want))
	for i, k := range want {
		key[k] = parts[i+1]
	}
	return label, key, true
}

func dropDangling(n *nodeSet, s *edgeSet) map[EdgeType]int {
	out := map[EdgeType]int{}
	for id, e := range s.byID {
		if !n.has(e.From) || !n.has(e.To) {
			out[e.Type]++
			delete(s.byID, id)
		}
	}
	return out
}

type countByType[K ~string] struct {
	Total  int       `json:"total"`
	ByType map[K]int `json:"by_type"`
}

func counted[K ~string](m map[K]int) countByType[K] {
	total := 0
	for _, n := range m {
		total += n
	}
	return countByType[K]{total, m}
}

type inputsSummary struct {
	NormalizeSeen    int `json:"normalize_seen"`
	NormalizeDropped int `json:"normalize_dropped"`
	FindingsSeen     int `json:"findings_seen"`
	FindingsDropped  int `json:"findings_dropped"`
}

type nodesSummary struct {
	Total                int                `json:"total"`
	ByLabel              map[NodeLabel]int  `json:"by_label"`
	ObservedOnly         int                `json:"observed_only"`
	IncompleteIdentities map[NodeLabel]int  `json:"incomplete_identities"`
	IdentityMerges       []identityMerge    `json:"identity_merges"`
	PropertyConflicts    []propertyConflict `json:"property_conflicts"`
	DroppedProperties    int                `json:"dropped_properties"`
}

type edgesSummary struct {
	Total             int                   `json:"total"`
	ByType            map[EdgeType]int      `json:"by_type"`
	Unbuilt           countByType[string]   `json:"unbuilt"`
	DroppedDangling   countByType[EdgeType] `json:"dropped_dangling"`
	PropertyConflicts []edgeConflict        `json:"property_conflicts"`
}

type gapsSummary struct {
	EmptyLabels      []NodeLabel `json:"empty_labels"`
	EmptyEdgeTypes   []EdgeType  `json:"empty_edge_types"`
	EmptyEdgeTriples []string    `json:"empty_edge_triples"`
	Register         []gapEntry  `json:"register"`
}

type findingsSummary struct {
	Total              int                 `json:"total"`
	Attached           int                 `json:"attached"`
	Unattached         int                 `json:"unattached"`
	AttachedTo         map[string]int      `json:"attached_to"`
	UnattachedByReason map[string]int      `json:"unattached_by_reason"`
	UnattachedByRule   map[string]int      `json:"unattached_by_rule"`
	UnattachedDetail   []unattachedFinding `json:"unattached_detail"`
}

type summary struct {
	RunID       string          `json:"run_id"`
	GeneratedAt string          `json:"generated_at"`
	Inputs      inputsSummary   `json:"inputs"`
	Nodes       nodesSummary    `json:"nodes"`
	Edges       edgesSummary    `json:"edges"`
	Findings    findingsSummary `json:"findings"`
	Gaps        gapsSummary     `json:"gaps"`
}

const conflictsReported = 20

func summarize(runDir string, in inputsSummary, all []node, edgeList []edge, edges *edgeSet, nodes *nodeSet,
	observed int, dropped map[EdgeType]int, res *attachResult) summary {

	byLabel := nodes.byLabel()
	byType := edges.byType()
	conflicts := nodes.propertyConflicts()
	edgeConflicts := edges.propertyConflicts()

	empties := []NodeLabel{}
	for _, l := range NodeLabels() {
		if byLabel[l] == 0 {
			empties = append(empties, l)
		}
	}
	emptyEdges := []EdgeType{}
	for _, t := range EdgeTypes() {
		if byType[t] == 0 {
			emptyEdges = append(emptyEdges, t)
		}
	}

	return summary{
		RunID:       filepath.Base(runDir),
		GeneratedAt: engine.IsoformatUTC(time.Now()),
		Inputs:      in,
		Nodes: nodesSummary{
			Total:                len(all),
			ByLabel:              byLabel,
			ObservedOnly:         observed,
			IncompleteIdentities: nodes.incompleteIdentities(),
			IdentityMerges:       nodes.merges(),
			PropertyConflicts:    conflicts[:min(conflictsReported, len(conflicts))],
			DroppedProperties:    nodes.dropped,
		},
		Edges: edgesSummary{
			Total:             len(edgeList),
			ByType:            byType,
			Unbuilt:           counted(edges.unbuilt),
			DroppedDangling:   counted(dropped),
			PropertyConflicts: edgeConflicts[:min(conflictsReported, len(edgeConflicts))],
		},
		Findings: findingsSummary{
			Total:              res.total,
			Attached:           res.attached,
			Unattached:         len(res.unattached),
			AttachedTo:         map[string]int{"nodes": res.toNodes, "edges": res.toEdges},
			UnattachedByReason: res.byReason,
			UnattachedByRule:   res.byRule,
			UnattachedDetail:   res.unattached,
		},
		Gaps: gapsSummary{
			EmptyLabels:      empties,
			EmptyEdgeTypes:   emptyEdges,
			EmptyEdgeTriples: emptyEdgeTriples(edgeList),
			Register:         registerWithCounts(res.byTarget),
		},
	}
}

// Targets names the rule targets whose unattached findings the gap explains, so
// findings_blocked is computed from the run rather than written down. A target belongs
// to exactly one row, or the column stops summing to findings.unattached.
type gapEntry struct {
	Subject         string   `json:"subject"`
	Kind            string   `json:"kind"`
	Status          string   `json:"status"`
	Reason          string   `json:"reason"`
	UpstreamFix     string   `json:"upstream_fix"`
	FindingsBlocked int      `json:"findings_blocked"`
	Targets         []string `json:"targets"`
}

func registerWithCounts(byTarget map[string]int) []gapEntry {
	out := slices.Clone(gapRegister)
	for i := range out {
		for _, t := range out[i].Targets {
			out[i].FindingsBlocked += byTarget[t]
		}
	}
	return out
}

var gapRegister = []gapEntry{{
	Subject:     "RUNS_AS{Pipeline,BuildServiceIdentity}",
	Kind:        "edge",
	Status:      "identity_defect",
	Reason:      "the runs-as record carries identity_scope (project or collection) and no descriptor, so there is no build service identity to point at. The principals are collected — principals/build-service holds them — but nothing joins a scope to one.",
	UpstreamFix: "index BuildServiceIdentity by scope and project in the builder, then resolve the pair; the descriptor is already on the principal record.",
}, {
	Subject:     "TRIGGERS_ON_COMPLETION{Pipeline,Pipeline}",
	Kind:        "edge",
	Status:      "identity_defect",
	Reason:      "source_pipeline is a pipeline name and Pipeline identity needs the definition id, so the endpoint cannot be named from the record alone.",
	UpstreamFix: "build a (project, name) -> pipeline_id index in the builder. Names are not unique across projects, so source_project must qualify it.",
}, {
	Subject:     "SecureFile / KeyVault / WIFCredential / PipelineDecorator / ServiceHookSubscription",
	Kind:        "node",
	Status:      "empty",
	Reason:      "declared with normalizers in place and no instance in any corpus: the APIs return empty arrays because no test org provisions them. Fixture gaps, not code gaps, and distinct from a label whose writer is missing.",
	UpstreamFix: "provision a secure file, a key-vault-linked variable group, a WIF service connection, a decorator extension and a service hook in the firing range.",
	Targets:     []string{"node(SecureFile)"},
}, {
	Subject:     "extends: template stages",
	Kind:        "node",
	Status:      "partial",
	Reason:      "a pipeline that emits no jobs falls back to ADO's server-resolved preview, so extends: pipelines now yield stages and jobs. A pipeline mixing inline stages with a template stage reference still emits only the inline ones — jobs > 0, so the fallback does not fire, and widening the trigger would double-emit and erase the ${{ }} parameter sinks the inline stages carry.",
	UpstreamFix: "none wanted. The preview substitutes every ${{ }} before returning, so it can only ever be a fallback.",
}, {
	Subject:     "HAS_ROLE for uncollected principals",
	Kind:        "edge",
	Status:      "partial",
	Reason:      "an ACE whose identity the Graph API does not enumerate — built-in server SIDs — has no principal record, so there is no label to point at and the grant is counted rather than pointed at an invented node. 14 of 45 rows in the richest corpus.",
	UpstreamFix: "none available: the descriptor is kept on the record, but User and SecurityGroup cannot be told apart without the Graph API returning the subject.",
}, {
	Subject:     "RUNS_ON for Microsoft-hosted jobs",
	Kind:        "edge",
	Status:      "partial",
	Reason:      "a job whose pool is a vmImage names no project queue, so project_agent_pool_id is 0 and no ProjectAgentPool exists to point at. Every unbuilt RUNS_ON in every corpus is this case; the self-hosted jobs all resolve.",
	UpstreamFix: "none wanted. Pointing hosted jobs at a stand-in pool would assert a shared machine, which is the claim the agent rules exist to test.",
	Targets:     []string{"edge(RUNS_ON)"},
}, {
	Subject:     "attack edge step_index",
	Kind:        "edge",
	Status:      "identity_defect",
	Reason:      "parallel edges of one type between one pair do not exist in this model, so two sinks in different steps of the same job merge onto one edge and the second step_index is discarded.",
	UpstreamFix: "carry the step indices as an array property rather than a scalar, once a rule needs to name the step.",
}, {
	Subject:     "ACL namespace coverage",
	Kind:        "edge",
	Status:      "partial",
	Reason:      "3 of roughly 90 security namespaces are read (Git, Build, ServiceEndpoints), and the Build ACL is read at the project token only, so QUEUE_TIME_INJECTION source_principals is a project-wide approximation rather than a per-pipeline grant.",
	UpstreamFix: "read the Build namespace at the definition token, and add the namespaces governing variable groups, secure files and environments.",
}, {
	Subject:     "ArtifactsFeed scope",
	Kind:        "node",
	Status:      "partial",
	Reason:      "normalizeFeeds collects only the org-level feed list and hardcodes scope: \"org\", which is asserted rather than observed. Project-scoped feeds are invisible.",
	UpstreamFix: "collect per-project feeds; scope is already in the identity key, so they slot in without rekeying.",
}, {
	Subject:     "task groups, classic releases, deployment groups",
	Kind:        "node",
	Status:      "not_collected",
	Reason:      "no NormalizeADO path helper exists for any of them. Task groups are the ADO composite-action analogue and the reusable-code supply chain; cat-14's five rules are self-described posture proxies standing in for classic releases.",
	UpstreamFix: "normalize the already-collected release-definition and build-definition surfaces, then add node writers.",
}, {
	Subject:     "synthetic positional names",
	Kind:        "node",
	Status:      "identity_defect",
	Reason:      "an unnamed stage or job becomes stage_<i> / job_<i>, so inserting a stage re-keys every downstream job and every taint edge that hangs off it. step_index is likewise array position and the only step identity.",
	UpstreamFix: "none available: the YAML supplies no other identity, and a content hash would churn on every edit.",
}}
