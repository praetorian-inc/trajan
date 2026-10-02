package graph

import (
	"cmp"
	"context"
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
	"github.com/praetorian-inc/trajan/internal/ui"
	"github.com/praetorian-inc/trajan/pkg/finding"
)

func Build[L ~string, T ~string](ctx context.Context, cfg *engine.Config, runDir string,
	p Provider[L, T], targets map[string]Target) error {

	state, err := engine.LoadState(runDir)
	if err != nil {
		return err
	}
	if err := state.CheckPhase(engine.PhaseGraph); err != nil {
		return err
	}
	out := cfg.Sink()
	out.PhaseHeader("Graph")
	timer := engine.StartPhaseTimer(engine.PhaseGraph, "graph")
	stats, buildErr := runBuild(ctx, cfg, runDir, p, targets, timer)

	rec := timer.Stop(buildErr)
	state.RecordPhase(rec)
	saveErr := state.Save(runDir)
	if buildErr == nil {
		out.Outcome("Graph complete", []ui.Count{
			{Label: "nodes", N: stats.nodes},
			{Label: "edges", N: stats.edges},
		}, engine.Elapsed(rec.DurationS))
		if stats.attached > 0 || stats.unattached > 0 {
			out.Note(fmt.Sprintf("%d findings attached, %d unattached", stats.attached, stats.unattached))
		}
	}
	return errors.Join(buildErr, saveErr)
}

type buildStats struct{ nodes, edges, attached, unattached int }

type nodesFile[L ~string] struct {
	Nodes []Node[L] `json:"nodes"`
}

type edgesFile[L ~string, T ~string] struct {
	Edges []Edge[L, T] `json:"edges"`
}

func runBuild[L ~string, T ~string](ctx context.Context, cfg *engine.Config, runDir string,
	p Provider[L, T], targets map[string]Target, timer *engine.PhaseTimer) (buildStats, error) {

	// RunPartial calls onError from its workers.
	var errMu sync.Mutex
	onError := func(e error) {
		errMu.Lock()
		timer.Errors = append(timer.Errors, e.Error())
		errMu.Unlock()
	}

	c, err := LoadCorpus(ctx, cfg, runDir, p.SkipRecords(), onError)
	if err != nil {
		return buildStats{}, err
	}
	b, err := p.Open(c)
	if err != nil {
		return buildStats{}, err
	}
	c.Org = b.Org()

	findings, findingsSeen, err := engine.LoadFindings(ctx, cfg, runDir, onError)
	if err != nil {
		return buildStats{}, err
	}
	in := InputsSummary{
		NormalizeSeen:    c.Seen,
		NormalizeDropped: c.Seen - c.Files,
		FindingsSeen:     findingsSeen,
		FindingsDropped:  findingsSeen - len(findings),
	}
	timer.InputFiles = in.NormalizeSeen + in.FindingsSeen
	if in.NormalizeDropped+in.FindingsDropped > 0 {
		slog.Warn("graph built on incomplete input", "normalize_dropped", in.NormalizeDropped,
			"findings_dropped", in.FindingsDropped)
	}

	if err := os.RemoveAll(filepath.Join(runDir, engine.DirGraph)); err != nil {
		return buildStats{}, fmt.Errorf("clear %s: %w", engine.DirGraph, err)
	}

	nodes, err := b.Nodes(ctx)
	if err != nil {
		return buildStats{}, err
	}
	edges, err := b.Edges(ctx)
	if err != nil {
		return buildStats{}, err
	}
	observed := BackfillObserved(nodes, edges)
	dropped := DropDangling(nodes, edges)

	res, err := b.Attach(ctx, targets, findings)
	if err != nil {
		return buildStats{}, err
	}

	all := nodes.All()
	for i := range all {
		all[i].Findings = FinalizeFindings(all[i].Findings, all[i].Properties)
	}
	edgeList := edges.All()
	for i := range edgeList {
		edgeList[i].Findings = FinalizeFindings(edgeList[i].Findings, edgeList[i].Properties)
	}

	sum := Summarize(runDir, p, in, nodes, edges, observed, dropped, res)
	cp := engine.CurrentPhase{RunDir: runDir}
	for _, w := range []struct {
		rel string
		v   any
	}{
		{engine.GraphNodes(), nodesFile[L]{all}},
		{engine.GraphEdges(), edgesFile[L, T]{edgeList}},
		{engine.GraphResources(), resourcesFile{ToResources(p, c.Org, all)}},
		{engine.GraphRelationships(), relationshipsFile{ToRelationships(p, edgeList)}},
		{engine.GraphSummary(), sum},
	} {
		if err := cp.Write(w.rel, w.v); err != nil {
			return buildStats{}, fmt.Errorf("write %s: %w", w.rel, err)
		}
	}
	timer.OutputFiles = 5
	return buildStats{
		nodes:      len(all),
		edges:      len(edgeList),
		attached:   res.Attached,
		unattached: len(res.Unattached),
	}, nil
}

// An endpoint with a complete identity tuple and no backing record is a real entity
// outside the collection — a callee in an uncollected repo, an environment named only
// by a deployment — so emitting it is truthful where inventing an identity is not.
func BackfillObserved[L ~string, T ~string](n *NodeSet[L, T], s *EdgeSet[L, T]) int {
	minted := 0
	for _, id := range s.IDs() {
		e := s.Get(id)
		for _, ep := range [2]struct {
			id    string
			label L
		}{{e.From, e.FromLabel}, {e.To, e.ToLabel}} {
			if n.Has(ep.id) {
				continue
			}
			label, key, ok := ParseNodeID(n.Schema(), ep.id)
			if !ok || label != ep.label {
				continue
			}
			props := map[string]any{"observed_only": true}
			if src, isArray := e.Properties["_source"].([]any); isArray {
				props["_source"] = src
			}
			if n.Upsert(label, key, props, "") != nil {
				minted++
			}
		}
	}
	return minted
}

// ParseNodeID inverts NodeID. esc is injective and leaves no unescaped '|', so
// splitting on unescaped '|' recovers the identity tuple exactly.
func ParseNodeID[L ~string, T ~string](sc Schema[L, T], id string) (L, map[string]string, bool) {
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

	label := L(parts[0])
	want := sc.IdentityKey(label)
	if len(want) == 0 || len(parts)-1 != len(want) {
		return "", nil, false
	}
	key := make(map[string]string, len(want))
	for i, k := range want {
		key[k] = parts[i+1]
	}
	return label, key, true
}

// Zero on a correct build: backfillObserved has already emitted every endpoint
// whose identity is complete, so a survivor here is a builder bug.
func DropDangling[L ~string, T ~string](n *NodeSet[L, T], s *EdgeSet[L, T]) map[T]int {
	out := map[T]int{}
	for _, id := range s.IDs() {
		e := s.Get(id)
		if !n.Has(e.From) || !n.Has(e.To) {
			out[e.Type]++
			s.Delete(id)
		}
	}
	return out
}

// Findings are never nodes; each rule id lands in the bucket for its severity
// on the node or edge it was raised against.
const (
	FindingsCritical = "findings_critical"
	FindingsHigh     = "findings_high"
	FindingsMedium   = "findings_medium"
	FindingsLow      = "findings_low"
)

var severityBuckets = map[string]string{
	"critical": FindingsCritical,
	"high":     FindingsHigh,
	"medium":   FindingsMedium,
	"low":      FindingsLow,
}

// SeverityBucket returns "" for info and unknown severities, which have no
// bucket and are not written onto the graph.
func SeverityBucket(severity string) string { return severityBuckets[severity] }

func FindingBuckets() []string {
	return []string{FindingsCritical, FindingsHigh, FindingsMedium, FindingsLow}
}

func FinalizeFindings(fs []FindingRef, props map[string]any) []FindingRef {
	slices.SortFunc(fs, func(a, b FindingRef) int {
		return cmp.Or(
			cmp.Compare(finding.SeverityRank(b.Severity), finding.SeverityRank(a.Severity)),
			cmp.Compare(finding.ConfidenceRank(b.Confidence), finding.ConfidenceRank(a.Confidence)),
			cmp.Compare(a.RuleID, b.RuleID),
			cmp.Compare(a.Fingerprint, b.Fingerprint))
	})
	props["findings_count"] = len(fs)
	buckets := map[string][]string{}
	for _, f := range fs {
		if b := SeverityBucket(f.Severity); b != "" {
			buckets[b] = append(buckets[b], f.RuleID)
		}
	}
	for _, b := range FindingBuckets() {
		ids := buckets[b]
		if len(ids) == 0 {
			continue
		}
		// findings_<severity> is deduplicated to rule ids, so its length is a
		// rule count and not the number of findings at that severity.
		props["findings_count_"+strings.TrimPrefix(b, "findings_")] = len(ids)
		slices.Sort(ids)
		props[b] = slices.Compact(ids)
	}
	return fs
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

type NodesSummary[L ~string] struct {
	Total                int                   `json:"total"`
	ByLabel              map[L]int             `json:"by_label"`
	Synthetic            int                   `json:"synthetic"`
	ObservedOnly         int                   `json:"observed_only"`
	IncompleteIdentities map[L]int             `json:"incomplete_identities"`
	IdentityMerges       []IdentityMerge[L]    `json:"identity_merges"`
	PropertyConflicts    []PropertyConflict[L] `json:"property_conflicts"`
	DroppedProperties    int                   `json:"dropped_properties"`
}

type EdgesSummary[T ~string] struct {
	Total             int                 `json:"total"`
	ByType            map[T]int           `json:"by_type"`
	Unbuilt           countByType[string] `json:"unbuilt"`
	DroppedDangling   countByType[T]      `json:"dropped_dangling"`
	PropertyConflicts []EdgeConflict[T]   `json:"property_conflicts"`
}

type FindingsSummary struct {
	Total              int                 `json:"total"`
	Attached           int                 `json:"attached"`
	Unattached         int                 `json:"unattached"`
	AttachedTo         map[string]int      `json:"attached_to"`
	UnattachedByReason map[string]int      `json:"unattached_by_reason"`
	UnattachedByRule   map[string]int      `json:"unattached_by_rule"`
	UnattachedDetail   []UnattachedFinding `json:"unattached_detail"`
}

type GapsSummary[L ~string, T ~string] struct {
	EmptyLabels      []L        `json:"empty_labels"`
	EmptyEdgeTypes   []T        `json:"empty_edge_types"`
	EmptyEdgeTriples []string   `json:"empty_edge_triples"`
	Register         []GapEntry `json:"register"`
}

// A dropped input is a per-item failure the phase continues past, so every count
// downstream of it is a floor rather than a total; seen and dropped are reported
// so a consumer can tell a complete graph from one built on part of its inputs.
type InputsSummary struct {
	NormalizeSeen    int `json:"normalize_seen"`
	NormalizeDropped int `json:"normalize_dropped"`
	FindingsSeen     int `json:"findings_seen"`
	FindingsDropped  int `json:"findings_dropped"`
}

type Summary[L ~string, T ~string] struct {
	RunID       string            `json:"run_id"`
	GeneratedAt string            `json:"generated_at"`
	Inputs      InputsSummary     `json:"inputs"`
	Nodes       NodesSummary[L]   `json:"nodes"`
	Edges       EdgesSummary[T]   `json:"edges"`
	Findings    FindingsSummary   `json:"findings"`
	Gaps        GapsSummary[L, T] `json:"gaps"`
}

const conflictsReported = 20

func Summarize[L ~string, T ~string](runDir string, p Provider[L, T], in InputsSummary,
	nodes *NodeSet[L, T], edges *EdgeSet[L, T],
	observed int, dropped map[T]int, res *AttachResult) Summary[L, T] {

	all, edgeList := nodes.All(), edges.All()
	byLabel := nodes.ByLabel()
	byType := edges.ByType()
	synthetic := 0
	for _, n := range all {
		if Truthy(n.Properties["synthetic"]) {
			synthetic++
		}
	}
	conflicts := nodes.PropertyConflicts()
	edgeConflicts := edges.PropertyConflicts()

	empties := []L{}
	for _, l := range p.NodeLabels() {
		if byLabel[l] == 0 {
			empties = append(empties, l)
		}
	}
	emptyEdges := []T{}
	for _, t := range p.EdgeTypes() {
		if byType[t] == 0 {
			emptyEdges = append(emptyEdges, t)
		}
	}

	return Summary[L, T]{
		RunID:       filepath.Base(runDir),
		GeneratedAt: engine.IsoformatUTC(time.Now()),
		Inputs:      in,
		Nodes: NodesSummary[L]{
			Total:                len(all),
			ByLabel:              byLabel,
			Synthetic:            synthetic,
			ObservedOnly:         observed,
			IncompleteIdentities: nodes.IncompleteIdentities(),
			IdentityMerges:       nodes.Merges(),
			PropertyConflicts:    conflicts[:min(conflictsReported, len(conflicts))],
			DroppedProperties:    nodes.Dropped(),
		},
		Edges: EdgesSummary[T]{
			Total:             len(edgeList),
			ByType:            byType,
			Unbuilt:           counted(maps.Clone(edges.Unbuilt())),
			DroppedDangling:   counted(dropped),
			PropertyConflicts: edgeConflicts[:min(conflictsReported, len(edgeConflicts))],
		},
		Findings: FindingsSummary{
			Total:              res.Total,
			Attached:           res.Attached,
			Unattached:         len(res.Unattached),
			AttachedTo:         map[string]int{"nodes": res.ToNodes, "edges": res.ToEdges},
			UnattachedByReason: res.ByReason,
			UnattachedByRule:   res.ByRule,
			UnattachedDetail:   res.Unattached,
		},
		Gaps: GapsSummary[L, T]{
			EmptyLabels:      empties,
			EmptyEdgeTypes:   emptyEdges,
			EmptyEdgeTriples: edges.EmptyTriples(edgeList),
			Register:         registerWithCounts(p.Gaps(), res.ByTarget),
		},
	}
}

// Targets names the rule targets whose unattached findings the gap explains, so
// findings_blocked is computed from the run rather than written down. A target belongs
// to exactly one row, or the column stops summing to findings.unattached.
type GapEntry struct {
	Subject         string   `json:"subject"`
	Kind            string   `json:"kind"`
	Status          string   `json:"status"`
	Reason          string   `json:"reason"`
	UpstreamFix     string   `json:"upstream_fix"`
	FindingsBlocked int      `json:"findings_blocked"`
	Targets         []string `json:"targets"`
}

func registerWithCounts(register []GapEntry, byTarget map[string]int) []GapEntry {
	out := slices.Clone(register)
	for i := range out {
		for _, t := range out[i].Targets {
			out[i].FindingsBlocked += byTarget[t]
		}
	}
	return out
}
