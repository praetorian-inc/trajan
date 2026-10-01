package graph

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
)

type FindingRef struct {
	RuleID      string `json:"rule_id"`
	Fingerprint string `json:"fingerprint"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Target      string `json:"target"`
	SubjectKind string `json:"subject_kind"`
	SubjectID   string `json:"subject_id"`
	Title       string `json:"title"`
}

// Findings is a sibling of Properties, not a member: Neo4j property values
// cannot be arrays of maps, so nesting it would make nodes.json un-importable.
type Node[L ~string] struct {
	ID         string            `json:"id"`
	Labels     []L               `json:"labels"`
	Key        map[string]string `json:"key"`
	Properties map[string]any    `json:"properties"`
	Findings   []FindingRef      `json:"findings"`
}

type Edge[L ~string, T ~string] struct {
	ID         string         `json:"id"`
	Type       T              `json:"type"`
	From       string         `json:"from"`
	To         string         `json:"to"`
	FromLabel  L              `json:"from_label"`
	ToLabel    L              `json:"to_label"`
	Properties map[string]any `json:"properties"`
	Findings   []FindingRef   `json:"findings"`
}

type IdentityMerge[L ~string] struct {
	Label         L      `json:"label"`
	SourceRecords int    `json:"source_records"`
	Nodes         int    `json:"nodes"`
	MergedRecords int    `json:"merged_records"`
	Note          string `json:"note"`
}

type PropertyConflict[L ~string] struct {
	Label     L      `json:"label"`
	Property  string `json:"property"`
	Discarded int    `json:"discarded"`
}

type EdgeConflict[T ~string] struct {
	Type      T      `json:"type"`
	Property  string `json:"property"`
	Discarded int    `json:"discarded"`
}

func esc(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "|", `\|`)
}

func NodeID[L ~string, T ~string](sc Schema[L, T], l L, key map[string]string) string {
	parts := []string{string(l)}
	for _, k := range sc.IdentityKey(l) {
		parts = append(parts, esc(key[k]))
	}
	return strings.Join(parts, "|")
}

func EdgeID[T ~string](t T, from, to string) string {
	return string(t) + "|" + esc(from) + "|" + esc(to)
}

// An empty from or to names an endpoint the writer could not label at all.
func EdgeKey[L ~string, T ~string](t T, from, to L) string {
	return fmt.Sprintf("%s{%s,%s}", t, from, to)
}

type Endpoint[L ~string] struct {
	Label L
	Key   map[string]string
	ID    string
}

type conflictKey[L ~string] struct {
	label    L
	property string
}

type edgeConflictKey[T ~string] struct {
	edgeType T
	property string
}

type SetOptions[L ~string] struct {
	OrTrue      map[string]bool
	SkipProps   []string
	MergeLabels map[L]bool
	MergeNotes  map[L]string
}

type NodeSet[L ~string, T ~string] struct {
	schema Schema[L, T]
	opts   SetOptions[L]

	byID map[string]*Node[L]
	// subjects indexes a finding's (subject.kind, subject.id) onto the node the
	// record produced. subject.id is a record _id and is never parsed.
	subjects   map[string]map[string]string
	sourceRecs map[L]int
	incomplete map[L]int
	conflicts  map[conflictKey[L]]int
	illegal    map[conflictKey[L]]bool
	dropped    int
}

func NewNodeSet[L ~string, T ~string](sc Schema[L, T], opts SetOptions[L]) *NodeSet[L, T] {
	return &NodeSet[L, T]{
		schema:     sc,
		opts:       opts,
		byID:       map[string]*Node[L]{},
		subjects:   map[string]map[string]string{},
		sourceRecs: map[L]int{},
		incomplete: map[L]int{},
		conflicts:  map[conflictKey[L]]int{},
		illegal:    map[conflictKey[L]]bool{},
	}
}

func (s *NodeSet[L, T]) Schema() Schema[L, T] { return s.schema }

func (s *NodeSet[L, T]) NodeID(l L, key map[string]string) string {
	return NodeID(s.schema, l, key)
}

// Returns nil when an identity value does not identify: a placeholder would have to
// invent identity, and every consumer of the graph asks reachability questions.
func (s *NodeSet[L, T]) Upsert(l L, key map[string]string, props map[string]any, source string) *Node[L] {
	ident := s.schema.IdentityKey(l)
	if len(ident) == 0 {
		return nil
	}
	k := make(map[string]string, len(ident))
	for _, name := range ident {
		v := key[name]
		if !s.schema.Identifies(v) {
			s.incomplete[l]++
			return nil
		}
		k[name] = v
	}
	id := NodeID(s.schema, l, k)
	s.sourceRecs[l]++

	n := s.byID[id]
	if n == nil {
		n = &Node[L]{ID: id, Labels: []L{l}, Key: k, Properties: map[string]any{}, Findings: []FindingRef{}}
		s.byID[id] = n
	}
	s.Merge(n, props)
	if source != "" {
		s.Merge(n, map[string]any{"_source": []any{source}})
	}
	n.Properties["graph_id"] = id
	return n
}

func (s *NodeSet[L, T]) Merge(n *Node[L], props map[string]any) {
	for _, k := range slices.Sorted(maps.Keys(props)) {
		v := props[k]
		old, seen := n.Properties[k]
		if !seen {
			n.Properties[k] = v
			continue
		}
		if s.opts.OrTrue[k] {
			n.Properties[k] = Truthy(old) || Truthy(v)
			continue
		}
		ao, aok := old.([]any)
		an, nok := v.([]any)
		if aok && nok {
			n.Properties[k] = unionArray(ao, an)
			continue
		}
		if scalarKey(old) != scalarKey(v) {
			s.conflicts[conflictKey[L]{n.Labels[0], k}]++
		}
	}
}

func (s *NodeSet[L, T]) Index(kind, recordID string, n *Node[L]) {
	if n == nil || recordID == "" {
		return
	}
	if s.subjects[kind] == nil {
		s.subjects[kind] = map[string]string{}
	}
	if _, dup := s.subjects[kind][recordID]; !dup {
		s.subjects[kind][recordID] = n.ID
	}
}

func (s *NodeSet[L, T]) Subject(kind, recordID string) (string, bool) {
	id, ok := s.subjects[kind][recordID]
	return id, ok
}

func (s *NodeSet[L, T]) Get(id string) *Node[L] { return s.byID[id] }

func (s *NodeSet[L, T]) Has(id string) bool { _, ok := s.byID[id]; return ok }

func (s *NodeSet[L, T]) Len() int { return len(s.byID) }

func (s *NodeSet[L, T]) IDs() []string { return slices.Sorted(maps.Keys(s.byID)) }

func (s *NodeSet[L, T]) IllegalProp(l L, property string) bool {
	return s.illegal[conflictKey[L]{l, property}]
}

func (s *NodeSet[L, T]) Each(fn func(*Node[L])) {
	for _, id := range slices.Sorted(maps.Keys(s.byID)) {
		fn(s.byID[id])
	}
}

func (s *NodeSet[L, T]) All() []Node[L] {
	out := make([]Node[L], 0, len(s.byID))
	for _, n := range s.byID {
		out = append(out, *n)
	}
	slices.SortFunc(out, func(a, b Node[L]) int {
		return cmp.Or(cmp.Compare(a.Labels[0], b.Labels[0]), cmp.Compare(a.ID, b.ID))
	})
	return out
}

func (s *NodeSet[L, T]) ByLabel() map[L]int {
	labels := s.schema.NodeLabels()
	out := make(map[L]int, len(labels))
	for _, l := range labels {
		out[l] = 0
	}
	for _, n := range s.byID {
		out[n.Labels[0]]++
	}
	return out
}

func (s *NodeSet[L, T]) Merges() []IdentityMerge[L] {
	counts := s.ByLabel()
	out := []IdentityMerge[L]{}
	for _, l := range s.schema.NodeLabels() {
		src := s.sourceRecs[l]
		if s.opts.MergeLabels != nil && !s.opts.MergeLabels[l] {
			continue
		}
		if src == 0 || src == counts[l] {
			continue
		}
		out = append(out, IdentityMerge[L]{l, src, counts[l], src - counts[l], s.opts.MergeNotes[l]})
	}
	return out
}

func (s *NodeSet[L, T]) PropertyConflicts() []PropertyConflict[L] {
	out := make([]PropertyConflict[L], 0, len(s.conflicts))
	for k, n := range s.conflicts {
		out = append(out, PropertyConflict[L]{k.label, k.property, n})
	}
	slices.SortFunc(out, func(a, b PropertyConflict[L]) int {
		return cmp.Or(cmp.Compare(b.Discarded, a.Discarded),
			cmp.Compare(a.Label, b.Label), cmp.Compare(a.Property, b.Property))
	})
	return out
}

func (s *NodeSet[L, T]) IncompleteIdentities() map[L]int { return maps.Clone(s.incomplete) }

func (s *NodeSet[L, T]) Dropped() int { return s.dropped }

func (s *NodeSet[L, T]) RecordProps(l L, fields map[string]any) map[string]any {
	ident := s.schema.IdentityKey(l)
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		if k == "_id" || k == "_provenance" || slices.Contains(s.opts.SkipProps, k) || slices.Contains(ident, k) {
			continue
		}
		if !LegalProp(v) {
			s.illegal[conflictKey[L]{l, k}] = true
			continue
		}
		out[k] = v
	}
	return out
}

// SweepIllegal runs once every emitter has been seen, because a label's
// declared shape is the union of the shapes of all its sources.
func (s *NodeSet[L, T]) SweepIllegal() {
	for _, n := range s.byID {
		for k := range n.Properties {
			if s.illegal[conflictKey[L]{n.Labels[0], k}] {
				delete(n.Properties, k)
				s.dropped++
			}
		}
	}
}

type EdgeSet[L ~string, T ~string] struct {
	schema Schema[L, T]
	byID   map[string]*Edge[L, T]
	// Keyed by triple, not by type: a type with several declared endpoint pairs
	// otherwise reports one number that no pair can be held responsible for.
	unbuilt   map[string]int
	conflicts map[edgeConflictKey[T]]int
	illegal   map[string]int
}

func NewEdgeSet[L ~string, T ~string](sc Schema[L, T]) *EdgeSet[L, T] {
	return &EdgeSet[L, T]{schema: sc, byID: map[string]*Edge[L, T]{}, unbuilt: map[string]int{},
		conflicts: map[edgeConflictKey[T]]int{}, illegal: map[string]int{}}
}

func (s *EdgeSet[L, T]) Complete(e Endpoint[L]) bool {
	if e.ID != "" {
		return true
	}
	want := s.schema.IdentityKey(e.Label)
	if len(want) == 0 {
		return false
	}
	for _, k := range want {
		if e.Key[k] == "" {
			return false
		}
	}
	return true
}

func (s *EdgeSet[L, T]) endpointID(e Endpoint[L]) string {
	if e.ID != "" {
		return e.ID
	}
	return NodeID(s.schema, e.Label, e.Key)
}

// Merges into the existing edge when (type, from, to) repeats: parallel edges of one
// type between one pair do not exist in this model. An endpoint with an incomplete
// identity is dropped and counted rather than invented.
func (s *EdgeSet[L, T]) Add(t T, from, to Endpoint[L], props map[string]any) string {
	if !s.Complete(from) || !s.Complete(to) {
		s.unbuilt[EdgeKey(t, from.Label, to.Label)]++
		return ""
	}
	if !s.schema.ValidEdge(t, from.Label, to.Label) {
		s.illegal[EdgeKey(t, from.Label, to.Label)]++
		return ""
	}
	fromID, toID := s.endpointID(from), s.endpointID(to)
	id := EdgeID(t, fromID, toID)
	e := s.byID[id]
	if e == nil {
		e = &Edge[L, T]{
			ID: id, Type: t, From: fromID, To: toID,
			FromLabel: from.Label, ToLabel: to.Label,
			Properties: map[string]any{}, Findings: []FindingRef{},
		}
		s.byID[id] = e
	}
	for _, k := range slices.Sorted(maps.Keys(props)) {
		v := props[k]
		old, seen := e.Properties[k]
		if !seen {
			e.Properties[k] = v
			continue
		}
		ao, aok := old.([]any)
		an, nok := v.([]any)
		if aok && nok {
			e.Properties[k] = unionArray(ao, an)
			continue
		}
		if scalarKey(old) != scalarKey(v) {
			s.conflicts[edgeConflictKey[T]{t, k}]++
		}
	}
	e.Properties["graph_id"] = id
	return id
}

func (s *EdgeSet[L, T]) Miss(t T, from, to L, n int) { s.unbuilt[EdgeKey(t, from, to)] += n }

func (s *EdgeSet[L, T]) Get(id string) *Edge[L, T] { return s.byID[id] }

func (s *EdgeSet[L, T]) IDs() []string { return slices.Sorted(maps.Keys(s.byID)) }

func (s *EdgeSet[L, T]) Delete(id string) { delete(s.byID, id) }

func (s *EdgeSet[L, T]) All() []Edge[L, T] {
	out := make([]Edge[L, T], 0, len(s.byID))
	for _, e := range s.byID {
		out = append(out, *e)
	}
	slices.SortFunc(out, func(a, b Edge[L, T]) int {
		return cmp.Or(cmp.Compare(a.Type, b.Type), cmp.Compare(a.From, b.From), cmp.Compare(a.To, b.To))
	})
	return out
}

func (s *EdgeSet[L, T]) ByType() map[T]int {
	types := s.schema.EdgeTypes()
	out := make(map[T]int, len(types))
	for _, t := range types {
		out[t] = 0
	}
	for _, e := range s.byID {
		out[e.Type]++
	}
	return out
}

func (s *EdgeSet[L, T]) Len() int { return len(s.byID) }

func (s *EdgeSet[L, T]) Unbuilt() map[string]int { return s.unbuilt }

func (s *EdgeSet[L, T]) Illegal() map[string]int { return s.illegal }

func (s *EdgeSet[L, T]) PropertyConflicts() []EdgeConflict[T] {
	out := make([]EdgeConflict[T], 0, len(s.conflicts))
	for k, n := range s.conflicts {
		out = append(out, EdgeConflict[T]{k.edgeType, k.property, n})
	}
	slices.SortFunc(out, func(a, b EdgeConflict[T]) int {
		return cmp.Or(cmp.Compare(b.Discarded, a.Discarded),
			cmp.Compare(a.Type, b.Type), cmp.Compare(a.Property, b.Property))
	})
	return out
}

func (s *EdgeSet[L, T]) Err() error {
	if len(s.illegal) == 0 {
		return nil
	}
	return fmt.Errorf("%d illegal endpoint pair(s): %v", len(s.illegal), s.illegal)
}

// ByType cannot report this: a pair with no writer hides behind a sibling pair of the
// same type, so the types with the most missing code look the healthiest.
func (s *EdgeSet[L, T]) EmptyTriples(edgeList []Edge[L, T]) []string {
	present := make(map[string]bool, len(edgeList))
	for _, e := range edgeList {
		present[EdgeKey(e.Type, e.FromLabel, e.ToLabel)] = true
	}
	out := []string{}
	for _, t := range s.schema.EdgeTypes() {
		for _, p := range s.schema.EdgeEndpoints(t) {
			if k := EdgeKey(t, p[0], p[1]); !present[k] {
				out = append(out, k)
			}
		}
	}
	return out
}

func LegalProp(v any) bool {
	switch t := v.(type) {
	case nil, bool, string, json.Number, float64:
		return true
	case []any:
		return primitiveArray(t)
	}
	return false
}

// Neo4j array properties must be homogeneous and cannot contain null.
func primitiveArray(a []any) bool {
	kind := ""
	for _, e := range a {
		k := primKind(e)
		if k == "" || (kind != "" && k != kind) {
			return false
		}
		kind = k
	}
	return true
}

func primKind(v any) string {
	switch v.(type) {
	case string:
		return "s"
	case bool:
		return "b"
	case json.Number, float64:
		return "n"
	}
	return ""
}

func unionArray(a, b []any) []any {
	out := make([]any, 0, len(a)+len(b))
	seen := make(map[string]bool, len(a)+len(b))
	for _, e := range slices.Concat(a, b) {
		k := scalarKey(e)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return lessPrimitive(out[i], out[j]) })
	return out
}

func lessPrimitive(a, b any) bool {
	na, aok := a.(json.Number)
	nb, bok := b.(json.Number)
	if aok && bok {
		fa, ea := na.Float64()
		fb, eb := nb.Float64()
		if ea == nil && eb == nil && fa != fb {
			return fa < fb
		}
	}
	return scalarKey(a) < scalarKey(b)
}

func scalarKey(v any) string {
	switch t := v.(type) {
	case nil:
		return "\x00null"
	case string:
		return "s" + t
	case bool:
		return "b" + strconv.FormatBool(t)
	case json.Number:
		return "n" + t.String()
	case float64:
		return "n" + strconv.FormatFloat(t, 'g', -1, 64)
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, scalarKey(e))
		}
		return "a[" + strings.Join(parts, ",") + "]"
	}
	return "?"
}
