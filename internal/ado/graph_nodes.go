package ado

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

type findingRef struct {
	RuleID      string `json:"rule_id"`
	Fingerprint string `json:"fingerprint"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Target      string `json:"target"`
	SubjectKind string `json:"subject_kind"`
	SubjectID   string `json:"subject_id"`
	Title       string `json:"title"`
}

type node struct {
	ID         string            `json:"id"`
	Labels     []NodeLabel       `json:"labels"`
	Key        map[string]string `json:"key"`
	Properties map[string]any    `json:"properties"`
	Findings   []findingRef      `json:"findings"`
}

type edge struct {
	ID         string         `json:"id"`
	Type       EdgeType       `json:"type"`
	From       string         `json:"from"`
	To         string         `json:"to"`
	FromLabel  NodeLabel      `json:"from_label"`
	ToLabel    NodeLabel      `json:"to_label"`
	Properties map[string]any `json:"properties"`
	Findings   []findingRef   `json:"findings"`
}

type identityMerge struct {
	Label         NodeLabel `json:"label"`
	SourceRecords int       `json:"source_records"`
	Nodes         int       `json:"nodes"`
	MergedRecords int       `json:"merged_records"`
}

type propertyConflict struct {
	Label     NodeLabel `json:"label"`
	Property  string    `json:"property"`
	Discarded int       `json:"discarded"`
}

type edgeConflict struct {
	Type      EdgeType `json:"type"`
	Property  string   `json:"property"`
	Discarded int      `json:"discarded"`
}

func esc(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "|", `\|`)
}

func nodeID(l NodeLabel, key map[string]string) string {
	parts := []string{string(l)}
	for _, k := range IdentityKey(l) {
		parts = append(parts, esc(key[k]))
	}
	return strings.Join(parts, "|")
}

func (e endpoint) id() string { return nodeID(e.Label, e.Key) }

func edgeID(t EdgeType, from, to string) string {
	return fmt.Sprintf("%s|%s|%s", t, esc(from), esc(to))
}

func edgeKey(t EdgeType, from, to NodeLabel) string {
	return fmt.Sprintf("%s{%s,%s}", t, from, to)
}

// ADO has three expression syntaxes and a node named $(rolearn) or ${{ parameters.env }}
// is a template, not an entity.
func identifies(v string) bool {
	return v != "" && !strings.Contains(v, "$(") && !strings.Contains(v, "${{") && !strings.Contains(v, "$[")
}

type conflictKey struct {
	label    NodeLabel
	property string
}

type nodeSet struct {
	byID       map[string]*node
	subjects   map[string]map[string]string
	sourceRecs map[NodeLabel]int
	incomplete map[NodeLabel]int
	conflicts  map[conflictKey]int
	illegal    map[conflictKey]bool
	dropped    int
}

func newNodeSet() *nodeSet {
	return &nodeSet{
		byID:       map[string]*node{},
		subjects:   map[string]map[string]string{},
		sourceRecs: map[NodeLabel]int{},
		incomplete: map[NodeLabel]int{},
		conflicts:  map[conflictKey]int{},
		illegal:    map[conflictKey]bool{},
	}
}

func (s *nodeSet) upsert(l NodeLabel, key map[string]string, props map[string]any, source string) *node {
	ident := IdentityKey(l)
	if len(ident) == 0 {
		return nil
	}
	k := make(map[string]string, len(ident))
	for _, name := range ident {
		v := key[name]
		if !identifies(v) {
			s.incomplete[l]++
			return nil
		}
		k[name] = v
	}
	id := nodeID(l, k)
	s.sourceRecs[l]++

	n := s.byID[id]
	if n == nil {
		n = &node{ID: id, Labels: []NodeLabel{l}, Key: k, Properties: map[string]any{}, Findings: []findingRef{}}
		s.byID[id] = n
	}
	s.merge(n, props)
	if source != "" {
		s.merge(n, map[string]any{"_source": []any{source}})
	}
	n.Properties["graph_id"] = id
	return n
}

func (s *nodeSet) merge(n *node, props map[string]any) {
	for _, k := range slices.Sorted(maps.Keys(props)) {
		v := props[k]
		old, seen := n.Properties[k]
		if !seen {
			n.Properties[k] = v
			continue
		}
		ao, aok := old.([]any)
		an, nok := v.([]any)
		if aok && nok {
			n.Properties[k] = unionArray(ao, an)
			continue
		}
		if scalarKey(old) != scalarKey(v) {
			s.conflicts[conflictKey{n.Labels[0], k}]++
		}
	}
}

func (s *nodeSet) index(kind, recordID string, n *node) {
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

func (s *nodeSet) subject(kind, recordID string) (string, bool) {
	id, ok := s.subjects[kind][recordID]
	return id, ok
}

func (s *nodeSet) has(id string) bool { _, ok := s.byID[id]; return ok }

func (s *nodeSet) all() []node {
	out := make([]node, 0, len(s.byID))
	for _, n := range s.byID {
		out = append(out, *n)
	}
	slices.SortFunc(out, func(a, b node) int {
		return cmp.Or(cmp.Compare(a.Labels[0], b.Labels[0]), cmp.Compare(a.ID, b.ID))
	})
	return out
}

func (s *nodeSet) byLabel() map[NodeLabel]int {
	out := make(map[NodeLabel]int, len(identityKeys))
	for _, l := range NodeLabels() {
		out[l] = 0
	}
	for _, n := range s.byID {
		out[n.Labels[0]]++
	}
	return out
}

func (s *nodeSet) merges() []identityMerge {
	counts := s.byLabel()
	out := []identityMerge{}
	for _, l := range NodeLabels() {
		src := s.sourceRecs[l]
		if src == 0 || src == counts[l] {
			continue
		}
		out = append(out, identityMerge{l, src, counts[l], src - counts[l]})
	}
	return out
}

func (s *nodeSet) propertyConflicts() []propertyConflict {
	out := make([]propertyConflict, 0, len(s.conflicts))
	for k, n := range s.conflicts {
		out = append(out, propertyConflict{k.label, k.property, n})
	}
	slices.SortFunc(out, func(a, b propertyConflict) int {
		return cmp.Or(cmp.Compare(b.Discarded, a.Discarded),
			cmp.Compare(a.Label, b.Label), cmp.Compare(a.Property, b.Property))
	})
	return out
}

func (s *nodeSet) incompleteIdentities() map[NodeLabel]int { return maps.Clone(s.incomplete) }

func (s *nodeSet) recordProps(l NodeLabel, fields map[string]any) map[string]any {
	ident := IdentityKey(l)
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		if k == "_id" || k == "kind" || k == "_provenance" || slices.Contains(ident, k) {
			continue
		}
		if !legalProp(v) {
			s.illegal[conflictKey{l, k}] = true
			continue
		}
		out[k] = v
	}
	return out
}

func (s *nodeSet) sweepIllegal() {
	for _, n := range s.byID {
		for k := range n.Properties {
			if s.illegal[conflictKey{n.Labels[0], k}] {
				delete(n.Properties, k)
				s.dropped++
			}
		}
	}
}

type edgeConflictKey struct {
	edgeType EdgeType
	property string
}

type edgeSet struct {
	byID      map[string]*edge
	unbuilt   map[string]int
	conflicts map[edgeConflictKey]int
	illegal   map[string]int
}

func newEdgeSet() *edgeSet {
	return &edgeSet{byID: map[string]*edge{}, unbuilt: map[string]int{},
		conflicts: map[edgeConflictKey]int{}, illegal: map[string]int{}}
}

func (s *edgeSet) add(t EdgeType, from, to endpoint, props map[string]any) {
	if !complete(from) || !complete(to) {
		s.unbuilt[edgeKey(t, from.Label, to.Label)]++
		return
	}
	if !ValidEdge(t, from.Label, to.Label) {
		s.illegal[edgeKey(t, from.Label, to.Label)]++
		return
	}
	id := edgeID(t, from.id(), to.id())
	e := s.byID[id]
	if e == nil {
		e = &edge{
			ID: id, Type: t, From: from.id(), To: to.id(),
			FromLabel: from.Label, ToLabel: to.Label,
			Properties: map[string]any{}, Findings: []findingRef{},
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
			s.conflicts[edgeConflictKey{t, k}]++
		}
	}
	e.Properties["graph_id"] = id
}

func (s *edgeSet) miss(t EdgeType, from, to NodeLabel, n int) { s.unbuilt[edgeKey(t, from, to)] += n }

func (s *edgeSet) all() []edge {
	out := make([]edge, 0, len(s.byID))
	for _, e := range s.byID {
		out = append(out, *e)
	}
	slices.SortFunc(out, func(a, b edge) int {
		return cmp.Or(cmp.Compare(a.Type, b.Type), cmp.Compare(a.From, b.From), cmp.Compare(a.To, b.To))
	})
	return out
}

func (s *edgeSet) byType() map[EdgeType]int {
	out := make(map[EdgeType]int, len(edgeEndpoints))
	for _, t := range EdgeTypes() {
		out[t] = 0
	}
	for _, e := range s.byID {
		out[e.Type]++
	}
	return out
}

func (s *edgeSet) propertyConflicts() []edgeConflict {
	out := make([]edgeConflict, 0, len(s.conflicts))
	for k, n := range s.conflicts {
		out = append(out, edgeConflict{k.edgeType, k.property, n})
	}
	slices.SortFunc(out, func(a, b edgeConflict) int {
		return cmp.Or(cmp.Compare(b.Discarded, a.Discarded),
			cmp.Compare(a.Type, b.Type), cmp.Compare(a.Property, b.Property))
	})
	return out
}

func (s *edgeSet) err() error {
	if len(s.illegal) == 0 {
		return nil
	}
	return fmt.Errorf("%d illegal endpoint pair(s): %v", len(s.illegal), s.illegal)
}

func emptyEdgeTriples(edgeList []edge) []string {
	present := make(map[string]bool, len(edgeList))
	for _, e := range edgeList {
		present[edgeKey(e.Type, e.FromLabel, e.ToLabel)] = true
	}
	out := []string{}
	for _, t := range EdgeTypes() {
		for _, p := range edgeEndpoints[t] {
			if k := edgeKey(t, p[0], p[1]); !present[k] {
				out = append(out, k)
			}
		}
	}
	return out
}

func legalProp(v any) bool {
	switch t := v.(type) {
	case nil, bool, string, json.Number, float64:
		return true
	case []any:
		return primitiveArray(t)
	}
	return false
}

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
