package graph

import (
	"fmt"
	"strings"
)

type TargetKind string

const (
	TargetNode   TargetKind = "node"
	TargetEdge   TargetKind = "edge"
	TargetAttack TargetKind = "attack"
)

// Target is where a rule lands in the graph. Findings are never nodes: a rule is
// either a property on the node or edge it names, or an attack edge in its own
// right. Attack targets resolve their endpoints from the schema, so every kind
// carries enough to write the graph without re-consulting the rule text.
type Target struct {
	Kind  TargetKind
	Label NodeLabel
	Type  EdgeType
	From  NodeLabel
	To    NodeLabel
}

const targetForms = "node(<Label>), edge(<TYPE>, <From>, <To>) or attack(<TYPE>)"

func ParseTarget(s string) (Target, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Target{}, fmt.Errorf("missing graph target: want %s", targetForms)
	}
	open := strings.IndexByte(s, '(')
	if open < 0 || !strings.HasSuffix(s, ")") {
		return Target{}, fmt.Errorf("malformed graph target %q: want %s", s, targetForms)
	}
	kind := TargetKind(strings.TrimSpace(s[:open]))
	args := strings.Split(s[open+1:len(s)-1], ",")
	for i, a := range args {
		args[i] = strings.TrimSpace(a)
	}

	switch kind {
	case TargetNode:
		if len(args) != 1 {
			return Target{}, fmt.Errorf("node target %q takes 1 label, got %d", s, len(args))
		}
		label := NodeLabel(args[0])
		if !ValidNodeLabel(label) {
			return Target{}, fmt.Errorf("unknown node label %q in %q", args[0], s)
		}
		return Target{Kind: TargetNode, Label: label}, nil

	case TargetEdge:
		if len(args) != 3 {
			return Target{}, fmt.Errorf("edge target %q takes <TYPE>, <From>, <To>, got %d arg(s)", s, len(args))
		}
		et, from, to := EdgeType(args[0]), NodeLabel(args[1]), NodeLabel(args[2])
		if !ValidEdgeType(et) {
			return Target{}, fmt.Errorf("unknown edge type %q in %q", args[0], s)
		}
		if !ValidNodeLabel(from) {
			return Target{}, fmt.Errorf("unknown node label %q in %q", args[1], s)
		}
		if !ValidNodeLabel(to) {
			return Target{}, fmt.Errorf("unknown node label %q in %q", args[2], s)
		}
		if !ValidEdge(et, from, to) {
			return Target{}, fmt.Errorf("%s does not connect %s -> %s: allowed %s", et, from, to, formatEndpoints(et))
		}
		return Target{Kind: TargetEdge, Type: et, From: from, To: to}, nil

	case TargetAttack:
		if len(args) != 1 {
			return Target{}, fmt.Errorf("attack target %q takes 1 edge type, got %d", s, len(args))
		}
		et := EdgeType(args[0])
		eps := edgeEndpoints[et]
		if len(eps) == 0 {
			return Target{}, fmt.Errorf("unknown edge type %q in %q", args[0], s)
		}
		if len(eps) > 1 {
			return Target{}, fmt.Errorf("%s has %d endpoint pairs (%s), so it needs the explicit edge(...) form", et, len(eps), formatEndpoints(et))
		}
		return Target{Kind: TargetAttack, Type: et, From: eps[0][0], To: eps[0][1]}, nil
	}
	return Target{}, fmt.Errorf("unknown graph target form %q in %q: want %s", kind, s, targetForms)
}

func formatEndpoints(t EdgeType) string {
	pairs := make([]string, 0, len(edgeEndpoints[t]))
	for _, ep := range edgeEndpoints[t] {
		pairs = append(pairs, fmt.Sprintf("%s -> %s", ep[0], ep[1]))
	}
	return strings.Join(pairs, ", ")
}
