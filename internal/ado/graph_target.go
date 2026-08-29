package ado

import (
	"fmt"
	"strings"
)

type TargetKind string

const (
	TargetNode TargetKind = "node"
	TargetEdge TargetKind = "edge"
)

// An edge target names only its type: an ADO attack edge starts at whichever
// principal the record resolved to, so no single From/To pair describes it.
type Target struct {
	Kind  TargetKind
	Label NodeLabel
	Type  EdgeType
}

const targetForms = "node(<Label>) or edge(<TYPE>)"

func ParseTarget(s string) (Target, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Target{}, fmt.Errorf("missing graph target: want %s", targetForms)
	}
	open := strings.IndexByte(s, '(')
	if open < 0 || !strings.HasSuffix(s, ")") {
		return Target{}, fmt.Errorf("malformed graph target %q: want %s", s, targetForms)
	}
	arg := strings.TrimSpace(s[open+1 : len(s)-1])
	switch TargetKind(strings.TrimSpace(s[:open])) {
	case TargetNode:
		if l := NodeLabel(arg); ValidNodeLabel(l) {
			return Target{Kind: TargetNode, Label: l}, nil
		}
		return Target{}, fmt.Errorf("unknown node label %q in %q", arg, s)
	case TargetEdge:
		if t := EdgeType(arg); ValidEdgeType(t) {
			return Target{Kind: TargetEdge, Type: t}, nil
		}
		return Target{}, fmt.Errorf("unknown edge type %q in %q", arg, s)
	}
	return Target{}, fmt.Errorf("unknown graph target form in %q: want %s", s, targetForms)
}

func renderTarget(t Target) string {
	switch t.Kind {
	case TargetNode:
		return fmt.Sprintf("node(%s)", t.Label)
	case TargetEdge:
		return fmt.Sprintf("edge(%s)", t.Type)
	}
	return ""
}
