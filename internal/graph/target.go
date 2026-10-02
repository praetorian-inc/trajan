package graph

import (
	"fmt"
	"slices"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine/detect"
)

type TargetKind string

const (
	TargetNode   TargetKind = "node"
	TargetEdge   TargetKind = "edge"
	TargetAttack TargetKind = "attack"
)

// A rule lands as a property on the node or edge it names, or as an attack edge in
// its own right; findings are never nodes. From and To are optional: a provider
// whose attack edge starts at whichever principal the record resolved to has no
// single pair to name, so its grammar accepts edge(<TYPE>) alone.
type Target struct {
	Kind  TargetKind
	Label string
	Type  string
	From  string
	To    string
}

func RenderTarget(t Target) string {
	switch t.Kind {
	case TargetNode:
		return fmt.Sprintf("node(%s)", t.Label)
	case TargetEdge:
		if t.From == "" && t.To == "" {
			return fmt.Sprintf("edge(%s)", t.Type)
		}
		return fmt.Sprintf("edge(%s, %s, %s)", t.Type, t.From, t.To)
	case TargetAttack:
		return fmt.Sprintf("attack(%s)", t.Type)
	}
	return ""
}

// detect keeps rule.Graph unparsed to stay provider-generic, so the index is built
// here rather than inside Build.
func RuleTargets[L ~string, T ~string](p Provider[L, T], onError func(error)) (map[string]Target, error) {
	rules, err := detect.LoadRules(p.RuleSubtree(), onError)
	if err != nil {
		return nil, err
	}
	targets := make(map[string]Target, len(rules))
	for _, r := range rules {
		t, err := ParseTarget(p, r.Graph)
		if err != nil {
			if onError != nil {
				onError(fmt.Errorf("%s: %w", r.ID, err))
			}
			continue
		}
		targets[r.ID] = t
	}
	return targets, nil
}

type Grammar struct {
	Forms         []TargetKind
	EdgeNamesPair bool
}

func (g Grammar) accepts(k TargetKind) bool { return slices.Contains(g.Forms, k) }

func (g Grammar) String() string {
	forms := make([]string, 0, len(g.Forms))
	for _, k := range g.Forms {
		switch k {
		case TargetNode:
			forms = append(forms, "node(<Label>)")
		case TargetEdge:
			if g.EdgeNamesPair {
				forms = append(forms, "edge(<TYPE>, <From>, <To>)")
			} else {
				forms = append(forms, "edge(<TYPE>)")
			}
		case TargetAttack:
			forms = append(forms, "attack(<TYPE>)")
		}
	}
	return strings.Join(forms, " or ")
}

func ParseTarget[L ~string, T ~string](p Provider[L, T], s string) (Target, error) {
	g := p.Grammar()
	forms := g.String()
	s = strings.TrimSpace(s)
	if s == "" {
		return Target{}, fmt.Errorf("missing graph target: want %s", forms)
	}
	open := strings.IndexByte(s, '(')
	if open < 0 || !strings.HasSuffix(s, ")") {
		return Target{}, fmt.Errorf("malformed graph target %q: want %s", s, forms)
	}
	kind := TargetKind(strings.TrimSpace(s[:open]))
	if !g.accepts(kind) {
		return Target{}, fmt.Errorf("unknown graph target form %q in %q: want %s", kind, s, forms)
	}
	args := strings.Split(s[open+1:len(s)-1], ",")
	for i, a := range args {
		args[i] = strings.TrimSpace(a)
	}

	switch kind {
	case TargetNode:
		if len(args) != 1 {
			return Target{}, fmt.Errorf("node target %q takes 1 label, got %d", s, len(args))
		}
		if !p.ValidNodeLabel(L(args[0])) {
			return Target{}, fmt.Errorf("unknown node label %q in %q", args[0], s)
		}
		return Target{Kind: TargetNode, Label: args[0]}, nil

	case TargetEdge:
		if !g.EdgeNamesPair {
			if len(args) != 1 {
				return Target{}, fmt.Errorf("edge target %q takes <TYPE>, got %d arg(s)", s, len(args))
			}
			if !p.ValidEdgeType(T(args[0])) {
				return Target{}, fmt.Errorf("unknown edge type %q in %q", args[0], s)
			}
			return Target{Kind: TargetEdge, Type: args[0]}, nil
		}
		if len(args) != 3 {
			return Target{}, fmt.Errorf("edge target %q takes <TYPE>, <From>, <To>, got %d arg(s)", s, len(args))
		}
		et, from, to := T(args[0]), L(args[1]), L(args[2])
		if !p.ValidEdgeType(et) {
			return Target{}, fmt.Errorf("unknown edge type %q in %q", args[0], s)
		}
		if !p.ValidNodeLabel(from) {
			return Target{}, fmt.Errorf("unknown node label %q in %q", args[1], s)
		}
		if !p.ValidNodeLabel(to) {
			return Target{}, fmt.Errorf("unknown node label %q in %q", args[2], s)
		}
		if !p.ValidEdge(et, from, to) {
			return Target{}, fmt.Errorf("%s does not connect %s -> %s: allowed %s", et, from, to, formatEndpoints(p, et))
		}
		return Target{Kind: TargetEdge, Type: args[0], From: args[1], To: args[2]}, nil

	case TargetAttack:
		if len(args) != 1 {
			return Target{}, fmt.Errorf("attack target %q takes 1 edge type, got %d", s, len(args))
		}
		et := T(args[0])
		eps := p.EdgeEndpoints(et)
		if len(eps) == 0 {
			return Target{}, fmt.Errorf("unknown edge type %q in %q", args[0], s)
		}
		if len(eps) > 1 {
			return Target{}, fmt.Errorf("%s has %d endpoint pairs (%s), so it needs the explicit edge(...) form",
				et, len(eps), formatEndpoints(p, et))
		}
		return Target{Kind: TargetAttack, Type: args[0], From: string(eps[0][0]), To: string(eps[0][1])}, nil
	}
	return Target{}, fmt.Errorf("unknown graph target form %q in %q: want %s", kind, s, forms)
}

func formatEndpoints[L ~string, T ~string](p Provider[L, T], t T) string {
	eps := p.EdgeEndpoints(t)
	pairs := make([]string, 0, len(eps))
	for _, ep := range eps {
		pairs = append(pairs, fmt.Sprintf("%s -> %s", ep[0], ep[1]))
	}
	return strings.Join(pairs, ", ")
}
