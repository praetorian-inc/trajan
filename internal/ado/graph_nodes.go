package ado

import (
	"strings"

	"github.com/praetorian-inc/trajan/internal/graph"
)

type nodeSet = graph.NodeSet[NodeLabel, EdgeType]
type edgeSet = graph.EdgeSet[NodeLabel, EdgeType]
type node = graph.Node[NodeLabel]
type findingRef = graph.FindingRef
type endpoint = graph.Endpoint[NodeLabel]

func newNodeSet() *nodeSet {
	return graph.NewNodeSet[NodeLabel, EdgeType](adoSchema{}, graph.SetOptions[NodeLabel]{
		SkipProps: []string{"kind"},
	})
}

func newEdgeSet() *edgeSet { return graph.NewEdgeSet[NodeLabel, EdgeType](adoSchema{}) }

// ADO has three expression syntaxes and a node named $(rolearn) or ${{ parameters.env }}
// is a template, not an entity.
func identifies(v string) bool {
	return v != "" && !strings.Contains(v, "$(") && !strings.Contains(v, "${{") && !strings.Contains(v, "$[")
}
