package ado

type adoSchema struct{}

func (adoSchema) NodeLabels() []NodeLabel                 { return NodeLabels() }
func (adoSchema) EdgeTypes() []EdgeType                   { return EdgeTypes() }
func (adoSchema) IdentityKey(l NodeLabel) []string        { return IdentityKey(l) }
func (adoSchema) ValidNodeLabel(l NodeLabel) bool         { return ValidNodeLabel(l) }
func (adoSchema) ValidEdgeType(t EdgeType) bool           { return ValidEdgeType(t) }
func (adoSchema) NodeSlug(l NodeLabel) string             { return resourceSlug(string(l)) }
func (adoSchema) EdgeSlug(t EdgeType) string              { return resourceSlug(string(t)) }
func (adoSchema) Identifies(v string) bool                { return identifies(v) }
func (adoSchema) EdgeEndpoints(t EdgeType) [][2]NodeLabel { return edgeEndpoints[t] }

func (adoSchema) ValidEdge(t EdgeType, from, to NodeLabel) bool { return ValidEdge(t, from, to) }
