package graph

import (
	"context"

	"github.com/praetorian-inc/trajan/pkg/finding"
)

type Schema[L ~string, T ~string] interface {
	NodeLabels() []L
	EdgeTypes() []T
	IdentityKey(L) []string
	ValidNodeLabel(L) bool
	ValidEdgeType(T) bool
	ValidEdge(T, L, L) bool
	EdgeEndpoints(T) [][2]L
	NodeSlug(L) string
	EdgeSlug(T) string
	Identifies(string) bool
}

type Provider[L ~string, T ~string] interface {
	Schema[L, T]

	Name() string
	RuleSubtree() string
	Grammar() Grammar

	SkipRecords() []string
	Gaps() []GapEntry
	Hierarchy(org string, n Node[L]) []string

	Open(c *Corpus) (Session[L, T], error)
}

type Session[L ~string, T ~string] interface {
	Org() string
	Nodes(ctx context.Context) (*NodeSet[L, T], error)
	Edges(ctx context.Context) (*EdgeSet[L, T], error)
	Attach(ctx context.Context, targets map[string]Target, findings []finding.Finding) (*AttachResult, error)
}
