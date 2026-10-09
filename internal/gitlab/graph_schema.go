package gitlab

import (
	"maps"
	"slices"
)

type NodeLabel string

const (
	LabelInstance     NodeLabel = "Instance"
	LabelGroup        NodeLabel = "Group"
	LabelProject      NodeLabel = "Project"
	LabelJob          NodeLabel = "Job"
	LabelMergeRequest NodeLabel = "MergeRequest"
	LabelEnvironment  NodeLabel = "Environment"
	LabelRunner       NodeLabel = "Runner"
	LabelAgent        NodeLabel = "Agent"
	LabelCredential   NodeLabel = "Credential"
	LabelIntegration  NodeLabel = "Integration"
)

type EdgeType string

const Contains EdgeType = "CONTAINS"

// GitLab has no graph vocabulary: one node per normalized record, keyed by its _id.
var identityKeys = map[NodeLabel][]string{
	LabelInstance:     {"_id"},
	LabelGroup:        {"_id"},
	LabelProject:      {"_id"},
	LabelJob:          {"_id"},
	LabelMergeRequest: {"_id"},
	LabelEnvironment:  {"_id"},
	LabelRunner:       {"_id"},
	LabelAgent:        {"_id"},
	LabelCredential:   {"_id"},
	LabelIntegration:  {"_id"},
}

var edgeEndpoints = map[EdgeType][][2]NodeLabel{
	Contains: {
		{LabelInstance, LabelGroup},
		{LabelInstance, LabelProject},
		{LabelInstance, LabelRunner},
		{LabelGroup, LabelGroup},
		{LabelGroup, LabelProject},
		{LabelGroup, LabelRunner},
		{LabelProject, LabelAgent},
		{LabelProject, LabelCredential},
		{LabelProject, LabelEnvironment},
		{LabelProject, LabelIntegration},
		{LabelProject, LabelJob},
		{LabelProject, LabelMergeRequest},
		{LabelProject, LabelRunner},
	},
}

var nodeSlugs = map[NodeLabel]string{
	LabelInstance:     "instance",
	LabelGroup:        "group",
	LabelProject:      "project",
	LabelJob:          "job",
	LabelMergeRequest: "merge_request",
	LabelEnvironment:  "environment",
	LabelRunner:       "runner",
	LabelAgent:        "agent",
	LabelCredential:   "credential",
	LabelIntegration:  "integration",
}

func ValidNodeLabel(l NodeLabel) bool { _, ok := identityKeys[l]; return ok }

func ValidEdgeType(t EdgeType) bool { _, ok := edgeEndpoints[t]; return ok }

func ValidEdge(t EdgeType, from, to NodeLabel) bool {
	return slices.Contains(edgeEndpoints[t], [2]NodeLabel{from, to})
}

func NodeLabels() []NodeLabel { return slices.Sorted(maps.Keys(identityKeys)) }

func EdgeTypes() []EdgeType { return slices.Sorted(maps.Keys(edgeEndpoints)) }

func IdentityKey(l NodeLabel) []string { return identityKeys[l] }

type glSchema struct{}

func (glSchema) NodeLabels() []NodeLabel                 { return NodeLabels() }
func (glSchema) EdgeTypes() []EdgeType                   { return EdgeTypes() }
func (glSchema) IdentityKey(l NodeLabel) []string        { return IdentityKey(l) }
func (glSchema) ValidNodeLabel(l NodeLabel) bool         { return ValidNodeLabel(l) }
func (glSchema) ValidEdgeType(t EdgeType) bool           { return ValidEdgeType(t) }
func (glSchema) NodeSlug(l NodeLabel) string             { return nodeSlugs[l] }
func (glSchema) EdgeSlug(EdgeType) string                { return "contains" }
func (glSchema) Identifies(v string) bool                { return v != "" }
func (glSchema) EdgeEndpoints(t EdgeType) [][2]NodeLabel { return edgeEndpoints[t] }

func (glSchema) ValidEdge(t EdgeType, from, to NodeLabel) bool { return ValidEdge(t, from, to) }
