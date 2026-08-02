package graph

import (
	"maps"
	"slices"
)

type NodeLabel string

const (
	Organization  NodeLabel = "Organization"
	Repository    NodeLabel = "Repository"
	Branch        NodeLabel = "Branch"
	Tag           NodeLabel = "Tag"
	Workflow      NodeLabel = "Workflow"
	Job           NodeLabel = "Job"
	Action        NodeLabel = "Action"
	Secret        NodeLabel = "Secret"
	Artifact      NodeLabel = "Artifact"
	Cache         NodeLabel = "Cache"
	Runner        NodeLabel = "Runner"
	RunnerGroup   NodeLabel = "RunnerGroup"
	Environment   NodeLabel = "Environment"
	Ruleset       NodeLabel = "Ruleset"
	App           NodeLabel = "App"
	User          NodeLabel = "User"
	Team          NodeLabel = "Team"
	DeployKey     NodeLabel = "DeployKey"
	CloudRole     NodeLabel = "CloudRole"
	ExternalActor NodeLabel = "ExternalActor"
)

type EdgeType string

const (
	Contains         EdgeType = "CONTAINS"
	Defines          EdgeType = "DEFINES"
	Reads            EdgeType = "READS"
	Writes           EdgeType = "WRITES"
	HasAccess        EdgeType = "HAS_ACCESS"
	CanAccess        EdgeType = "CAN_ACCESS"
	Needs            EdgeType = "NEEDS"
	PushesTo         EdgeType = "PUSHES_TO"
	RunsOn           EdgeType = "RUNS_ON"
	Targets          EdgeType = "TARGETS"
	Governs          EdgeType = "GOVERNS"
	DeployableFrom   EdgeType = "DEPLOYABLE_FROM"
	RequiresReviewBy EdgeType = "REQUIRES_REVIEW_BY"
	ProtectedBy      EdgeType = "PROTECTED_BY"
	MemberOf         EdgeType = "MEMBER_OF"
	TriggeredBy      EdgeType = "TRIGGERED_BY"
	CanBypass        EdgeType = "CAN_BYPASS"
	InstalledOn      EdgeType = "INSTALLED_ON"

	UsesAction   EdgeType = "USES_ACTION"
	Calls        EdgeType = "CALLS"
	PassesSecret EdgeType = "PASSES_SECRET"
	CanAssume    EdgeType = "CAN_ASSUME"
	Triggers     EdgeType = "TRIGGERS"
	MintsTokenAs EdgeType = "MINTS_TOKEN_AS"

	CanLandCode EdgeType = "CAN_LAND_CODE"
	CanApprove  EdgeType = "CAN_APPROVE"

	PwnRequest          EdgeType = "PWN_REQUEST"
	ExpressionInjection EdgeType = "EXPRESSION_INJECTION"
	AgentInjection      EdgeType = "AGENT_INJECTION"
)

var edgeEndpoints = map[EdgeType][][2]NodeLabel{
	Contains: {
		{Organization, Repository},
		{Organization, Team},
		{Organization, App},
		{Organization, Secret},
		{Organization, Runner},
		{Organization, RunnerGroup},
		{Organization, Ruleset},
		{Repository, Branch},
		{Repository, Tag},
		{Repository, Workflow},
		{Repository, Environment},
		{Repository, Secret},
		{Repository, Runner},
		{Repository, Ruleset},
		{Workflow, Job},
		{Environment, Secret},
		{RunnerGroup, Runner},
	},
	// The repo an Action's `owner/repo@ref` resolves to; Action identity carries
	// no structural link back to its source otherwise.
	Defines: {
		{Repository, Action},
	},
	Reads: {
		{Job, Secret},
		{Job, Cache},
		{Job, Artifact},
	},
	Writes: {
		{Job, Cache},
		{Job, Artifact},
	},
	HasAccess: {
		{User, Repository},
		{Team, Repository},
	},
	CanAccess: {
		{App, Repository},
		{RunnerGroup, Repository},
		{Repository, Secret},
	},
	Needs: {
		{Job, Job},
	},
	PushesTo: {
		{Job, Branch},
		{Job, Repository},
	},
	RunsOn: {
		{Job, Runner},
		{Job, RunnerGroup},
	},
	Targets: {
		{Job, Environment},
		{Workflow, Branch},
	},
	Governs: {
		{Ruleset, Organization},
		{Ruleset, Repository},
	},
	DeployableFrom: {
		{Environment, Branch},
		{Environment, Tag},
	},
	RequiresReviewBy: {
		{Environment, User},
		{Environment, Team},
	},
	ProtectedBy: {
		{Branch, Ruleset},
		{Tag, Ruleset},
	},
	MemberOf: {
		{User, Organization},
		{User, Team},
		{Team, Team},
	},
	TriggeredBy: {
		{Workflow, ExternalActor},
		{Workflow, User},
	},
	CanBypass: {
		{User, Ruleset},
		{Team, Ruleset},
		{App, Ruleset},
	},
	InstalledOn: {
		{DeployKey, Repository},
	},
	UsesAction: {
		{Job, Action},
	},
	Calls: {
		{Job, Workflow},
	},
	PassesSecret: {
		{Job, Workflow},
		{Job, Action},
	},
	CanAssume: {
		{Job, CloudRole},
		{Repository, CloudRole},
	},
	Triggers: {
		{Workflow, Workflow},
		{Job, Workflow},
	},
	MintsTokenAs: {
		{Job, App},
	},
	CanLandCode: {
		{User, Branch},
		{Team, Branch},
		{App, Branch},
		{DeployKey, Branch},
	},
	CanApprove: {
		{User, Branch},
		{Team, Branch},
		{User, Environment},
		{Team, Environment},
		{Job, Repository},
	},
	PwnRequest: {
		{ExternalActor, Job},
	},
	ExpressionInjection: {
		{ExternalActor, Job},
	},
	AgentInjection: {
		{ExternalActor, Job},
	},
}

var identityKeys = map[NodeLabel][]string{
	Organization: {"login"},
	Repository:   {"full_name"},
	Branch:       {"repo", "name"},
	Tag:          {"repo", "name"},
	Workflow:     {"repo", "path"},
	Job:          {"repo", "workflow", "job_id"},
	Action:       {"ref"},
	// scope is the kind ("repo"/"environment"/"org"); without scope_key naming the
	// repo or environment that owns it, every repo's NPM_TOKEN is one node and a
	// path query reports two unrelated jobs reading the same credential.
	Secret:   {"scope", "scope_key", "name"},
	Artifact: {"repo", "name"},
	// Keyed on the prefix, not the full key: every cache rule correlates on the
	// restore-keys prefix, so the prefix is the entity the graph reasons about.
	Cache:       {"key_prefix"},
	Runner:      {"scope", "id"},
	RunnerGroup: {"org", "id"},
	Environment: {"repo", "name"},
	Ruleset:     {"scope", "id"},
	App:         {"app_slug"},
	User:        {"login"},
	Team:        {"org", "slug"},
	// Repo-independent so one key reused across repos is a single node with an
	// INSTALLED_ON edge per repo.
	DeployKey: {"fingerprint"},
	CloudRole: {"identifier"},
	// A closed modelling vocabulary no API will ever return; "external" is its
	// only value, minted by the attach pass when an attack edge needs a source.
	ExternalActor: {"kind"},
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

func ValidNodeLabel(l NodeLabel) bool { _, ok := identityKeys[l]; return ok }

func ValidEdgeType(t EdgeType) bool { _, ok := edgeEndpoints[t]; return ok }

func ValidEdge(t EdgeType, from, to NodeLabel) bool {
	return slices.Contains(edgeEndpoints[t], [2]NodeLabel{from, to})
}

func NodeLabels() []NodeLabel { return slices.Sorted(maps.Keys(identityKeys)) }

func EdgeTypes() []EdgeType { return slices.Sorted(maps.Keys(edgeEndpoints)) }

func IdentityKey(l NodeLabel) []string { return identityKeys[l] }

// SeverityBucket returns "" for info and unknown severities, which have no
// bucket and are not written onto the graph.
func SeverityBucket(severity string) string { return severityBuckets[severity] }

func FindingBuckets() []string {
	return []string{FindingsCritical, FindingsHigh, FindingsMedium, FindingsLow}
}
