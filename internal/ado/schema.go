package ado

import (
	"maps"
	"slices"
)

type NodeLabel string

const (
	Organization            NodeLabel = "Organization"
	Project                 NodeLabel = "Project"
	Repository              NodeLabel = "Repository"
	Branch                  NodeLabel = "Branch"
	BranchPolicy            NodeLabel = "BranchPolicy"
	Pipeline                NodeLabel = "Pipeline"
	Stage                   NodeLabel = "Stage"
	Job                     NodeLabel = "Job"
	Environment             NodeLabel = "Environment"
	ServiceConnection       NodeLabel = "ServiceConnection"
	WIFCredential           NodeLabel = "WIFCredential"
	VariableGroup           NodeLabel = "VariableGroup"
	SecretVariable          NodeLabel = "SecretVariable"
	SecureFile              NodeLabel = "SecureFile"
	KeyVault                NodeLabel = "KeyVault"
	ArtifactsFeed           NodeLabel = "ArtifactsFeed"
	OrgAgentPool            NodeLabel = "OrgAgentPool"
	ProjectAgentPool        NodeLabel = "ProjectAgentPool"
	Extension               NodeLabel = "Extension"
	PipelineDecorator       NodeLabel = "PipelineDecorator"
	ServiceHookSubscription NodeLabel = "ServiceHookSubscription"
	User                    NodeLabel = "User"
	SecurityGroup           NodeLabel = "SecurityGroup"
	BuildServiceIdentity    NodeLabel = "BuildServiceIdentity"
)

type EdgeType string

const (
	HasProject    EdgeType = "HAS_PROJECT"
	HasRepository EdgeType = "HAS_REPOSITORY"
	HasBranch     EdgeType = "HAS_BRANCH"
	HasPipeline   EdgeType = "HAS_PIPELINE"
	HasStage      EdgeType = "HAS_STAGE"
	HasJob        EdgeType = "HAS_JOB"

	DefinedBy      EdgeType = "DEFINED_BY"
	Defines        EdgeType = "DEFINES"
	HasPolicy      EdgeType = "HAS_POLICY"
	HasRole        EdgeType = "HAS_ROLE"
	MemberOf       EdgeType = "MEMBER_OF"
	ReferencesPool EdgeType = "REFERENCES_POOL"
	Installs       EdgeType = "INSTALLS"
	LinksTo        EdgeType = "LINKS_TO"
	FederatesTo    EdgeType = "FEDERATES_TO"

	Reads                EdgeType = "READS"
	ConsumesGroup        EdgeType = "CONSUMES_GROUP"
	UsesConnection       EdgeType = "USES_CONNECTION"
	RunsOn               EdgeType = "RUNS_ON"
	RunsAs               EdgeType = "RUNS_AS"
	Targets              EdgeType = "TARGETS"
	BuildValidates       EdgeType = "BUILD_VALIDATES"
	TriggersOnCompletion EdgeType = "TRIGGERS_ON_COMPLETION"

	CanPushTo     EdgeType = "CAN_PUSH_TO"
	CanMergeViaPR EdgeType = "CAN_MERGE_VIA_PR"
	CanBypass     EdgeType = "CAN_BYPASS"

	PipelinePoisoning       EdgeType = "PIPELINE_POISONING"
	QueueTimeInjection      EdgeType = "QUEUE_TIME_INJECTION"
	LoggingCommandInjection EdgeType = "LOGGING_COMMAND_INJECTION"
	AgentInjection          EdgeType = "AGENT_INJECTION"
)

var identityKeys = map[NodeLabel][]string{
	Organization:            {"org"},
	Project:                 {"org", "project"},
	Repository:              {"org", "project", "repo"},
	Branch:                  {"org", "project", "repo", "name"},
	BranchPolicy:            {"org", "project", "config_id"},
	Pipeline:                {"org", "project", "pipeline_id"},
	Stage:                   {"org", "project", "pipeline_id", "stage"},
	Job:                     {"org", "project", "pipeline_id", "stage", "job"},
	Environment:             {"org", "project", "name"},
	ServiceConnection:       {"org", "owner_project", "connection_id"},
	WIFCredential:           {"org", "owner_project", "connection_id", "subject"},
	VariableGroup:           {"org", "owner_project", "group_id"},
	SecretVariable:          {"org", "owner_project", "group_id", "name"},
	SecureFile:              {"org", "project", "file_id"},
	KeyVault:                {"name"},
	ArtifactsFeed:           {"org", "scope", "feed_id"},
	OrgAgentPool:            {"org", "pool_id"},
	ProjectAgentPool:        {"org", "project", "queue_id"},
	Extension:               {"org", "extension_id"},
	PipelineDecorator:       {"org", "extension_id"},
	ServiceHookSubscription: {"org", "subscription_id"},
	User:                    {"descriptor"},
	SecurityGroup:           {"descriptor"},
	BuildServiceIdentity:    {"descriptor"},
}

var edgeEndpoints = map[EdgeType][][2]NodeLabel{
	HasProject:    {{Organization, Project}},
	HasRepository: {{Project, Repository}},
	HasBranch:     {{Repository, Branch}},
	HasPipeline:   {{Project, Pipeline}},
	HasStage:      {{Pipeline, Stage}},
	HasJob:        {{Stage, Job}},

	DefinedBy: {{Pipeline, Branch}},
	Defines:   {{VariableGroup, SecretVariable}},
	HasPolicy: {{BranchPolicy, Branch}},
	HasRole: {
		{User, Project},
		{User, Repository},
		{User, Pipeline},
		{User, ServiceConnection},
		{SecurityGroup, Project},
		{SecurityGroup, Repository},
		{SecurityGroup, Pipeline},
		{SecurityGroup, ServiceConnection},
		{BuildServiceIdentity, Project},
		{BuildServiceIdentity, Repository},
		{BuildServiceIdentity, Pipeline},
		{BuildServiceIdentity, ServiceConnection},
	},
	MemberOf: {
		{User, SecurityGroup},
		{SecurityGroup, SecurityGroup},
		{BuildServiceIdentity, SecurityGroup},
	},
	ReferencesPool: {{ProjectAgentPool, OrgAgentPool}},
	Installs:       {{Extension, PipelineDecorator}},
	LinksTo:        {{VariableGroup, KeyVault}},
	FederatesTo:    {{ServiceConnection, WIFCredential}},

	Reads:                {{Job, SecretVariable}},
	ConsumesGroup:        {{Pipeline, VariableGroup}, {Stage, VariableGroup}, {Job, VariableGroup}},
	UsesConnection:       {{Job, ServiceConnection}},
	RunsOn:               {{Job, ProjectAgentPool}},
	RunsAs:               {{Pipeline, BuildServiceIdentity}},
	Targets:              {{Job, Environment}},
	BuildValidates:       {{BranchPolicy, Pipeline}},
	TriggersOnCompletion: {{Pipeline, Pipeline}},

	CanPushTo:     {{User, Branch}, {SecurityGroup, Branch}, {BuildServiceIdentity, Branch}},
	CanMergeViaPR: {{User, Branch}, {SecurityGroup, Branch}, {BuildServiceIdentity, Branch}},
	CanBypass:     {{User, BranchPolicy}, {SecurityGroup, BranchPolicy}, {BuildServiceIdentity, BranchPolicy}},

	PipelinePoisoning:       {{User, Job}, {SecurityGroup, Job}, {BuildServiceIdentity, Job}},
	QueueTimeInjection:      {{User, Job}, {SecurityGroup, Job}, {BuildServiceIdentity, Job}},
	LoggingCommandInjection: {{User, Job}, {SecurityGroup, Job}, {BuildServiceIdentity, Job}},
	AgentInjection:          {{User, Job}, {SecurityGroup, Job}, {BuildServiceIdentity, Job}},
}

var severityBuckets = map[string]string{
	"critical": "findings_critical",
	"high":     "findings_high",
	"medium":   "findings_medium",
	"low":      "findings_low",
}

var findingBuckets = []string{"findings_critical", "findings_high", "findings_medium", "findings_low"}

func ValidNodeLabel(l NodeLabel) bool { _, ok := identityKeys[l]; return ok }

func ValidEdgeType(t EdgeType) bool { _, ok := edgeEndpoints[t]; return ok }

func ValidEdge(t EdgeType, from, to NodeLabel) bool {
	return slices.Contains(edgeEndpoints[t], [2]NodeLabel{from, to})
}

func NodeLabels() []NodeLabel { return slices.Sorted(maps.Keys(identityKeys)) }

func EdgeTypes() []EdgeType { return slices.Sorted(maps.Keys(edgeEndpoints)) }

func IdentityKey(l NodeLabel) []string { return identityKeys[l] }
