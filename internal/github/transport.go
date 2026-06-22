package github

import "errors"

// errUnservable means a transport cannot serve a surface (git clone/command
// failure or unhandled path; any graphql error). The router falls through to the
// next capable transport without retrying. Distinct from a definitive
// GhError{404/403}, which collectors soft-degrade on.
var errUnservable = errors.New("github transport cannot serve surface")

type transportKind string

const (
	transportGit     transportKind = "git"
	transportGraphQL transportKind = "graphql"
	transportREST    transportKind = "rest"
)

// preferenceOrder is the global affinity ranking git > graphql > rest (D2.3).
var preferenceOrder = []transportKind{transportGit, transportGraphQL, transportREST}

type transport interface {
	GitHub
	kind() transportKind
}

// restTransport is the floor: it serves every surface, so it always terminates
// router fall-through.
type restTransport struct{ *Client }

func (restTransport) kind() transportKind { return transportREST }

var _ transport = restTransport{}

type surface string

const (
	surfaceWorkflowFiles surface = "workflow_files"
	surfaceLocalActions  surface = "local_actions"
	surfaceBranchRefs    surface = "branch_refs"
	surfaceRefResolve    surface = "ref_resolve"
	surfaceRepoMeta      surface = "repo_meta"
	surfaceRepoTopics    surface = "repo_topics"
	surfaceOrgMembers    surface = "org_members"
	// surfaceRESTFloor is the rest-only tail (org object, teams, branch
	// protection, rulesets, environments, secrets, variables, runners, webhooks,
	// app enum): graphql cannot reproduce these shapes, so they are never offloaded.
	surfaceRESTFloor surface = "rest_floor"
)

// capabilityMatrix lists the transports that may serve each surface; the router
// intersects it with registered transports and orders by preferenceOrder. graphql
// appears only where its mapper reproduces the REST data shape field-for-field, so
// on-disk data stays byte-identical to direct REST.
var capabilityMatrix = map[surface][]transportKind{
	surfaceWorkflowFiles: {transportGit, transportREST},
	surfaceLocalActions:  {transportGit, transportREST},
	surfaceBranchRefs:    {transportGit, transportREST},
	surfaceRefResolve:    {transportGit, transportREST},
	surfaceRepoMeta:      {transportGraphQL, transportREST},
	surfaceRepoTopics:    {transportGraphQL, transportREST},
	surfaceOrgMembers:    {transportGraphQL, transportREST},
	surfaceRESTFloor:     {transportREST},
}
