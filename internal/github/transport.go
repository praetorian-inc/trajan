package github

import "errors"

// A transport cannot serve this surface, so the router falls through to the next
// capable one without retrying. Distinct from a definitive GhError{404/403}, which
// collectors soft-degrade on.
var errUnservable = errors.New("github transport cannot serve surface")

type transportKind string

const (
	transportGit     transportKind = "git"
	transportGraphQL transportKind = "graphql"
	transportREST    transportKind = "rest"
)

var preferenceOrder = []transportKind{transportGit, transportGraphQL, transportREST}

type transport interface {
	GitHub
	kind() transportKind
}

// The floor: it serves every surface, so it always terminates router fall-through.
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
	// The rest-only tail (org object, teams, branch protection, rulesets,
	// environments, secrets, variables, runners, webhooks, app enum): graphql cannot
	// reproduce these shapes, so they are never offloaded.
	surfaceRESTFloor surface = "rest_floor"
)

// The router intersects this with the registered transports and orders by
// preferenceOrder. graphql appears only where its mapper reproduces the REST data
// shape field-for-field, so on-disk data stays byte-identical to direct REST.
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
