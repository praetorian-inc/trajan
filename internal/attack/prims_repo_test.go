package attack

import (
	"slices"
	"strings"
	"testing"
)

const (
	forkRepoPath = "/repos/range-attacker/fr-11-07-stale-approval"
	forkRefPath  = "/repos/range-attacker/fr-11-07-stale-approval/git/ref/heads/main"
)

// Forking is asynchronous and the lag GitHub documents is on the git objects, not
// on the repository record: "You may have to wait a short period of time before you
// can access the git objects." A poll that stops at the first 200 from /repos hands
// ref.create or commit.code a repository whose default branch does not resolve yet,
// which is an intermittent failure at the head of every fork chain.
func TestAwaitForkWaitsForTheRefAndNotTheRepositoryRecord(t *testing.T) {
	t.Run("the record exists but the ref does not", func(t *testing.T) {
		api := &stubAPI{routes: map[string]stubReply{
			forkRepoPath: {body: `{"name":"fr-11-07-stale-approval","default_branch":"main"}`},
			// Absent from the table, so it answers 404 the way the singular ref endpoint
			// does until the object exists.
		}}

		_, err := awaitFork(t.Context(), api, "range-attacker", "fr-11-07-stale-approval", "1ns")

		if err == nil {
			t.Fatal("the fork has no refs yet, so awaitFork must not report it usable")
		}
		if !strings.Contains(err.Error(), "refs/heads/main") {
			t.Errorf("the failure must name the signal it waited on, got %v", err)
		}
		if !api.sawPath(forkRefPath) {
			t.Errorf("the ref was never read, so only the repository record was polled; asked %v", api.asked)
		}
	})

	t.Run("the ref resolves", func(t *testing.T) {
		api := &stubAPI{routes: map[string]stubReply{
			forkRepoPath: {body: `{"name":"fr-11-07-stale-approval","default_branch":"main"}`},
			forkRefPath:  {body: `{"ref":"refs/heads/main","object":{"sha":"7fd1a60b01f91b314f59955a4e4d4e80d8edf11d","type":"commit"}}`},
		}}

		body, err := awaitFork(t.Context(), api, "range-attacker", "fr-11-07-stale-approval", "1s")

		if err != nil {
			t.Fatalf("the record and the ref are both readable: %v", err)
		}
		if body.DefaultBranch != "main" {
			t.Errorf("default branch = %q, want main", body.DefaultBranch)
		}
	})

	t.Run("a ref that exists with no object sha is the same not-yet as a 404", func(t *testing.T) {
		api := &stubAPI{routes: map[string]stubReply{
			forkRepoPath: {body: `{"name":"fr-11-07-stale-approval","default_branch":"main"}`},
			forkRefPath:  {body: `{"ref":"refs/heads/main","object":{}}`},
		}}

		if _, err := awaitFork(t.Context(), api, "range-attacker", "fr-11-07-stale-approval", "1ns"); err == nil {
			t.Fatal("a ref carrying no sha resolves to nothing, so the fork is not usable yet")
		}
	})

	// A fork of a repository with no commits never grows a ref, so waiting on one
	// would spend the whole timeout on a fork that is as ready as it will ever be.
	t.Run("an upstream with no commits", func(t *testing.T) {
		api := &stubAPI{routes: map[string]stubReply{
			forkRepoPath: {body: `{"name":"fr-11-07-stale-approval","default_branch":""}`},
		}}

		if _, err := awaitFork(t.Context(), api, "range-attacker", "fr-11-07-stale-approval", "1s"); err != nil {
			t.Fatalf("a fork with no default branch has no ref to wait for: %v", err)
		}
		if api.sawPath(forkRefPath) {
			t.Errorf("there is no ref to poll, yet the poll asked for one; asked %v", api.asked)
		}
	})
}

// POST /repos/{owner}/{repo}/forks needs "Administration" repository permissions
// (write) — the same large grant repo.delete gates behind delete_repo. Undeclared,
// the preflight reports that the fork needs nothing, the step fails at the call
// rather than in validation, and the plan understates what the engagement
// credential must hold.
func TestRepoForkDeclaresAdministrationWrite(t *testing.T) {
	spec, found := lookup("repo.fork")
	if !found {
		t.Fatal("repo.fork is not registered")
	}
	if !slices.Contains(spec.spec.Caps, CapAdministration) {
		t.Errorf("repo.fork must declare %q, declares %v", CapAdministration, spec.spec.Caps)
	}
	// Contents: read is the other half of the documented requirement, and it has no
	// place in a vocabulary that names only write grants, so the summary carries it.
	if !strings.Contains(spec.spec.Summary, "contents:read") {
		t.Errorf("the summary must state the contents:read half of the requirement, got %q", spec.spec.Summary)
	}
}
