package attack

import (
	"net/http"
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

// repo.create writes a DELETE to the ledger before the call that creates the
// repository. A name that already resolves must therefore be refused rather than
// adopted the way repo.fork adopts an existing fork: adopting one arms an undo
// against a repository this run did not create, and cleanup would delete it.
func TestRepoCreateRefusesAnExistingName(t *testing.T) {
	const existing = "/repos/portus-labs/platform-selftest"
	s := &Session{Execute: true}

	t.Run("the name resolves", func(t *testing.T) {
		api := &stubAPI{routes: map[string]stubReply{existing: {body: `{"name":"platform-selftest"}`}}}

		err := repoNameIsFree(t.Context(), s, api, "portus-labs", "platform-selftest")

		if err == nil {
			t.Fatal("the repository exists, so the create must be refused before an inverse is recorded")
		}
		if !strings.Contains(err.Error(), "delete") {
			t.Errorf("the refusal must say why adoption is unsafe, got %v", err)
		}
	})

	t.Run("the name is free", func(t *testing.T) {
		// Absent from the table, so it answers 404 the way /repos does for a name
		// nobody has taken.
		if err := repoNameIsFree(t.Context(), s, &stubAPI{}, "portus-labs", "platform-selftest"); err != nil {
			t.Fatalf("the name resolves to nothing, so there is nothing to refuse: %v", err)
		}
	})

	// An unreadable name is not a free one. Proceeding would record a DELETE against
	// a repository this run cannot say it created, which is the one mistake here with
	// no way back — so under --execute the read failing is the step failing.
	t.Run("the name is unreadable", func(t *testing.T) {
		api := &stubAPI{routes: map[string]stubReply{existing: {status: http.StatusForbidden, body: `{}`}}}

		if err := repoNameIsFree(t.Context(), s, api, "portus-labs", "platform-selftest"); err == nil {
			t.Fatal("the read was refused, so whether the repository exists is unestablished and the create must not proceed")
		}
	})
}

// The organization setting is visible to owners, and a member reading its own
// organization gets a profile without the field. An absent field must therefore
// leave the call to decide, not stand in for a negative: refusing here would report
// a permission as denied on the strength of a read that never measured it.
func TestOrgPrivateRepoGateSeparatesAbsentFromFalse(t *testing.T) {
	const org = "/orgs/portus-labs"

	cases := []struct {
		name   string
		reply  stubReply
		refuse bool
	}{
		{"the visibility setting is off", stubReply{body: `{"members_can_create_repositories":true,"members_can_create_private_repositories":false}`}, true},
		// The org-wide switch off makes the visibility switch irrelevant, and GitHub
		// keeps reporting the latter as true — so reading only the narrower field would
		// pass the guard on a configuration that refuses the call.
		{"the org-wide switch is off", stubReply{body: `{"members_can_create_repositories":false,"members_can_create_private_repositories":true}`}, true},
		{"both are on", stubReply{body: `{"members_can_create_repositories":true,"members_can_create_private_repositories":true}`}, false},
		{"the fields are absent", stubReply{body: `{"login":"portus-labs"}`}, false},
		{"the organization is unreadable", stubReply{status: http.StatusNotFound, body: `{}`}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Session{Execute: true}
			api := &stubAPI{routes: map[string]stubReply{org: tc.reply}}

			err := orgAllowsPrivateRepos(t.Context(), s, api, "portus-labs")

			if tc.refuse && err == nil {
				t.Fatal("the setting was read as off, so the call must be refused locally rather than spent on a 403")
			}
			if !tc.refuse && err != nil {
				t.Fatalf("nothing established that the creation is forbidden: %v", err)
			}
		})
	}
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
