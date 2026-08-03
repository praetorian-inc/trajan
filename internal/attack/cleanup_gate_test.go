package attack

import "testing"

// The stale-approval shape: the merge is gated on the approval surviving, and the
// pull request is closed when it did not. Both steps read the same fact, so the
// close must run in exactly the case the merge skipped — the case it was written
// for. A cleanup gate therefore reads a skipped step as its zero handle instead of
// inheriting the skip.
const staleApprovalTail = `apiVersion: trajan.attack/v1
scope: [acme/lab]
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: lab }
  - { id: writable, uses: repo.writable, repo: target }
  - { id: branch, uses: ref.create, on: writable, name: chore/dep-bump }
  - { id: pr, uses: pr.open, head: branch, base: target, title: t }
  - { id: survived, uses: pr.review.state, on: pr }
  - { id: merge, uses: pr.merge, when: "survived.review_decision == 'APPROVED'", pr: pr, method: squash }
cleanup:
  - { id: cleanup-pr, uses: test.mutate, repo: target, when: "merge.sha == ''" }
`

func staleApprovalExecutor(t *testing.T, decision string) *executor {
	t.Helper()
	p := testPlan(t, staleApprovalTail)
	x := newTestExecutor(t, p, t.TempDir())
	x.seedHandle("target", testRepo, statusOK)
	x.seedHandle("pr", PullRequest{IssueLoc: IssueLoc{Owner: "acme", Repo: "lab", Number: 7}}, statusOK)
	x.seedHandle("survived", ReviewState{
		RepoLoc: RepoLoc{Owner: "acme", Repo: "lab"}, ReviewDecision: decision,
	}, statusOK)
	testMutateCalls = 0
	x.step(t.Context(), testStep(t, p, "merge"))
	x.step(t.Context(), testStep(t, p, "cleanup-pr"))
	return x
}

func TestCleanupGateRunsWhenItsPredecessorSkipped(t *testing.T) {
	x := staleApprovalExecutor(t, "CHANGES_REQUESTED")

	if x.status["merge"] != statusSkipped {
		t.Fatalf("setup: the merge must skip on a dismissed approval, got %q", x.status["merge"])
	}
	if x.status["cleanup-pr"] != statusOK || testMutateCalls != 1 {
		t.Fatalf("the close must run when the merge did not: status %q after %d call(s)", x.status["cleanup-pr"], testMutateCalls)
	}
}

// The same path through the shipped template, whose cleanup: block is the reason
// the exemption exists. Without a client the close fails on the request it tries
// to make — what matters is that it is not skipped, because a skip leaves the
// pull request open on the customer's repository.
func TestShippedStaleApprovalClosesThePullRequestItCouldNotMerge(t *testing.T) {
	p, err := LoadTemplate("github/stale-approval")
	if err != nil {
		t.Fatal(err)
	}
	p.SetValues = map[string]string{"benign_patch": "p", "payload": "x"}
	if errs := p.resolveInputs(); len(errs) != 0 {
		t.Fatalf("inputs: %v", errs)
	}
	x := newTestExecutor(t, p, t.TempDir())
	x.seedHandle("pr", PullRequest{IssueLoc: IssueLoc{Owner: "ghektestorg", Repo: "fr-11-07-stale-approval", Number: 3}}, statusOK)
	x.seedHandle("survived", ReviewState{ReviewDecision: "CHANGES_REQUESTED"}, statusOK)

	x.step(t.Context(), testStep(t, p, "merge"))
	x.step(t.Context(), testStep(t, p, "cleanup-pr"))

	if x.status["merge"] != statusSkipped {
		t.Fatalf("setup: the merge must skip when the approval did not survive, got %q", x.status["merge"])
	}
	if x.status["cleanup-pr"] == statusSkipped {
		t.Fatalf("the pull request would be left open: %s", x.records[len(x.records)-1].Note)
	}
}

// The other half of the same gate: a merged pull request must not be closed. The
// exemption is about reading a skipped predecessor, not about running the undo
// unconditionally.
func TestCleanupGateStillSkipsWhenThePredecessorSucceeded(t *testing.T) {
	p := testPlan(t, staleApprovalTail)
	x := newTestExecutor(t, p, t.TempDir())
	x.seedHandle("target", testRepo, statusOK)
	x.seedHandle("merge", Commit{RefLoc: RefLoc{Owner: "acme", Repo: "lab", SHA: "9f1c2d3"}}, statusOK)
	testMutateCalls = 0

	x.step(t.Context(), testStep(t, p, "cleanup-pr"))

	if x.status["cleanup-pr"] != statusSkipped || testMutateCalls != 0 {
		t.Fatalf("a merged pull request must not be closed: status %q after %d call(s)", x.status["cleanup-pr"], testMutateCalls)
	}
}

// The exemption covers when: alone. A cleanup step whose port binds a step that
// skipped has no subject to act on, and running it would name a resource that was
// never created.
func TestCleanupStepBindingASkippedStepStillSkips(t *testing.T) {
	p := testPlan(t, `apiVersion: trajan.attack/v1
scope: [acme/lab]
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: lab }
  - { id: never, uses: test.adopt, when: "target.private == true" }
cleanup:
  - { id: undo, uses: test.mutate, repo: never, when: "never.owner == ''" }
`)
	x := newTestExecutor(t, p, t.TempDir())
	x.seedHandle("target", testRepo, statusOK)
	testMutateCalls = 0

	x.step(t.Context(), testStep(t, p, "never"))
	x.step(t.Context(), testStep(t, p, "undo"))

	if x.status["never"] != statusSkipped {
		t.Fatalf("setup: the producer must skip, got %q", x.status["never"])
	}
	if x.status["undo"] != statusSkipped || testMutateCalls != 0 {
		t.Fatalf("a cleanup step with nothing to act on must skip: status %q after %d call(s)", x.status["undo"], testMutateCalls)
	}
}

// A gate in the steps: block keeps the transitive skip: everything below a false
// predicate is reasoning about state the run never reached.
func TestStepGateStillSkipsItsDependents(t *testing.T) {
	p := testPlan(t, `apiVersion: trajan.attack/v1
scope: [acme/lab]
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: lab }
  - { id: never, uses: test.adopt, when: "target.private == true" }
  - { id: after, uses: test.mutate, repo: target, when: "never.owner == ''" }
`)
	x := newTestExecutor(t, p, t.TempDir())
	x.seedHandle("target", testRepo, statusOK)
	testMutateCalls = 0

	x.step(t.Context(), testStep(t, p, "never"))
	x.step(t.Context(), testStep(t, p, "after"))

	if x.status["after"] != statusSkipped || testMutateCalls != 0 {
		t.Fatalf("a step gated on a skipped step must skip: status %q after %d call(s)", x.status["after"], testMutateCalls)
	}
}
