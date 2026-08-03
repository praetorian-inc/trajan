package attack

import (
	"encoding/json"
	"strings"
	"testing"
)

func newDryRunExecutor(t *testing.T, p *Plan, runDir string) *executor {
	t.Helper()
	x := newTestExecutor(t, p, runDir)
	x.execute, x.sess.Execute = false, false
	return x
}

func plannedFor(t *testing.T, x *executor, step string) PlannedMutation {
	t.Helper()
	for _, m := range x.planned {
		if m.Step == step {
			return m
		}
	}
	t.Fatalf("step %q rendered no mutation at all; the document holds %d", step, len(x.planned))
	return PlannedMutation{}
}

// The dry run is the operator's last review before --execute, so it has to hold
// every request the run would issue with its payload fully rendered. A step
// bound to an object the render never created — an issue number that is still 0
// because nothing was posted — is the normal case downstream of any create, not a
// reason to leave the request out of the document.
func TestDryRunRendersTheRequestForAnUncreatedTarget(t *testing.T) {
	const payload = "@bot run ci --profile release"
	p := testPlan(t, `apiVersion: trajan.attack/v1
scope: [acme/lab]
steps:
  - { id: repo, uses: repo.resolve, owner: acme, repo: lab }
  - { id: issue, uses: issue.open, repo: repo, title: "CI reproduction", body: "opening a carrier" }
  - { id: carrier, uses: comment.create, on: issue, body: "`+payload+`" }
`)
	x := newDryRunExecutor(t, p, t.TempDir())
	x.seedHandle("repo", testRepo, statusOK)

	x.step(t.Context(), testStep(t, p, "issue"))
	x.step(t.Context(), testStep(t, p, "carrier"))

	comment := plannedFor(t, x, "carrier")
	if len(comment.Requests) != 1 {
		t.Fatalf("the comment rendered %d request(s), want the one it would post: %+v", len(comment.Requests), comment)
	}
	req := comment.Requests[0]
	if req.Path != "/repos/acme/lab/issues/0/comments" {
		t.Errorf("path = %q, want the request with the number the render has (0)", req.Path)
	}
	body, err := json.Marshal(req.Body)
	if err != nil {
		t.Fatalf("marshal rendered body: %v", err)
	}
	if !strings.Contains(string(body), payload) {
		t.Errorf("the rendered payload is nowhere in the document: body = %s", body)
	}
}

// A sha the render invented resolves to nothing, so the reads a status would
// otherwise make against it are skipped. The step still has to render its request
// and still has to state the ordering hazard, which is the half of the record the
// operator reads — and which used to arrive only as a by-product of those reads.
func TestDryRunStatesTheOrderingHazardWithoutReadingASynthesisedSHA(t *testing.T) {
	p := testPlan(t, `apiVersion: trajan.attack/v1
scope: [acme/lab]
steps:
  - { id: repo, uses: repo.resolve, owner: acme, repo: lab }
  - { id: branch, uses: ref.create, on: writable, name: payload }
  - { id: gate, uses: status.create, repo: repo, commit: commit, context: ci/build, state: success }
`)
	x := newDryRunExecutor(t, p, t.TempDir())
	x.seedHandle("repo", testRepo, statusOK)
	x.seedHandle("commit", Commit{RefLoc: RefLoc{Owner: "acme", Repo: "lab", Ref: "refs/heads/payload", SHA: plannedSHA}}, statusPlanned)

	x.step(t.Context(), testStep(t, p, "gate"))

	gate := plannedFor(t, x, "gate")
	if len(gate.Requests) != 1 || gate.Requests[0].Path != "/repos/acme/lab/statuses/"+plannedSHA {
		t.Fatalf("the status must still render, got %+v", gate.Requests)
	}
	if !strings.Contains(gate.Note, "a status attaches to a sha") {
		t.Errorf("note = %q, want the ordering hazard stated without a request", gate.Note)
	}
}
