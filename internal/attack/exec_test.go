package attack

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// test.mutate stands in for any primitive that changes state: it writes the
// write-ahead intent a real mutation writes and issues no request, which is
// exactly the state a process killed between the call and the record leaves.
type testMutateParams struct{}

var testMutateCalls int

// test.adopt is the shape of every idempotent read-or-create primitive: it
// reports that it created nothing and still hands back a usable handle.
type testAdoptParams struct{}

func init() {
	Register(Spec{
		Name:       "test.mutate",
		Summary:    "test-only: records the write-ahead intent of a mutation without issuing a request.",
		Ports:      []Port{Accepts[Repo]("repo", true)},
		Mutating:   true,
		OriginFrom: "repo",
	}, func(ctx context.Context, s *Session, _ testMutateParams, in Inputs) (Repo, error) {
		testMutateCalls++
		repo := In[Repo](in, "repo")
		_, err := s.Ledger.Intent(LedgerEntry{
			Step: s.acting.step, Uses: s.acting.uses, Target: repo.Owner + "/" + repo.Repo,
			Method: http.MethodPut, Path: "/repos/" + repo.Owner + "/" + repo.Repo + "/pulls/1/merge",
		})
		return repo, err
	})

	Register(Spec{
		Name:    "test.adopt",
		Summary: "test-only: adopts an existing resource, marking the step empty while producing a real handle.",
	}, func(ctx context.Context, s *Session, _ testAdoptParams, in Inputs) (Repo, error) {
		s.MarkEmpty("adopted the existing repository")
		return testRepo, nil
	})
}

var testRepo = Repo{
	RepoLoc: RepoLoc{Owner: "acme", Repo: "lab"}, DefaultBranch: "main", Perms: Perms{Push: true},
}

func testPlan(t *testing.T, y string) *Plan {
	t.Helper()
	p := mustParse(t, y)
	p.Source = "test.yaml"
	if errs := p.resolveInputs(); len(errs) != 0 {
		t.Fatalf("inputs: %v", errs)
	}
	return p
}

// newTestExecutor drives the executor without a network: the acting identity
// resolves and carries no client, so a step that reaches a primitive body fails
// on the client rather than issuing anything.
func newTestExecutor(t *testing.T, p *Plan, runDir string) *executor {
	t.Helper()
	l, err := OpenLedger(filepath.Join(runDir, engine.AttackLedger(p.ID)))
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	sess := &Session{
		Plan: p, PlanDir: filepath.Join(runDir, engine.AttackDir(p.ID)), Ledger: l, Execute: true,
		identities: map[string]*identityClient{}, aliases: map[string]string{},
		extraScope: map[string]string{},
	}
	ic := &identityClient{name: "test-identity"}
	sess.identities[""] = ic
	sess.acting.id = ic

	x := &executor{
		plan: p, sess: sess, runDir: runDir, execute: true,
		handles: map[string]Handle{}, subjects: map[string]any{}, status: map[string]string{},
		targets: map[string]string{}, stepIDs: map[string]bool{},
		reads: []string{}, planned: []PlannedMutation{},
	}
	for _, st := range allSteps(p) {
		x.stepIDs[st.ID] = true
	}
	return x
}

// seedHandle puts a step's outcome into the graph without running it.
func (x *executor) seedHandle(id string, h Handle, status string) {
	x.handles[id] = h
	x.subjects[id] = toSubject(h)
	x.status[id] = status
	if rs, ok := h.(RepoScoped); ok {
		x.targets[id] = rs.RepoRef().Owner + "/" + rs.RepoRef().Repo
	}
}

func testStep(t *testing.T, p *Plan, id string) *Step {
	t.Helper()
	all := allSteps(p)
	for i := range all {
		if all[i].ID == id {
			return &all[i]
		}
	}
	t.Fatalf("no step %q", id)
	return nil
}

// A dead producer must stop every step that reads it, whichever way the plan
// spells the reference. A quoted port is the case that used to slip through:
// bind reads it as a handle regardless of quoting, so the edge has to be
// registered on the same terms.
func TestStepSkipsThroughEveryEdgeKind(t *testing.T) {
	for _, tc := range []struct{ name, consumer string }{
		{"port", `{ id: use, uses: test.mutate, repo: prep }`},
		{"quoted port", `{ id: use, uses: test.mutate, repo: "prep" }`},
		{"field reference", `{ id: use, uses: repo.resolve, owner: acme, repo: prep.repo }`},
		{"when", `{ id: use, uses: repo.resolve, owner: acme, repo: lab, when: "prep.repo == 'lab'" }`},
		{"as", `{ id: use, uses: repo.resolve, owner: acme, repo: lab, as: prep }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testPlan(t, `apiVersion: trajan.attack/v1
scope: [acme/lab]
steps:
  - { id: prep, uses: repo.resolve, owner: acme, repo: lab }
  - `+tc.consumer+"\n")
			x := newTestExecutor(t, p, t.TempDir())
			x.seedHandle("prep", testRepo, statusFailed)
			testMutateCalls = 0

			x.step(t.Context(), testStep(t, p, "use"))

			if got := x.status["use"]; got != statusSkipped {
				t.Fatalf("a step reading a failed producer must skip, got %q", got)
			}
			if !strings.Contains(x.records[0].Note, `"prep"`) {
				t.Errorf("the record must name the dead producer, got %q", x.records[0].Note)
			}
			if testMutateCalls != 0 {
				t.Errorf("a skipped step must not run its body")
			}
		})
	}
}

// The same chain with a live producer must not skip: the gate is the producer's
// state, not the presence of an edge.
func TestStepRunsWhenItsProducerSucceeded(t *testing.T) {
	p := testPlan(t, `apiVersion: trajan.attack/v1
scope: [acme/lab]
steps:
  - { id: prep, uses: repo.resolve, owner: acme, repo: lab }
  - { id: use, uses: test.mutate, repo: prep }
`)
	x := newTestExecutor(t, p, t.TempDir())
	x.seedHandle("prep", testRepo, statusOK)
	testMutateCalls = 0

	x.step(t.Context(), testStep(t, p, "use"))

	if x.status["use"] != statusOK || testMutateCalls != 1 {
		t.Fatalf("status %q after %d call(s); want the step to run", x.status["use"], testMutateCalls)
	}
}

// A field whose reference resolves to nothing must fail the bind. Dropping the
// key hands the primitive a zero value the step record does not even show was
// lost — an empty sha in a ref update, an empty body in a comment.
func TestBindRefusesAReferenceThatResolvesToNothing(t *testing.T) {
	// perms exists on a repo handle, so only the last segment misses: the
	// validator checks the first segment alone, which is how this reaches bind.
	p := testPlan(t, `apiVersion: trajan.attack/v1
scope: [acme/lab]
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: lab }
  - { id: writable, uses: repo.writable, repo: target }
  - { id: branch, uses: ref.create, on: writable, name: x }
  - { id: c, uses: commit.code, on: branch, message: target.perms.nonesuch }
  - { id: d, uses: commit.code, on: branch, message: target.default_branch }
`)
	x := newTestExecutor(t, p, t.TempDir())
	x.seedHandle("target", testRepo, statusOK)
	x.seedHandle("branch", Branch{RefLoc: RefLoc{Owner: "acme", Repo: "lab", Ref: "refs/heads/x", SHA: "abc"}}, statusOK)
	e, _ := lookup("commit.code")

	if _, fields, err := x.bind(testStep(t, p, "c"), e, true); err == nil {
		t.Fatalf("an unresolvable reference must fail the bind; got fields %#v", fields)
	}
	_, fields, err := x.bind(testStep(t, p, "d"), e, true)
	if err != nil {
		t.Fatalf("a reference that does resolve must bind: %v", err)
	}
	if fields["message"] != "main" {
		t.Fatalf("want the resolved value, got %#v", fields["message"])
	}
}

// when: is held to the same standard as a field: a reference that resolves to
// nothing fails the step rather than reading as nil, which a negative predicate
// would otherwise pass on.
func TestWhenRefusesAReferenceThatResolvesToNothing(t *testing.T) {
	p := testPlan(t, `apiVersion: trajan.attack/v1
scope: [acme/lab]
steps:
  - { id: gate, uses: repo.resolve, owner: acme, repo: lab }
  - { id: use, uses: test.mutate, repo: gate, when: "gate.perms.nonesuch == false" }
`)
	x := newTestExecutor(t, p, t.TempDir())
	x.seedHandle("gate", testRepo, statusOK)
	testMutateCalls = 0

	x.step(t.Context(), testStep(t, p, "use"))

	if x.status["use"] != statusFailed {
		t.Fatalf("an unresolvable when: reference must fail the step, got %q", x.status["use"])
	}
	if testMutateCalls != 0 {
		t.Fatal("the mutation must not run on a gate that could not be read")
	}
}

// A gate decides whether to change the customer's system. A comparison the chain
// could not make is not a measured false — acting on it would put a fact nobody
// established behind a mutation — so the step fails and names the value and the
// reason, while a measurement that was made decides the gate as authored.
func TestWhenRefusesAnUnestablishedValue(t *testing.T) {
	const why = "#7 reports no head sha, so there was nothing to compare review 3 against"
	for _, tc := range []struct {
		name  string
		stale Measurement
		want  string
		calls int
	}{
		{"never measured", Unmeasured(why), statusFailed, 0},
		{"measured false", Measured(false), statusOK, 1},
		{"measured true", Measured(true), statusSkipped, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// approval is seeded rather than run: the review it stands for is what a
			// primitive with no readable head produces.
			p := testPlan(t, `apiVersion: trajan.attack/v1
scope: [acme/lab]
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: lab }
  - { id: approval, uses: test.adopt }
  - { id: merge, uses: test.mutate, repo: target, when: "approval.stale == false" }
`)
			x := newTestExecutor(t, p, t.TempDir())
			x.seedHandle("target", testRepo, statusOK)
			x.seedHandle("approval", Review{
				RepoLoc: RepoLoc{Owner: "acme", Repo: "lab"}, Number: 7, ID: 3, State: "APPROVED", Stale: tc.stale,
			}, statusOK)
			testMutateCalls = 0

			x.step(t.Context(), testStep(t, p, "merge"))

			if x.status["merge"] != tc.want || testMutateCalls != tc.calls {
				t.Fatalf("status %q after %d call(s), want %q after %d", x.status["merge"], testMutateCalls, tc.want, tc.calls)
			}
			if tc.want != statusFailed {
				return
			}
			if got := x.records[0].Error; !strings.Contains(got, "approval.stale") || !strings.Contains(got, why) {
				t.Errorf("the failure must name the value and why it was not established, got %q", got)
			}
		})
	}
}

// MarkEmpty says "no request was sent", not "nothing was produced": every
// read-or-create primitive marks the step empty when it adopts what is already
// there. Gating dependents on it would cut the chain below every adoption.
func TestEmptyProducerStillFeedsTheChain(t *testing.T) {
	p := testPlan(t, `apiVersion: trajan.attack/v1
scope: [acme/lab]
steps:
  - { id: prep, uses: test.adopt }
  - { id: use, uses: test.mutate, repo: prep }
`)
	x := newTestExecutor(t, p, t.TempDir())
	testMutateCalls = 0

	x.step(t.Context(), testStep(t, p, "prep"))
	x.step(t.Context(), testStep(t, p, "use"))

	if !x.records[0].Empty || x.records[0].Status != statusOK {
		t.Fatalf("an adoption is empty and ok, got empty=%t status=%q", x.records[0].Empty, x.records[0].Status)
	}
	if x.status["use"] != statusOK || testMutateCalls != 1 {
		t.Fatalf("the chain below an adopted resource must run: status %q after %d call(s)", x.status["use"], testMutateCalls)
	}
}

// The step record is written after the primitive returns, so a step killed
// between its call and that write leaves the ledger's intent as the only
// evidence. A resume must read it and refuse rather than repeat the call.
func TestResumeDoesNotRepeatAnIssuedMutation(t *testing.T) {
	dir := t.TempDir()
	p := testPlan(t, `apiVersion: trajan.attack/v1
scope: [acme/lab]
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: lab }
  - { id: merge, uses: test.mutate, repo: target }
`)
	testMutateCalls = 0

	first := newTestExecutor(t, p, dir)
	first.seedHandle("target", testRepo, statusOK)
	first.step(t.Context(), testStep(t, p, "merge"))
	if testMutateCalls != 1 || first.status["merge"] != statusOK {
		t.Fatalf("setup: %d call(s), status %q", testMutateCalls, first.status["merge"])
	}
	// The kill window: the call landed, the record never reached disk.
	if err := os.Remove(filepath.Join(dir, engine.AttackStep(p.ID, 1, "merge"))); err != nil {
		t.Fatal(err)
	}

	second := newTestExecutor(t, p, dir)
	if err := second.resumeFrom(dir, p.ID); err != nil {
		t.Fatal(err)
	}
	second.seedHandle("target", testRepo, statusOK)
	second.step(t.Context(), testStep(t, p, "merge"))

	if testMutateCalls != 1 {
		t.Fatalf("the resume re-issued the mutation: %d calls", testMutateCalls)
	}
	if second.status["merge"] != statusFailed || !strings.Contains(second.records[0].Error, "already issued") {
		t.Fatalf("the resume must fail the step and say why, got %q / %q", second.status["merge"], second.records[0].Error)
	}
}

// A step a prior run completed is replayed, whatever the ledger holds for it.
func TestResumeReplaysACompletedStepWithoutRunningIt(t *testing.T) {
	dir := t.TempDir()
	p := testPlan(t, `apiVersion: trajan.attack/v1
scope: [acme/lab]
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: lab }
  - { id: merge, uses: test.mutate, repo: target }
`)
	testMutateCalls = 0

	first := newTestExecutor(t, p, dir)
	first.seedHandle("target", testRepo, statusOK)
	first.step(t.Context(), testStep(t, p, "merge"))

	second := newTestExecutor(t, p, dir)
	if err := second.resumeFrom(dir, p.ID); err != nil {
		t.Fatal(err)
	}
	second.seedHandle("target", testRepo, statusOK)
	second.step(t.Context(), testStep(t, p, "merge"))

	if testMutateCalls != 1 || second.status["merge"] != statusOK {
		t.Fatalf("want a replay, got %d call(s) and status %q", testMutateCalls, second.status["merge"])
	}
	if second.handles["merge"] == nil {
		t.Fatal("a replayed step must put its handle back in the graph")
	}
}

// A resumed watch's checkpoint is the reason the watch resumes instead of the
// provocation being re-issued. A step that dies before its first poll must not
// erase it.
func TestStepKeepsThePriorCursorWhenItFailsBeforeCheckpointing(t *testing.T) {
	dir := t.TempDir()
	p := testPlan(t, `apiVersion: trajan.attack/v1
scope: [acme/lab]
steps:
  - { id: watch, uses: repo.resolve, owner: acme, repo: lab }
`)
	x := newTestExecutor(t, p, dir)
	x.prior = map[string]StepRecord{"watch": {
		ID: "watch", Seq: 1, Status: statusWaiting, Cursor: map[string]any{"run_id": float64(42)},
	}}

	x.step(t.Context(), testStep(t, p, "watch"))

	var rec StepRecord
	if err := engine.ReadJSON(filepath.Join(dir, engine.AttackStep(p.ID, 1, "watch")), &rec); err != nil {
		t.Fatalf("read record: %v", err)
	}
	if rec.Status != statusFailed {
		t.Fatalf("setup: want the step to fail without a client, got %q", rec.Status)
	}
	cursor, ok := rec.Cursor.(map[string]any)
	if !ok || cursor["run_id"] != float64(42) {
		t.Fatalf("the prior cursor must survive the failure, got %#v", rec.Cursor)
	}
}
