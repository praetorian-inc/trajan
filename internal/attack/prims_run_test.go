package attack

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/trajan/internal/github"
)

// The oracle for these cases is fr-01-03-prt-checkout-exec: a fork pull request
// against a pull_request_target workflow, where the pull_request run and the
// pull_request_target run are two runs of the same workflow file created seconds
// apart, both of them things the chain caused, and only the second carries the
// base repository's secrets.
var provocationAt = time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)

func prtWatch() runWatch {
	return runWatch{
		repo:     RepoLoc{Owner: "ghektestorg", Repo: "fr-01-03-prt-checkout-exec"},
		workflow: ".github/workflows/ci.yml",
		since:    provocationAt.Add(-correlationSkew),
		events:   []string{"pull_request", "pull_request_target"},
		pr:       7,
		from:     "pr",
	}
}

func listed(id int64, event string, offset time.Duration, opts ...func(*runBody)) runBody {
	b := runBody{
		ID:           id,
		Name:         "CI",
		Path:         ".github/workflows/ci.yml",
		Event:        event,
		Status:       "in_progress",
		HeadBranch:   "chore/ci-matrix",
		DisplayTitle: "chore: widen node matrix",
		CreatedAt:    provocationAt.Add(offset),
		RunAttempt:   1,
	}
	for _, o := range opts {
		o(&b)
	}
	return b
}

func namesPR(n int) func(*runBody) {
	return func(b *runBody) {
		b.PullRequests = []struct {
			Number int `json:"number"`
		}{{Number: n}}
	}
}

func candidateIDs(cands []runCandidate) []int64 {
	out := make([]int64, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.ID)
	}
	return out
}

func find(t *testing.T, cands []runCandidate, id int64) runCandidate {
	t.Helper()
	i := slices.IndexFunc(cands, func(c runCandidate) bool { return c.ID == id })
	if i < 0 {
		t.Fatalf("run %d is absent from the candidate record %v", id, candidateIDs(cands))
	}
	return cands[i]
}

// The first poll fires seconds after the provocation and sees whichever co-firing
// run registered first, so ambiguity measured on that one snapshot is ambiguity
// hidden. A second eligible run is a second eligible run whichever poll listed it.
func TestObserveLateCandidateIsAmbiguous(t *testing.T) {
	w := prtWatch()
	pull := listed(100, "pull_request", 4*time.Second)
	target := listed(101, "pull_request_target", 9*time.Second)

	cur := runCursor{Candidates: []runCandidate{}}
	cur.observe([]runBody{pull}, w, nil)

	if cur.RunID != 100 {
		t.Fatalf("the first poll saw one eligible run and must correlate it, chose %d", cur.RunID)
	}
	if cur.Ambiguous {
		t.Fatal("one eligible run is not ambiguous")
	}

	cur.observe([]runBody{target, pull}, w, nil)

	if cur.RunID != 100 {
		t.Fatalf("a correlated watch keeps polling its own run, it must not switch to %d", cur.RunID)
	}
	if !cur.Ambiguous {
		t.Fatal("two runs were eligible for one correlation and the record still says ambiguous=false")
	}
	late := find(t, cur.Candidates, 101)
	if !late.Late {
		t.Error("the run listed after the choice is not marked late")
	}
	if !strings.Contains(late.Rejected, "after run 100 was correlated") {
		t.Errorf("a late candidate needs a rejection reason naming the choice, got %q", late.Rejected)
	}
	if !late.eligible() {
		t.Error("a run rejected only for its timing is still one this correlation could have taken")
	}
	if !find(t, cur.Candidates, 100).eligible() || countEligible(cur.Candidates) != 2 {
		t.Errorf("both runs executed and both must count as eligible, got %v", cur.Candidates)
	}
	if n := cur.ambiguityNote(w.workflow); !strings.Contains(n, "2 runs") || !strings.Contains(n, "best guess") {
		t.Errorf("the disclosure must carry the count and say the choice is a guess, got %q", n)
	}
}

// Ambiguity must not un-latch: a later listing that happens to show only the
// chosen run cannot erase a contender the run already had.
func TestObserveKeepsAmbiguityOnceSeen(t *testing.T) {
	w := prtWatch()
	cur := runCursor{Candidates: []runCandidate{}}
	cur.observe([]runBody{listed(100, "pull_request", 4*time.Second)}, w, nil)
	cur.observe([]runBody{listed(101, "pull_request_target", 9*time.Second)}, w, nil)
	if !cur.Ambiguous {
		t.Fatal("the second listing added an eligible run")
	}

	cur.observe([]runBody{listed(100, "pull_request", 4*time.Second)}, w, nil)

	if !cur.Ambiguous {
		t.Fatal("a listing that dropped the contender must not clear the ambiguity it established")
	}
	if len(cur.Candidates) != 2 {
		t.Fatalf("the candidate record is append-only, got %v", candidateIDs(cur.Candidates))
	}
}

func TestObserveChoosesEarliestOfTwoEligible(t *testing.T) {
	w := prtWatch()
	cur := runCursor{Candidates: []runCandidate{}}
	cur.observe([]runBody{
		listed(101, "pull_request_target", 9*time.Second),
		listed(100, "pull_request", 4*time.Second),
	}, w, nil)

	if cur.RunID != 100 {
		t.Fatalf("the earliest eligible run is 100, chose %d", cur.RunID)
	}
	if !cur.Ambiguous {
		t.Fatal("two eligible runs in one listing is ambiguous")
	}
	if !find(t, cur.Candidates, 100).Chosen {
		t.Error("the chosen run is not marked chosen")
	}
	if find(t, cur.Candidates, 101).Late {
		t.Error("a run listed alongside the choice did not appear after it")
	}
	if find(t, cur.Candidates, 101).Rejected != "" {
		t.Error("an eligible run the watch simply did not take is not rejected")
	}
}

// pull_requests[] is filled in inconsistently on fork-PR runs, so it is a
// preference among eligible runs and never a filter.
func TestChooseRunPrefersNamedPullRequest(t *testing.T) {
	w := prtWatch()
	cur := runCursor{Candidates: []runCandidate{}}
	cur.observe([]runBody{
		listed(100, "pull_request", 4*time.Second),
		listed(101, "pull_request_target", 9*time.Second, namesPR(7)),
	}, w, nil)

	if cur.RunID != 101 {
		t.Fatalf("the run naming pull request 7 is the better correlation, chose %d", cur.RunID)
	}
	if !cur.Ambiguous {
		t.Fatal("the run that was passed over is still a contender")
	}
}

func TestCandidateRejectionReasons(t *testing.T) {
	w := prtWatch()
	w.ref = "chore/ci-matrix"
	w.match = "widen node"
	match, err := compileMatch(w.match)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		body runBody
		want string
	}{
		{"before the cursor", listed(1, "pull_request", -5*time.Minute), "created before the watch cursor"},
		{"inside the clock skew", listed(2, "pull_request", -30*time.Second), ""},
		{"an event the provocation cannot fire", listed(3, "push", time.Second), "not one the provocation fires"},
		{"another head branch", listed(4, "pull_request", time.Second, func(b *runBody) { b.HeadBranch = "main" }), `is not "chore/ci-matrix"`},
		{"match absent", listed(5, "pull_request", time.Second, func(b *runBody) {
			b.DisplayTitle, b.Name, b.HeadBranch = "unrelated", "other", "chore/ci-matrix"
		}), "match did not appear"},
		{"eligible", listed(6, "pull_request_target", time.Second), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, others := candidates([]runBody{tc.body}, w, match)
			if others != 0 {
				t.Fatalf("the run is of the named workflow, not another one: others=%d", others)
			}
			if len(got) != 1 {
				t.Fatalf("every run of the named workflow is recorded whether eligible or not, got %d", len(got))
			}
			switch {
			case tc.want == "" && got[0].Rejected != "":
				t.Fatalf("expected an eligible candidate, rejected as %q", got[0].Rejected)
			case tc.want != "" && !strings.Contains(got[0].Rejected, tc.want):
				t.Fatalf("rejection %q does not explain %q", got[0].Rejected, tc.want)
			}
		})
	}
}

// An empty candidate set must not read the same whether the provocation fired
// nothing or the plan named a path no workflow has, and a correlation that only
// held on the file name has to say so.
func TestCandidatesRecordOtherWorkflowsAndFileNameMatch(t *testing.T) {
	w := prtWatch()
	got, others := candidates([]runBody{
		listed(1, "pull_request", time.Second, func(b *runBody) { b.Path = ".github/workflows/deploy.yml" }),
		listed(2, "pull_request", time.Second, func(b *runBody) { b.Path = ".github/workflows/lint.yml" }),
		listed(3, "pull_request", time.Second, func(b *runBody) { b.Path = "vendored/ci.yml" }),
	}, w, nil)

	if others != 2 {
		t.Errorf("two runs of other workflows shared the window, recorded %d", others)
	}
	if len(got) != 1 {
		t.Fatalf("only the file-name match is a candidate, got %v", candidateIDs(got))
	}
	if got[0].Rejected != "" {
		t.Errorf("a file-name match is eligible, not rejected: %q", got[0].Rejected)
	}
	if !strings.Contains(got[0].Note, "vendored/ci.yml") || !strings.Contains(got[0].Note, "file name") {
		t.Errorf("a file-name-only correlation must be noted, got %q", got[0].Note)
	}
}

// A resumed watch polls the run it already correlated rather than correlating a
// second time, and must not mistake the candidates the prior process recorded for
// runs that arrived late.
func TestObserveResumedWatchKeepsItsRun(t *testing.T) {
	w := prtWatch()
	first := runCursor{Candidates: []runCandidate{}}
	first.observe([]runBody{listed(100, "pull_request", 4*time.Second)}, w, nil)

	resumed := runCursor{RunID: first.RunID, Candidates: first.Candidates, Ambiguous: first.Ambiguous}
	resumed.observe([]runBody{listed(100, "pull_request", 4*time.Second)}, w, nil)

	if resumed.RunID != 100 {
		t.Fatalf("a resumed watch polls the run it already correlated, got %d", resumed.RunID)
	}
	if resumed.Ambiguous {
		t.Fatal("re-listing the same single run must not invent ambiguity")
	}
	if len(resumed.Candidates) != 1 {
		t.Fatalf("the same run must not be recorded twice, got %v", candidateIDs(resumed.Candidates))
	}
}

func TestAmbiguityNoteSilentWhenUnambiguous(t *testing.T) {
	cur := runCursor{RunID: 100, Candidates: []runCandidate{{ID: 100, Chosen: true}}}
	if n := cur.ambiguityNote(".github/workflows/ci.yml"); n != "" {
		t.Errorf("one eligible run needs no disclosure, got %q", n)
	}
}

// Every run this correlation could have taken executed on the customer's system
// and none can be untriggered, so each needs its own irreversible-effect record —
// including the one the watch did not poll.
func TestRecordRunEffectsCoversEveryEligibleRun(t *testing.T) {
	w := prtWatch()
	s, effects := effectSession(t)

	cur := runCursor{Repository: "ghektestorg/fr-01-03-prt-checkout-exec", Candidates: []runCandidate{}}
	recorded := map[int64]bool{}

	cur.observe([]runBody{listed(100, "pull_request", 4*time.Second)}, w, nil)
	if err := recordRunEffects(s, w, &cur, recorded); err != nil {
		t.Fatal(err)
	}
	cur.observe([]runBody{listed(101, "pull_request_target", 9*time.Second), listed(100, "pull_request", 4*time.Second)}, w, nil)
	if err := recordRunEffects(s, w, &cur, recorded); err != nil {
		t.Fatal(err)
	}
	// A third poll changes nothing and must not duplicate a record.
	if err := recordRunEffects(s, w, &cur, recorded); err != nil {
		t.Fatal(err)
	}

	got := effects()
	if len(got) != 2 {
		t.Fatalf("two runs executed, the ledger holds %d effect record(s)", len(got))
	}
	for _, want := range []int64{100, 101} {
		i := slices.IndexFunc(got, func(e LedgerEntry) bool {
			id, ok := e.Effect.Detail["run_id"].(float64)
			return ok && int64(id) == want
		})
		if i < 0 {
			t.Fatalf("run %d executed and has no effect record; the ledger holds %v", want, got)
		}
		if !strings.Contains(got[i].Effect.Summary, "cannot be untriggered") {
			t.Errorf("run %d: %q does not report the run as irreversible", want, got[i].Effect.Summary)
		}
	}
	// The ledger is append-only, so no record may carry a count or a flag a later
	// poll can move. The run that was not polled says so in its own summary instead.
	uncorrelated := slices.IndexFunc(got, func(e LedgerEntry) bool { return e.Effect.Detail["correlated"] == false })
	if uncorrelated < 0 {
		t.Fatal("one of the two runs was not the one this watch polled and no record says which")
	}
	if !strings.Contains(got[uncorrelated].Effect.Summary, "same correlation as run 100") {
		t.Errorf("the run the watch passed over must name the run it was passed over for, got %q", got[uncorrelated].Effect.Summary)
	}
}

// A run.observe watch caused nothing, so the rest of the window belongs to the
// customer and must not be booked as consequences of this engagement.
func TestRecordRunEffectsObservedWatchRecordsOnlyItsRun(t *testing.T) {
	w := prtWatch()
	w.from, w.events = "", nil
	s, effects := effectSession(t)

	cur := runCursor{Repository: "ghektestorg/fr-01-03-prt-checkout-exec", Candidates: []runCandidate{}}
	cur.observe([]runBody{
		listed(100, "pull_request", 4*time.Second),
		listed(200, "schedule", 6*time.Second),
	}, w, nil)
	if err := recordRunEffects(s, w, &cur, map[int64]bool{}); err != nil {
		t.Fatal(err)
	}

	got := effects()
	if len(got) != 1 {
		t.Fatalf("an observed watch records the run it watched and nothing else, got %d", len(got))
	}
	if id, _ := got[0].Effect.Detail["run_id"].(float64); int64(id) != cur.RunID {
		t.Errorf("recorded run %v, watched %d", got[0].Effect.Detail["run_id"], cur.RunID)
	}
}

// WorkflowRun carries Provoked because the port lattice cannot tell a run this
// chain caused from one it merely watched, and the repository allowlist is no gate
// here: it contains the customer's repository by construction.
func TestRunCancelRefusesAnObservedRun(t *testing.T) {
	observed := WorkflowRun{
		RepoLoc: RepoLoc{Owner: "ghektestorg", Repo: "fr-01-03-prt-checkout-exec"},
		ID:      4242,
		Status:  "in_progress",
	}
	s := &Session{Plan: &Plan{Scope: []string{"ghektestorg/*"}}, Execute: true}
	s.begin(actingContext{step: "kill", uses: "run.cancel"})

	out, err := runCancel(t.Context(), s, runCancelParams{}, Inputs{ports: map[string]Handle{"run": observed}})
	if err == nil {
		t.Fatal("run.cancel accepted a run this plan did not provoke")
	}
	if !strings.Contains(err.Error(), "4242") || !strings.Contains(err.Error(), "run.await") {
		t.Errorf("the refusal must name the run and the primitive that may cancel one, got %v", err)
	}
	if out.Status != "in_progress" {
		t.Errorf("a refused cancellation must not restate the run's state, got %q", out.Status)
	}
}

func TestProvokedEvents(t *testing.T) {
	cases := []struct {
		name string
		rec  StepRecord
		want []string
	}{
		{
			name: "no trigger falls back to the table",
			rec:  StepRecord{Uses: "pr.open", Inputs: map[string]any{}},
			want: []string{"pull_request", "pull_request_target"},
		},
		{
			name: "a declared trigger is used verbatim, never widened",
			rec:  StepRecord{Uses: "workflow.commit", Inputs: map[string]any{"trigger": []any{"workflow_dispatch"}}},
			want: []string{"workflow_dispatch"},
		},
		{
			name: "a scalar trigger yields nothing rather than the table",
			rec:  StepRecord{Uses: "workflow.commit", Inputs: map[string]any{"trigger": "workflow_dispatch"}},
			want: nil,
		},
		{
			name: "an explicit empty trigger yields nothing rather than the widest entry",
			rec:  StepRecord{Uses: "workflow.commit", Inputs: map[string]any{"trigger": []any{}}},
			want: []string{},
		},
		{
			name: "a trigger holding a non-event yields nothing",
			rec:  StepRecord{Uses: "workflow.commit", Inputs: map[string]any{"trigger": []any{"push", 4}}},
			want: nil,
		},
		{
			name: "a primitive with no table entry names no events",
			rec:  StepRecord{Uses: "label.add", Inputs: map[string]any{}},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := provokedEvents(tc.rec); !slices.Equal(got, tc.want) {
				t.Fatalf("events = %v, want %v", got, tc.want)
			}
		})
	}
}

// An empty event set skips the event filter altogether, which makes every run of
// the workflow eligible. run.await refuses rather than correlate against a set it
// cannot name.
func TestRunAwaitRefusesAnUnnamedEventSet(t *testing.T) {
	s := &Session{Plan: &Plan{Scope: []string{"ghektestorg/*"}}, Execute: true}
	s.begin(actingContext{step: "await", uses: "run.await", prev: &Provocation{
		Step: "commit", Uses: "workflow.commit",
		Repo:   RepoLoc{Owner: "ghektestorg", Repo: "fr-01-03-prt-checkout-exec"},
		At:     provocationAt,
		Events: provokedEvents(StepRecord{Uses: "workflow.commit", Inputs: map[string]any{"trigger": "workflow_dispatch"}}),
	}})

	if _, err := runAwait(t.Context(), s, runAwaitParams{Workflow: ".github/workflows/ci.yml"}, Inputs{}); err == nil {
		t.Fatal("run.await correlated against an empty event set")
	} else if !strings.Contains(err.Error(), `"commit"`) || !strings.Contains(err.Error(), "trigger:") {
		t.Errorf("the refusal must name the step and the fix, got %v", err)
	}
}

// The oracle for the cases below is the dispatch endpoint's documented answer
// under the API version this client pins: asked for return_run_details it replies
// 200 with workflow_run_id, run_url and html_url, so the run it started needs no
// correlating. fr-01-03-prt-checkout-exec is still the repository, but the
// weakness these establish is a workflow_dispatch one.
const dispatchedRun = 21556677

func dispatchProvocation(runID int64) *Provocation {
	return &Provocation{
		Step: "dispatch", Uses: "workflow.dispatch",
		Repo:   RepoLoc{Owner: "ghektestorg", Repo: "fr-01-03-prt-checkout-exec"},
		Ref:    "main",
		RunID:  runID,
		Events: provokedEvents(StepRecord{Uses: "workflow.dispatch", Inputs: map[string]any{}}),
		PR:     7,
		At:     provocationAt,
	}
}

// A run id the dispatch response returned identifies the run on its own, so every
// input a listing needs has to be absent: a leftover cursor would send
// created>=0001-01-01 and a leftover event set would re-introduce the guess.
func TestAwaitWatchTakesTheRunIDTheResponseReturned(t *testing.T) {
	w, err := awaitWatch(dispatchProvocation(dispatchedRun), runAwaitParams{Workflow: ".github/workflows/ci.yml"})
	if err != nil {
		t.Fatal(err)
	}
	if w.runID != dispatchedRun {
		t.Fatalf("the watch polls run %d, want the %d the dispatch returned", w.runID, dispatchedRun)
	}
	if !w.since.IsZero() || w.events != nil || w.pr != 0 {
		t.Errorf("a run GitHub named needs no window, event set or pull request preference to identify it, got since=%v events=%v pr=%d", w.since, w.events, w.pr)
	}
	if d := describeWatch(w); !strings.Contains(d, "21556677") || strings.Contains(d, "created after") {
		t.Errorf("the render must name the run it polls and claim no window, got %q", d)
	}

	// The event set is what the heuristic correlates against, so it is required
	// there and irrelevant here: an id makes the events the provocation could fire
	// no part of the answer.
	noEvents := dispatchProvocation(dispatchedRun)
	noEvents.Events = nil
	if _, err := awaitWatch(noEvents, runAwaitParams{Workflow: ".github/workflows/ci.yml"}); err != nil {
		t.Errorf("a watch handed its run id must not need an event set: %v", err)
	}
}

// A provocation with no id to hand over — a push, a comment, a 204 from an older
// dispatch — still correlates the old way, cursor, skew, events and all.
func TestAwaitWatchWithoutARunIDKeepsTheHeuristic(t *testing.T) {
	w, err := awaitWatch(dispatchProvocation(0), runAwaitParams{Workflow: ".github/workflows/ci.yml"})
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case w.runID != 0:
		t.Errorf("nothing named a run, so the watch has none to poll: %d", w.runID)
	case !w.since.Equal(provocationAt.Add(-correlationSkew)):
		t.Errorf("the cursor is the provocation less the clock skew, got %v", w.since)
	case !slices.Equal(w.events, []string{"workflow_dispatch"}):
		t.Errorf("the events the provoking step can fire are the event filter, got %v", w.events)
	case w.pr != 7:
		t.Errorf("the pull request preference is carried, got %d", w.pr)
	}
}

func TestDispatchedRunID(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int64
	}{
		{"200 with run details", `{"workflow_run_id":21556677,"run_url":"https://api.github.com/repos/o/r/actions/runs/21556677","html_url":"https://github.com/o/r/actions/runs/21556677"}`, 21556677},
		{"204 with an empty body", ``, 0},
		{"a 2xx carrying some other object", `{"id":4242}`, 0},
		{"a run id past the range a float64 holds exactly", `{"workflow_run_id":9007199254740993}`, 9007199254740993},
		{"a body that is not JSON", `<html>502</html>`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dispatchedRunID(json.RawMessage(tc.body)); got != tc.want {
				t.Fatalf("run id = %d, want %d", got, tc.want)
			}
		})
	}
}

// Without return_run_details the endpoint answers 204 under the pinned API
// version, and the run has to be guessed at out of the run listing.
func TestWorkflowDispatchAsksForTheRunID(t *testing.T) {
	s, planned := dispatchSession(t, "workflow.dispatch")
	receipt, err := workflowDispatch(t.Context(), s, workflowDispatchParams{
		Workflow: ".github/workflows/ci.yml", Ref: "main", Inputs: map[string]any{"marker": "trj-7f3a"},
	}, dispatchOn())
	if err != nil {
		t.Fatal(err)
	}
	body := planned()[0].Body.(map[string]any)
	if body["return_run_details"] != true {
		t.Errorf("the dispatch must ask for the run id, body was %v", body)
	}
	if receipt.RunID != 0 {
		t.Errorf("a dry run sent nothing, so it holds no run id: %d", receipt.RunID)
	}
}

func TestWorkflowDispatchRefusesOverLimitInputsLocally(t *testing.T) {
	cases := []struct {
		name    string
		inputs  map[string]any
		refused string
	}{
		{"the documented maximum", inputsOf(25), ""},
		{"one input past it", inputsOf(26), "at most 25"},
		{"a payload past the character maximum", map[string]any{"payload": strings.Repeat("x", maxDispatchPayloadChars)}, "65535 characters"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, planned := dispatchSession(t, "workflow.dispatch")
			_, err := workflowDispatch(t.Context(), s, workflowDispatchParams{
				Workflow: ".github/workflows/ci.yml", Ref: "main", Inputs: tc.inputs,
			}, dispatchOn())
			assertRefused(t, err, tc.refused, planned())
		})
	}
}

// An over-limit dispatch is a 422 in the customer's audit trail that produces no
// evidence, so each limit has to be refused here with nothing sent.
func TestRepoDispatchRefusesOverLimitPayloadsLocally(t *testing.T) {
	cases := []struct {
		name    string
		params  repoDispatchParams
		refused string
	}{
		{"the documented event_type maximum", repoDispatchParams{EventType: strings.Repeat("e", maxEventTypeChars)}, ""},
		{"one character past it", repoDispatchParams{EventType: strings.Repeat("e", maxEventTypeChars+1)}, "100 characters or fewer"},
		{"multi-byte characters are counted as characters", repoDispatchParams{EventType: strings.Repeat("é", maxEventTypeChars)}, ""},
		{"the documented property maximum", repoDispatchParams{EventType: "trj", ClientPayload: inputsOf(10)}, ""},
		{"one property past it", repoDispatchParams{EventType: "trj", ClientPayload: inputsOf(11)}, "at most 10 top-level properties"},
		{"a client_payload over 64KB", repoDispatchParams{EventType: "trj", ClientPayload: map[string]any{"blob": strings.Repeat("x", maxDispatchPayloadChars)}}, "under 64KB"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, planned := dispatchSession(t, "repo.dispatch")
			_, err := repoDispatch(t.Context(), s, tc.params, dispatchOn())
			assertRefused(t, err, tc.refused, planned())
		})
	}
}

// 409 is the only failure the cancel endpoint documents, and a run that finished
// between the pre-read and the call is the case the step already handles, so it
// must be recognized however Mutate and the ledger wrapped it. The rest of
// runCancel needs a fake API, which internal/github does not expose a hook for.
func TestCancelConflictIsRecognisedThroughWrapping(t *testing.T) {
	conflict := &github.GhError{Status: http.StatusConflict, URL: "https://api.github.com/repos/o/r/actions/runs/1/cancel"}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"the bare error Mutate returns", conflict, true},
		{"wrapped", fmt.Errorf("cancel run 1: %w", conflict), true},
		{"joined with a ledger failure", errors.Join(conflict, errors.New("ledger: closed")), true},
		{"a 404 on a run that was deleted", &github.GhError{Status: http.StatusNotFound}, false},
		{"a 5xx of unknown outcome", fmt.Errorf("%w: %w", github.ErrAmbiguous, &github.GhError{Status: http.StatusBadGateway}), false},
		{"a transport failure", errors.New("dial tcp: i/o timeout"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isConflict(tc.err); got != tc.want {
				t.Fatalf("isConflict(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func dispatchOn() Inputs {
	return Inputs{ports: map[string]Handle{"on": Repo{
		RepoLoc:       RepoLoc{Owner: "ghektestorg", Repo: "fr-01-03-prt-checkout-exec"},
		DefaultBranch: "main",
	}}}
}

// dispatchSession renders rather than sends, which is what makes "refused with no
// request issued" observable: every request a step would have made is in planned().
func dispatchSession(t *testing.T, uses string) (*Session, func() []PlannedRequest) {
	t.Helper()
	s := &Session{Plan: &Plan{Scope: []string{"ghektestorg/*"}}}
	s.begin(actingContext{step: "dispatch", uses: uses})
	return s, s.takePlanned
}

func inputsOf(n int) map[string]any {
	in := make(map[string]any, n)
	for i := range n {
		in[fmt.Sprintf("input%02d", i)] = "v"
	}
	return in
}

func assertRefused(t *testing.T, err error, want string, planned []PlannedRequest) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("a payload inside every documented limit was refused: %v", err)
		}
		if len(planned) != 1 {
			t.Fatalf("an accepted dispatch issues one request, planned %d", len(planned))
		}
		return
	}
	if err == nil {
		t.Fatalf("an over-limit dispatch was accepted; GitHub would answer 422 and the run would produce no evidence")
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("the refusal must name the limit it hit (%q), got %v", want, err)
	}
	if len(planned) != 0 {
		t.Errorf("a request that cannot succeed must not reach the customer's audit trail, planned %v", planned)
	}
}

// effectSession returns a session whose ledger is a temp file, plus a reader for
// the effect records written to it.
func effectSession(t *testing.T) (*Session, func() []LedgerEntry) {
	t.Helper()
	path := t.TempDir() + "/_ledger.jsonl"
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	s := &Session{Plan: &Plan{Scope: []string{"ghektestorg/*"}}, Ledger: l, Execute: true}
	s.begin(actingContext{step: "run", uses: "run.await"})
	return s, func() []LedgerEntry {
		all, err := ReadLedger(path)
		if err != nil {
			t.Fatal(err)
		}
		var out []LedgerEntry
		for _, e := range all {
			if e.Kind == RecordEffect && e.Effect != nil {
				out = append(out, e)
			}
		}
		return out
	}
}
