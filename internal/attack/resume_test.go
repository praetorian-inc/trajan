package attack

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const resumePlan = `apiVersion: trajan.attack/v1
id: t
scope: [acme/lab-1]
inputs:
  reviewer: { default: alice }
  attempts: { type: int, default: 2 }
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: lab-1 }
  - { id: writable, uses: repo.writable, repo: target }
  - { id: branch, uses: ref.create, on: writable, name: x }
  - id: c
    uses: commit.code
    on: branch
    message: hi
    params: { attempts: 2 }
cleanup:
  - { id: cleanup-branch, uses: ref.delete, ref: branch }
`

// recordOf is the run record the original invocation wrote, read back the way a
// resume reads it — through JSON, where a plan's int is a float.
func recordOf(t *testing.T, p *Plan) PlanRecord {
	t.Helper()
	rec := PlanRecord{
		APIVersion: p.APIVersion, ID: p.ID, Source: p.Source, Scope: p.Scope,
		Mode: "execute", Authorized: true, AuthorizedVia: "interactive",
		Inputs: p.resolvedInputs, Steps: planSteps(p.Steps), Cleanup: planSteps(p.Cleanup),
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var out PlanRecord
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// A resume takes no new authorization assertion, so the plan text it reloads has
// to be the text that was authorized — down to the keys that decide which
// repository a step lands in.
func TestSameChainRefusesAnEditedPlan(t *testing.T) {
	for _, tc := range []struct{ name, edit, want string }{
		{"scope widened", "scope: [acme/*]", "authorized for [acme/lab-1]"},
		{"target retargeted", "repo: prod", "now takes"},
		{"primitive swapped", "uses: repo.fork", "now uses"},
		{"identity swapped", "message: hi\n    as: other", "now acts as"},
		{"gate added", "message: hi\n    when: target.private == true", "now gated on"},
		{"step appended", "  - { id: extra, uses: repo.resolve, owner: acme, repo: lab-1 }", "now has 6 steps"},
		{"input redeclared", "reviewer: { default: mallory }", "resolves its inputs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := testPlan(t, resumePlan)
			rec := recordOf(t, original)

			var edited string
			switch tc.name {
			case "scope widened":
				edited = strings.Replace(resumePlan, "scope: [acme/lab-1]", tc.edit, 1)
			case "target retargeted":
				edited = strings.Replace(resumePlan, "owner: acme, repo: lab-1 }", "owner: acme, "+tc.edit+" }", 1)
			case "primitive swapped":
				edited = strings.Replace(resumePlan, "uses: repo.writable", tc.edit, 1)
			case "step appended":
				edited = resumePlan + tc.edit + "\n"
			case "input redeclared":
				edited = strings.Replace(resumePlan, "reviewer: { default: alice }", tc.edit, 1)
			default:
				edited = strings.Replace(resumePlan, "message: hi", tc.edit, 1)
			}

			err := sameChain(rec, testPlan(t, edited))
			if err == nil {
				t.Fatalf("an edited plan must be refused")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want %q in the refusal, got %v", tc.want, err)
			}
		})
	}
}

// The record a run writes must accept the plan that run loaded: the comparison
// has to survive its own round trip through JSON, where an int comes back as a
// float and an absent mapping comes back as null.
func TestSameChainAcceptsTheUneditedPlan(t *testing.T) {
	for name, text := range map[string]string{
		"typed inputs and numeric keys": resumePlan,
		"no inputs at all": `apiVersion: trajan.attack/v1
id: t
scope: [acme/lab-1]
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: lab-1 }
`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := recordOf(t, testPlan(t, text))
			if err := sameChain(rec, testPlan(t, text)); err != nil {
				t.Fatalf("the plan the run recorded must resume: %v", err)
			}
		})
	}
}

// A step's outcome is unknown only if a request went out under it. Which
// intents count is the same reading cleanup takes: a call GitHub refused with a
// 4xx changed nothing, and a declared artifact was never sent at all.
func TestIssuedMutationsCountsOnlyCallsThatMayHaveLanded(t *testing.T) {
	entries := []LedgerEntry{
		{Seq: 1, Kind: RecordRun, Plan: "t"},
		{Seq: 2, Kind: RecordIntent, Step: "landed", Method: http.MethodPut, Path: "/a"},
		{Seq: 3, Kind: RecordResult, Ref: 2, Status: 200},
		{Seq: 4, Kind: RecordIntent, Step: "refused", Method: http.MethodPost, Path: "/b"},
		{Seq: 5, Kind: RecordResult, Ref: 4, Status: 422, Error: "unprocessable"},
		{Seq: 6, Kind: RecordIntent, Step: "server-error", Method: http.MethodPost, Path: "/c"},
		{Seq: 7, Kind: RecordResult, Ref: 6, Status: 500, Error: "server error"},
		{Seq: 8, Kind: RecordIntent, Step: "no-result", Method: http.MethodDelete, Path: "/d"},
		{Seq: 9, Kind: RecordIntent, Step: "declared", Note: "a cache entry a job writes"},
		{Seq: 10, Kind: RecordEffect, Step: "harvest"},
	}
	issued := issuedMutations(entries)

	for _, step := range []string{"landed", "no-result", "server-error"} {
		if _, ok := issued[step]; !ok {
			t.Errorf("step %q issued a call that may have landed and must not be repeated", step)
		}
	}
	for _, step := range []string{"refused", "declared", "harvest"} {
		if _, ok := issued[step]; ok {
			t.Errorf("step %q changed nothing and must be free to run again", step)
		}
	}
	if got := issued["landed"]; got.Path != "/a" || got.Seq != 2 {
		t.Errorf("the refusal has to name the intent, got %+v", got)
	}
}

// The gate that refuses to act on a value nobody measured is decided against the
// handle a resume rehydrated, so the distinction has to survive the step record:
// a measured false has to come back false, and a comparison that was never made
// has to come back saying so, with the reason the first process recorded.
func TestAMeasurementSurvivesTheStepRecord(t *testing.T) {
	const why = "#7 reports no head sha, so there was nothing to compare review 3 against"
	for name, want := range map[string]Measurement{
		"measured false": Measured(false),
		"measured true":  Measured(true),
		"never measured": Unmeasured(why),
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(StepRecord{
				ID: "approval", Uses: "pr.review.await", Status: "ok", HandleKind: KindReview,
				Handle: Review{RepoLoc: RepoLoc{Owner: "acme", Repo: "lab"}, Number: 7, ID: 3, Stale: want},
			})
			if err != nil {
				t.Fatal(err)
			}
			var back StepRecord
			if err := json.Unmarshal(raw, &back); err != nil {
				t.Fatalf("decode %s: %v", raw, err)
			}
			review, isReview := back.Handle.(Review)
			if !isReview {
				t.Fatalf("the handle came back as %T", back.Handle)
			}
			if review.Stale != want {
				t.Fatalf("stale = %+v, want %+v; recorded as %s", review.Stale, want, raw)
			}
			// A gate reads the decoded subject rather than the typed handle.
			subject, _ := toSubject(review).(map[string]any)
			if _, unestablished := unmeasuredReason(subject["stale"]); unestablished == want.Known {
				t.Errorf("the subject a gate reads says unestablished=%t for %+v", unestablished, want)
			}
		})
	}
}

// The ledger names an identity by its plan name and cleanup replays each inverse
// as that identity: a resume acting as a different login would attribute this
// run's mutations to an account that never made them.
func TestSameIdentitiesRefusesADifferentLogin(t *testing.T) {
	was := []PlanIdentity{{Name: "attacker", From: "env", Login: "mallory"}}
	s := &Session{identities: map[string]*identityClient{
		"attacker": {name: "attacker", login: "someone-else"},
	}}
	if err := sameIdentities(was, s); err == nil {
		t.Fatal("a resume acting as another login must be refused")
	}

	same := &Session{identities: map[string]*identityClient{
		"attacker": {name: "attacker", login: "mallory"},
	}}
	if err := sameIdentities(was, same); err != nil {
		t.Fatalf("the same login must resume: %v", err)
	}

	// An installation token reports no login at all, which is not a mismatch.
	unknown := &Session{identities: map[string]*identityClient{
		"attacker": {name: "attacker"},
	}}
	if err := sameIdentities(was, unknown); err != nil {
		t.Fatalf("an unreadable login must not block a resume: %v", err)
	}
}
