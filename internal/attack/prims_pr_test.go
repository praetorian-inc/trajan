package attack

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/praetorian-inc/trajan/internal/github"
)

// actingAs gives the session an identity with a login, which is what an
// installation token does not have and what several read-backs narrow on.
func actingAs(t *testing.T, login, kind string, h http.HandlerFunc) *Session {
	t.Helper()
	s := liveAPI(t, h)
	s.begin(actingContext{step: "step", uses: "uses",
		id: &identityClient{name: "operator", login: login, kind: kind, client: github.NewClient("tok")}})
	return s
}

// recordedUndo is every inverse the run resolved after the fact — the records a
// created resource's id is only known in time for.
func recordedUndo(t *testing.T, s *Session) []UndoStep {
	t.Helper()
	var out []UndoStep
	for _, e := range ledgerEntries(t, s) {
		if e.Kind == RecordUndo {
			out = append(out, e.Inverse...)
		}
	}
	return out
}

func ledgerEntries(t *testing.T, s *Session) []LedgerEntry {
	t.Helper()
	entries, err := ReadLedger(ledgerOf(s))
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	return entries
}

// undoneBy asserts the run recorded exactly the inverse wantPath names and that
// cleanup reaches it, or — for an empty wantPath — that nothing was recorded at
// all: a guessed inverse would have cleanup act on the customer's own resource.
func undoneBy(t *testing.T, s *Session, wantPath string) {
	t.Helper()
	undo := recordedUndo(t, s)
	if wantPath == "" {
		if len(undo) != 0 {
			t.Fatalf("the read-back could not tell this run's artifact apart, yet an inverse was recorded: %+v", undo)
		}
		return
	}
	if len(undo) != 1 || undo[0].Path != wantPath {
		t.Fatalf("the ledger cannot name the artifact: recorded %+v, want an inverse against %s", undo, wantPath)
	}
	report := cleanupOf(t, s.PlanDir)
	if !slices.ContainsFunc(report.Partial, func(it CleanupItem) bool { return it.Path == wantPath }) {
		t.Fatalf("cleanup cannot reach %s: %+v", wantPath, report)
	}
}

// creating answers a POST with a 5xx after the resource has landed — the outcome
// where the id the inverse needs exists on the target and in no response — and
// answers every GET with what is standing at that point.
func creating(created *bool, before, after string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			*created = true
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(`<html><body>Server Error</body></html>`))
			return
		}
		if *created {
			w.Write([]byte(after))
			return
		}
		w.Write([]byte(before))
	}
}

// A pull request open from this head into this base was not there when the step
// looked, so one there now is what the 502 refused to name. Head and base are the
// key: adopting whatever the head= filter returned would have cleanup close a
// pull request into a base this chain never targeted.
func TestPROpenUnknownOutcomeNamesThePullRequestItLeft(t *testing.T) {
	const mine = `[{"number":42,"state":"open","head":{"label":"mallory:payload","ref":"payload"},"base":{"ref":"main"}}]`
	const otherBase = `[{"number":43,"state":"open","head":{"label":"mallory:payload","ref":"payload"},"base":{"ref":"release-1.2"}}]`

	for _, tc := range []struct {
		name  string
		after string
		undo  string
	}{
		{"the pull request the call opened", mine, "/repos/acme/lab/pulls/42"},
		{"the call did not apply", `[]`, ""},
		{"an open pull request from the same head into another base", otherBase, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var created bool
			s := actingAs(t, "mallory", "", creating(&created, `[]`, tc.after))

			head := Branch{RefLoc: RefLoc{Owner: "mallory", Repo: "lab", Ref: "refs/heads/payload"}}
			base := Repo{RepoLoc: RepoLoc{Owner: "acme", Repo: "lab"}, DefaultBranch: "main"}
			_, err := prOpen(t.Context(), s, prOpenParams{Title: "docs", BaseRef: "main"},
				Inputs{ports: map[string]Handle{"head": head, "base": base}})

			if !errors.Is(err, github.ErrAmbiguous) {
				t.Fatalf("an unknown outcome must still fail the step, got %v", err)
			}
			undoneBy(t, s, tc.undo)
		})
	}
}

// A review carries nothing that says which credential submitted it, and the
// credential the actions-approval chain runs as reports no login to match its
// author against. What is left is the commit, the decision and the set of reviews
// that were already standing: dismissing an approval that was there beforehand
// would reverse the customer's own reviewer, and dismissing one of two that
// appeared would leave this run's own approval standing.
func TestReviewSubmitUnknownOutcomeNamesOnlyTheReviewItAdded(t *testing.T) {
	const commit = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"
	review := func(id int, state, login string) string {
		return fmt.Sprintf(`{"id":%d,"state":%q,"commit_id":%q,"user":{"login":%q}}`, id, state, commit, login)
	}
	standing := review(900, "APPROVED", "reviewer")

	for _, tc := range []struct {
		name  string
		after string
		undo  string
	}{
		{"the review the call submitted",
			"[" + standing + "," + review(5150, "APPROVED", "github-actions[bot]") + "]",
			"/repos/acme/lab/pulls/7/reviews/5150/dismissals"},
		{"the approval that was already standing", "[" + standing + "]", ""},
		{"two approvals appeared where one was submitted",
			"[" + standing + "," + review(5150, "APPROVED", "github-actions[bot]") + "," + review(5151, "APPROVED", "reviewer") + "]", ""},
		{"the change request the customer's reviewer added",
			"[" + standing + "," + review(7777, "CHANGES_REQUESTED", "reviewer") + "]", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var created bool
			reviews := creating(&created, "["+standing+"]", tc.after)
			s := actingAs(t, "", kindAppInstallation, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/repos/acme/lab/pulls/7/reviews":
					reviews(w, r)
				case "/repos/acme/lab/actions/permissions/workflow":
					w.Write([]byte(`{"can_approve_pull_request_reviews":true}`))
				default:
					fmt.Fprintf(w, `{"number":7,"state":"open","head":{"sha":%q},"base":{"ref":"main"},"user":{"login":"victim"}}`, commit)
				}
			})

			pr := PullRequest{IssueLoc: IssueLoc{Owner: "acme", Repo: "lab", Number: 7}, Base: "main"}
			_, err := prReviewSubmit(t.Context(), s, prReviewSubmitParams{Decision: "APPROVE"},
				Inputs{ports: map[string]Handle{"pr": pr}})

			if !errors.Is(err, github.ErrAmbiguous) {
				t.Fatalf("an unknown outcome must still fail the step, got %v", err)
			}
			undoneBy(t, s, tc.undo)
		})
	}
}

// A submitted COMMENT review can be neither dismissed nor deleted, so no read-back
// can record an inverse for one. What the report must not do is fall back to the
// sentence a read that came up empty earns: this review may well be there, and the
// operator is the only one who can go and look.
func TestCommentReviewUnknownOutcomeIsReportedAsUnnameable(t *testing.T) {
	const commit = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"
	var created bool
	reviews := creating(&created, `[]`,
		fmt.Sprintf(`[{"id":6000,"state":"COMMENTED","commit_id":%q,"user":{"login":"mallory"}}]`, commit))
	s := actingAs(t, "mallory", "", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/acme/lab/pulls/7/reviews" {
			reviews(w, r)
			return
		}
		fmt.Fprintf(w, `{"number":7,"state":"open","head":{"sha":%q},"base":{"ref":"main"},"user":{"login":"victim"}}`, commit)
	})

	pr := PullRequest{IssueLoc: IssueLoc{Owner: "acme", Repo: "lab", Number: 7}, Base: "main"}
	_, err := prReviewSubmit(t.Context(), s, prReviewSubmitParams{Decision: "COMMENT", Body: "reproduction notes"},
		Inputs{ports: map[string]Handle{"pr": pr}})

	if !errors.Is(err, github.ErrAmbiguous) {
		t.Fatalf("an unknown outcome must still fail the step, got %v", err)
	}
	undoneBy(t, s, "")
	effs := unknownOutcomeEffects(ledgerEntries(t, s))
	if len(effs) != 1 {
		t.Fatalf("expected one unknown_outcome effect, got %+v", effs)
	}
	if strings.Contains(effs[0].Summary, "found nothing") {
		t.Errorf("a review no request can reverse was reported as absent: %q", effs[0].Summary)
	}
	if !strings.Contains(effs[0].Summary, "by hand") {
		t.Errorf("the operator is not told to look for it: %q", effs[0].Summary)
	}
}

// Whether an approval covers the head is what a plan gates a merge on, and it is
// a comparison of two shas. When either side is missing there is no comparison:
// reading that as false says the approval is still valid, which is the reading a
// stale-approval chain exists to disprove.
func TestStalenessIsUnestablishedWhenEitherSideIsMissing(t *testing.T) {
	const head = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const older = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	for _, tc := range []struct {
		name         string
		head, commit string
		known, stale bool
	}{
		{"the review covers the head", head, head, true, false},
		{"the review covers an older commit", head, older, true, true},
		{"the head could not be read", "", head, false, false},
		{"the review names no commit", head, "", false, false},
		{"neither side is readable", "", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := staleness(7, 3, tc.head, tc.commit)
			if got.Known != tc.known || got.Value != tc.stale {
				t.Fatalf("staleness = %+v, want established %t stale %t", got, tc.known, tc.stale)
			}
			if !got.Known && got.Reason == "" {
				t.Error("an unestablished comparison must say why it could not be made")
			}
		})
	}
}

const (
	protectionPath = "/repos/ghektestorg/fr-11-07-stale-approval/branches/main/protection"
	rulesPath      = "/repos/ghektestorg/fr-11-07-stale-approval/rules/branches/main"
)

// Whether a later push dismisses a standing approval is the fact a stale-approval
// chain rests on, and two surfaces enforce it. A branch a ruleset gates answers 404
// on the protection endpoint, so reading that 404 alone as "no approval is ever
// dismissed" tells the customer a gate they have is absent — and the same endpoint
// needs administration:read, so a credential without it must not produce a
// negative either.
func TestDismissStaleReviewsReadsBothProtectionSurfaces(t *testing.T) {
	const dismissingRuleset = `[{"type":"pull_request","ruleset_source_type":"Organization","ruleset_source":"ghektestorg",
	  "ruleset_id":42,"parameters":{"required_approving_review_count":1,"dismiss_stale_reviews_on_push":true}}]`
	const keepingRuleset = `[{"type":"pull_request","ruleset_source_type":"Repository","ruleset_source":"ghektestorg/fr-11-07-stale-approval",
	  "ruleset_id":7,"parameters":{"required_approving_review_count":1,"dismiss_stale_reviews_on_push":false}}]`
	const unrelatedRule = `[{"type":"commit_message_pattern","ruleset_source_type":"Repository","ruleset_id":9,
	  "parameters":{"operator":"starts_with","pattern":"issue"}}]`
	const silentRule = `[{"type":"pull_request","ruleset_source_type":"Repository","ruleset_id":11,
	  "parameters":{"required_approving_review_count":1}}]`
	const protectionDismisses = `{"required_pull_request_reviews":{"dismiss_stale_reviews":true,"required_approving_review_count":1}}`
	const protectionKeeps = `{"required_pull_request_reviews":{"dismiss_stale_reviews":false,"required_approving_review_count":1}}`

	for _, tc := range []struct {
		name           string
		protection     stubReply
		rules          stubReply
		known, dismiss bool
	}{
		{"a ruleset dismisses and no branch protection rule exists",
			stubReply{status: http.StatusNotFound}, stubReply{body: dismissingRuleset}, true, true},
		{"a branch protection rule dismisses",
			stubReply{body: protectionDismisses}, stubReply{body: `[]`}, true, true},
		{"neither surface dismisses",
			stubReply{status: http.StatusNotFound}, stubReply{body: unrelatedRule}, true, false},
		{"a ruleset requires review but keeps approvals across a push",
			stubReply{body: protectionKeeps}, stubReply{body: keepingRuleset}, true, false},
		{"the protection rule needs admin this credential lacks",
			stubReply{status: http.StatusForbidden, body: `{"message":"Must have admin rights to Repository."}`},
			stubReply{body: `[]`}, false, false},
		{"the rulesets are unreadable and no protection rule dismisses",
			stubReply{body: protectionKeeps}, stubReply{status: http.StatusForbidden}, false, false},
		{"a ruleset requires review but declares no dismissal parameter",
			stubReply{status: http.StatusNotFound}, stubReply{body: silentRule}, false, false},
		{"a protection rule dismisses even though the rulesets are unreadable",
			stubReply{body: protectionDismisses}, stubReply{status: http.StatusForbidden}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &stubAPI{routes: map[string]stubReply{protectionPath: tc.protection, rulesPath: tc.rules}}
			s := &Session{}

			got := dismissStaleReviews(t.Context(), s, api,
				RepoLoc{Owner: "ghektestorg", Repo: "fr-11-07-stale-approval"}, "main")

			if got.Known != tc.known || got.Value != tc.dismiss {
				t.Fatalf("dismiss_stale_reviews = %+v, want established %t dismissing %t", got, tc.known, tc.dismiss)
			}
			if !got.Known {
				if got.Reason == "" {
					t.Error("an unestablished reading must say why it could not be made")
				}
				if !strings.Contains(s.acting.note, "unestablished") {
					t.Errorf("the step record must say the reading is unestablished, note = %q", s.acting.note)
				}
			}
			if !api.sawPath(rulesPath) {
				t.Errorf("the rulesets were never read, so a ruleset-enforced dismissal could not be seen; asked %v", api.asked)
			}
		})
	}
}

// A positive from either surface settles the question, so it needs no agreement
// from the other; a negative needs both, because a surface nobody could read
// cannot be the difference between an approval that survives a push and one that
// does not.
func TestCombineDismissalNeedsBothSurfacesForANegative(t *testing.T) {
	for _, tc := range []struct {
		name                string
		protection, ruleset Measurement
		known, dismiss      bool
	}{
		{"both read, neither dismisses", Measured(false), Measured(false), true, false},
		{"protection dismisses, ruleset unreadable", Measured(true), Unmeasured("rulesets 403"), true, true},
		{"ruleset dismisses, protection unreadable", Unmeasured("protection 403"), Measured(true), true, true},
		{"protection unreadable, ruleset does not dismiss", Unmeasured("protection 403"), Measured(false), false, false},
		{"ruleset unreadable, protection does not dismiss", Measured(false), Unmeasured("rulesets 403"), false, false},
		{"neither surface readable", Unmeasured("protection 403"), Unmeasured("rulesets 403"), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := combineDismissal(tc.protection, tc.ruleset)
			if got.Known != tc.known || got.Value != tc.dismiss {
				t.Fatalf("combineDismissal = %+v, want established %t dismissing %t", got, tc.known, tc.dismiss)
			}
			if !got.Known && got.Reason == "" {
				t.Error("an unestablished reading must carry the reason forward")
			}
		})
	}
}

// The restriction on an Actions credential approving a pull request is a
// repository setting, not authorship: "Allow GitHub Actions to create and approve
// pull requests" is off by default on a repository created in a personal account,
// and GITHUB_TOKEN is an App installation token. Waiving the guard for that class
// sends an approval GitHub refuses, so the refusal lands in the customer's audit
// log instead of here and produces no evidence.
func TestActionsApprovalGuardReadsTheSettingThatBlocksIt(t *testing.T) {
	const workflowPath = "/repos/ghektestorg/fr-11-07-stale-approval/actions/permissions/workflow"
	pr := PullRequest{IssueLoc: IssueLoc{Owner: "ghektestorg", Repo: "fr-11-07-stale-approval", Number: 7}}
	acting := actingContext{id: &identityClient{name: "range-app", kind: kindAppInstallation}}

	for _, tc := range []struct {
		name    string
		reply   stubReply
		refused bool
		says    string
	}{
		{"the setting is off, which is the default for a personal-account repository",
			stubReply{body: `{"default_workflow_permissions":"write","can_approve_pull_request_reviews":false}`},
			true, "can_approve_pull_request_reviews false"},
		{"the setting is on",
			stubReply{body: `{"default_workflow_permissions":"write","can_approve_pull_request_reviews":true}`},
			false, "allows GitHub Actions to create and approve pull requests"},
		{"the setting needs admin this credential lacks",
			stubReply{status: http.StatusForbidden, body: `{"message":"Resource not accessible by integration"}`},
			false, "unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &stubAPI{routes: map[string]stubReply{workflowPath: tc.reply}}
			s := &Session{}
			s.begin(acting)

			err := selfReviewGuard(t.Context(), s, api, "APPROVE", "range-victim", pr)

			if tc.refused {
				if err == nil {
					t.Fatal("the approval must be refused here rather than on the customer's system")
				}
				if !strings.Contains(err.Error(), tc.says) {
					t.Errorf("the refusal must name the setting that causes it, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("the guard must not refuse an approval GitHub allows: %v", err)
			}
			if !strings.Contains(s.acting.note, tc.says) {
				t.Errorf("the step record must say what was read, note = %q", s.acting.note)
			}
		})
	}
}

// A COMMENT or REQUEST_CHANGES review is not an approval, so neither the setting
// nor authorship refuses it and nothing should be read to find that out.
func TestSelfReviewGuardOnlyGuardsApprovals(t *testing.T) {
	api := &stubAPI{routes: map[string]stubReply{}}
	s := &Session{}
	s.begin(actingContext{id: &identityClient{name: "range-app", kind: kindAppInstallation}})

	if err := selfReviewGuard(t.Context(), s, api, "COMMENT", "range-victim",
		PullRequest{IssueLoc: IssueLoc{Owner: "ghektestorg", Repo: "fr-11-07-stale-approval"}}); err != nil {
		t.Fatalf("a comment review is not an approval: %v", err)
	}
	if len(api.asked) != 0 {
		t.Errorf("nothing needed reading, yet the guard asked for %v", api.asked)
	}
}
