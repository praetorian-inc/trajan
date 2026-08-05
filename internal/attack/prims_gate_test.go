package attack

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

const gateSHA = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"

func gateInputs() Inputs {
	loc := RepoLoc{Owner: "acme", Repo: "lab"}
	return Inputs{ports: map[string]Handle{
		"repo":     Repo{RepoLoc: loc},
		"commit":   Commit{RefLoc: RefLoc{Owner: loc.Owner, Repo: loc.Repo, SHA: gateSHA}},
		"identity": Identity{},
	}}
}

func pageOf(q url.Values, n int) (from, to int) {
	page := max(atoiOr(q.Get("page"), 1), 1)
	per := 30
	if v := atoiOr(q.Get("per_page"), 0); v > 0 {
		per = min(v, 100)
	}
	from = min((page-1)*per, n)
	return from, min(from+per, n)
}

func atoiOr(s string, fallback int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return n
}

func linkNext(w http.ResponseWriter, r *http.Request, more bool) {
	if !more {
		return
	}
	q := r.URL.Query()
	q.Set("page", strconv.Itoa(max(atoiOr(q.Get("page"), 1), 1)+1))
	w.Header().Set("Link", fmt.Sprintf(`<http://%s%s?%s>; rel="next"`, r.Host, r.URL.Path, q.Encode()))
}

type fakeCheckRun struct {
	id       int64
	name     string
	external string
	app      string
}

// checkRunsAPI answers as the endpoint documents: 30 results per page unless
// per_page raises it to at most 100, and check_name filters by exact name on the
// server. A POST is counted rather than refused, because creating a second check run
// of a name the gate reads is the outcome under test.
func checkRunsAPI(all []fakeCheckRun, posts *int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			*posts++
			fmt.Fprintf(w, `{"id":777,"name":"required-ci","head_sha":%q,"status":"completed","conclusion":"success"}`, gateSHA)
			return
		}
		q := r.URL.Query()
		kept := all
		if name := q.Get("check_name"); name != "" {
			kept = nil
			for _, cr := range all {
				if cr.name == name {
					kept = append(kept, cr)
				}
			}
		}
		from, to := pageOf(q, len(kept))
		var body []string
		for _, cr := range kept[from:to] {
			body = append(body, fmt.Sprintf(`{"id":%d,"name":%q,"external_id":%q,"app":{"id":7,"slug":%q}}`,
				cr.id, cr.name, cr.external, cr.app))
		}
		linkNext(w, r, to < len(kept))
		fmt.Fprintf(w, `{"total_count":%d,"check_runs":[%s]}`, len(kept), strings.Join(body, ","))
	}
}

// The commit this chain has just pushed to is the one the customer's CI is answering,
// so the run carrying this plan's external id is not on the first page of anything.
// Missing it creates a second check run of the same name, which is what the marker
// exists to prevent and what the gate would then read two of.
func TestCheckCreateAdoptsItsOwnRunOnACrowdedCommit(t *testing.T) {
	const name = "required-ci"
	mine := fakeCheckRun{id: 90210, name: name, external: checkMarker(bucketPlan, name), app: "trajan-app"}
	all := make([]fakeCheckRun, 0, 140)
	for i := range 139 {
		all = append(all, fakeCheckRun{id: int64(100 + i), name: fmt.Sprintf("build (%d)", i), app: "customer-ci"})
	}
	all = append(all, mine)

	posts := 0
	s := liveAPI(t, checkRunsAPI(all, &posts))
	out, err := checkCreate(t.Context(), s, checkCreateParams{Name: name}, gateInputs())
	if err != nil {
		t.Fatalf("checkCreate: %v", err)
	}
	if posts != 0 {
		t.Errorf("this plan's own check run was already on the commit, so no second one may be created: %d POST(s)", posts)
	}
	if out.ID != mine.id {
		t.Errorf("want the run carrying this plan's external id adopted (%d), got %d", mine.id, out.ID)
	}
}

// The status a check run may report is GitHub's list, not a shorter one: waiting,
// requested and pending are what a run parked on a gate reports, and a merge gate
// parked on a check run is the thing being measured. conclusion belongs to a
// completed run alone, which is the pairing GitHub's own schema requires.
func TestCheckCreateStatusAndConclusionPairing(t *testing.T) {
	for _, tc := range []struct {
		status     string
		conclusion string
		wantStatus string
		wantConcl  string
		refused    bool
	}{
		{status: "", wantStatus: "completed", wantConcl: "success"},
		{status: "completed", conclusion: "stale", wantStatus: "completed", wantConcl: "stale"},
		{status: "waiting", wantStatus: "waiting"},
		{status: "requested", wantStatus: "requested"},
		{status: "pending", wantStatus: "pending"},
		{status: "queued", wantStatus: "queued"},
		{status: "in_progress", wantStatus: "in_progress"},
		{status: "waiting", conclusion: "success", refused: true},
		{status: "completed", conclusion: "parked", refused: true},
		{status: "asleep", refused: true},
	} {
		t.Run(tc.status+"/"+tc.conclusion, func(t *testing.T) {
			s := newProcess(t, t.TempDir(), "gate", "check.create")
			s.Execute = false
			_, err := checkCreate(t.Context(), s, checkCreateParams{Name: "required-ci", Status: tc.status, Conclusion: tc.conclusion}, gateInputs())
			planned := s.takePlanned()
			switch {
			case tc.refused && err == nil:
				t.Fatalf("want a refusal, got the request %+v", planned)
			case tc.refused:
				if len(planned) != 0 {
					t.Errorf("a refused pairing may build no request, got %+v", planned)
				}
				return
			case err != nil:
				t.Fatalf("status %q with conclusion %q is documented and must be accepted: %v", tc.status, tc.conclusion, err)
			}
			if len(planned) != 1 {
				t.Fatalf("want the one POST, got %+v", planned)
			}
			body, _ := planned[0].Body.(map[string]any)
			if body["status"] != tc.wantStatus {
				t.Errorf("status: want %q, got %v", tc.wantStatus, body["status"])
			}
			if got, ok := body["conclusion"]; tc.wantConcl != "" && got != tc.wantConcl {
				t.Errorf("conclusion: want %q, got %v", tc.wantConcl, got)
			} else if tc.wantConcl == "" && ok {
				t.Errorf("a run that has not completed carries no conclusion, got %v", got)
			}
		})
	}
}

// previous_state is the only thing an inverse of a commit status could aim at, and
// there is no delete-status endpoint, so a blank one on a context that did report
// before is a reversibility record that understates what this step overwrote.
func TestStatusCreateRecordsAPriorStateFromBeyondTheFirstPage(t *testing.T) {
	const context = "ci/required"
	s := liveAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/status") {
			fmt.Fprintf(w, `{"id":5,"state":"success","created_at":"2026-01-01T00:00:00Z"}`)
			return
		}
		all := make([]string, 0, 120)
		for i := range 119 {
			all = append(all, fmt.Sprintf(`{"context":"other/%d","state":"success"}`, i))
		}
		all = append(all, fmt.Sprintf(`{"context":%q,"state":"failure"}`, context))
		from, to := pageOf(r.URL.Query(), len(all))
		linkNext(w, r, to < len(all))
		fmt.Fprintf(w, `{"state":"failure","sha":%q,"total_count":%d,"statuses":[%s],"repository":{},"commit_url":"","url":""}`,
			gateSHA, len(all), strings.Join(all[from:to], ","))
	})

	out, err := statusCreate(t.Context(), s, statusCreateParams{Context: context, State: "success"}, gateInputs())
	if err != nil {
		t.Fatalf("statusCreate: %v", err)
	}
	if out.PreviousState != "failure" {
		t.Errorf("the context reported failure before this step, got %q", out.PreviousState)
	}
	effects := harvestEffects(t, ledgerOf(s), "commit_status")
	if len(effects) != 1 {
		t.Fatalf("want one commit_status effect, got %d", len(effects))
	}
	if got := effects[0].Detail["previous_state"]; got != "failure" {
		t.Errorf("previous_state in the effect record: want failure, got %v", got)
	}
	if got := effects[0].Detail["combined_before"]; got != "failure" {
		t.Errorf("combined_before is the server's own verdict over every context: want failure, got %v", got)
	}
}
