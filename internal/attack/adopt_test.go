package attack

import (
	"encoding/json"
	"testing"
)

// An adopt-existing read decides whether a resource already standing in the
// customer's repository is one this chain created. Getting it wrong hands the
// step somebody else's resource as its own product, and the finding then narrates
// a gate, a carrier or a pull request this run never made.

func items(t *testing.T, bodies ...string) []json.RawMessage {
	t.Helper()
	out := make([]json.RawMessage, 0, len(bodies))
	for _, b := range bodies {
		if !json.Valid([]byte(b)) {
			t.Fatalf("fixture is not valid json: %s", b)
		}
		out = append(out, json.RawMessage(b))
	}
	return out
}

const carrier = "<!-- trajan:fr-02-01 -->\nrunning the reproduction steps"

func TestIssueIsAdoptedOnlyWhenItCarriesThisRunsBody(t *testing.T) {
	const title = "CI reproduction"
	for _, tc := range []struct {
		name   string
		body   string
		adopts bool
	}{
		{"this chain's own issue", `{"number":12,"state":"open","title":"CI reproduction","body":"` + jsonEscape(carrier) + `"}`, true},
		{"same title, somebody else's text", `{"number":12,"state":"open","title":"CI reproduction","body":"please stop opening these"}`, false},
		{"same title, empty body", `{"number":12,"state":"open","title":"CI reproduction","body":""}`, false},
		{"same body, different title", `{"number":12,"state":"open","title":"unrelated","body":"` + jsonEscape(carrier) + `"}`, false},
		{"a pull request, which the issues list also returns", `{"number":12,"state":"open","title":"CI reproduction","body":"` + jsonEscape(carrier) + `","pull_request":{"url":"x"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, adopted := adoptableIssue(items(t, tc.body), title, carrier)
			if adopted != tc.adopts {
				t.Fatalf("adopted = %t, want %t (issue %+v)", adopted, tc.adopts, got)
			}
		})
	}
}

func TestIssueAdoptionFindsTheMatchAmongOthers(t *testing.T) {
	list := items(t,
		`{"number":3,"state":"open","title":"CI reproduction","body":"an older attempt"}`,
		`{"number":9,"state":"open","title":"CI reproduction","body":"`+jsonEscape(carrier)+`"}`,
	)

	got, adopted := adoptableIssue(list, "CI reproduction", carrier)
	if !adopted || got.Number != 9 {
		t.Fatalf("adopted %+v (%t), want issue 9: it is the one holding this run's carrier", got, adopted)
	}
}

func TestPullRequestIsAdoptedOnlyOnItsOwnHeadAndBase(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		adopts bool
	}{
		{"same head into the same base", `{"number":4,"state":"open","head":{"label":"mallory:payload","ref":"payload"},"base":{"ref":"main"}}`, true},
		{"same head into another base", `{"number":4,"state":"open","head":{"label":"mallory:payload","ref":"payload"},"base":{"ref":"release-1.2"}}`, false},
		{"another head into the same base", `{"number":4,"state":"open","head":{"label":"acme:hotfix","ref":"hotfix"},"base":{"ref":"main"}}`, false},
		{"already closed", `{"number":4,"state":"closed","head":{"label":"mallory:payload","ref":"payload"},"base":{"ref":"main"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, adopted := adoptablePR(items(t, tc.body), "mallory:payload", "main")
			if adopted != tc.adopts {
				t.Fatalf("adopted = %t, want %t (pull request %+v)", adopted, tc.adopts, got)
			}
		})
	}
}

// The customer's CI answers a pushed commit with its own check runs, and they are
// named the same ordinary things a plan names. Only the external id this chain
// stamps tells them apart.
func TestCheckRunIsAdoptedOnlyOnThisChainsMarker(t *testing.T) {
	marker := checkMarker("gate-bypass", "build")
	runs := []checkRunBody{
		{ID: 1, Name: "build", ExternalID: "", Status: "completed", Conclusion: "failure"},
		{ID: 2, Name: "ci/lint", ExternalID: marker},
		{ID: 3, Name: "build", ExternalID: "some-other-tool"},
	}

	mine, foreign := classifyCheckRuns(runs, "build", marker)

	if mine.ID != 0 {
		t.Errorf("adopted check run %d, but no run named build carries this chain's external id", mine.ID)
	}
	if len(foreign) != 2 {
		t.Errorf("foreign = %+v, want both runs named build", foreign)
	}
}

func TestCheckRunAdoptsThisChainsOwnRerun(t *testing.T) {
	marker := checkMarker("gate-bypass", "build")
	runs := []checkRunBody{
		{ID: 1, Name: "build", ExternalID: "", App: appOf("customer-ci")},
		{ID: 2, Name: "build", ExternalID: marker},
	}

	mine, foreign := classifyCheckRuns(runs, "build", marker)

	if mine.ID != 2 {
		t.Fatalf("adopted %d, want the run this chain created", mine.ID)
	}
	if len(foreign) != 1 || foreign[0].ID != 1 {
		t.Fatalf("foreign = %+v, want the customer's own run reported beside it", foreign)
	}
	if got := foreignApps(foreign); got != "customer-ci" {
		t.Errorf("foreignApps = %q, want the app the gate is also reading", got)
	}
}

// The marker has to differ per plan, or two plans forging the same gate name on
// one commit adopt each other's work.
func TestCheckMarkerIsPerPlanAndName(t *testing.T) {
	if checkMarker("plan-a", "build") == checkMarker("plan-b", "build") {
		t.Error("two plans must not share a marker")
	}
	if checkMarker("plan-a", "build") == checkMarker("plan-a", "test") {
		t.Error("two check names must not share a marker")
	}
}

func appOf(slug string) struct {
	ID   int64  `json:"id"`
	Slug string `json:"slug"`
} {
	var a struct {
		ID   int64  `json:"id"`
		Slug string `json:"slug"`
	}
	a.Slug = slug
	return a
}

func jsonEscape(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return s
	}
	return string(b[1 : len(b)-1])
}
