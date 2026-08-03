package attack

import (
	"errors"
	"fmt"
	"testing"

	"github.com/praetorian-inc/trajan/internal/github"
)

// The step listed the open issues before posting and found no byte-identical
// body, so one carrying it now is what the 502 refused to name. The same title
// over the customer's own text is not: closing their issue is worse than
// recording nothing, because cleanup would then act on it.
func TestIssueOpenUnknownOutcomeNamesTheIssueItLeft(t *testing.T) {
	const title = "CI reproduction"
	issue := func(number int, body string) string {
		return fmt.Sprintf(`[{"number":%d,"state":"open","title":%q,"body":"%s"}]`, number, title, jsonEscape(body))
	}

	for _, tc := range []struct {
		name  string
		after string
		undo  string
	}{
		{"the issue the call opened", issue(9, carrier), "/repos/acme/lab/issues/9"},
		{"the call did not apply", `[]`, ""},
		{"the same title over text this run never wrote", issue(9, "please stop opening these"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var created bool
			s := actingAs(t, "mallory", "", creating(&created, `[]`, tc.after))

			_, err := issueOpen(t.Context(), s, issueOpenParams{Title: title, Body: carrier},
				Inputs{ports: map[string]Handle{"repo": Repo{RepoLoc: RepoLoc{Owner: "acme", Repo: "lab"}}}})

			if !errors.Is(err, github.ErrAmbiguous) {
				t.Fatalf("an unknown outcome must still fail the step, got %v", err)
			}
			undoneBy(t, s, tc.undo)
		})
	}
}

// A comment has no key, so the body it rendered is the only thing that names it:
// a carrier embeds this run's own public key, so a byte-identical body is one of
// ours. Two of them cannot be told apart, and deleting the wrong one would leave
// a comment this run posted standing with nothing naming it.
func TestCommentCreateUnknownOutcomeNamesTheCommentItLeft(t *testing.T) {
	comment := func(id int, body, login string) string {
		return fmt.Sprintf(`{"id":%d,"body":"%s","user":{"login":%q}}`, id, jsonEscape(body), login)
	}
	mine := comment(7001, carrier, "mallory")

	for _, tc := range []struct {
		name  string
		after string
		undo  string
	}{
		{"the comment the call posted", "[" + mine + "]", "/repos/acme/lab/issues/comments/7001"},
		{"the call did not apply", "[" + comment(6000, "on it, thanks", "victim") + "]", ""},
		{"two comments carry the body this step rendered",
			"[" + mine + "," + comment(7002, carrier, "mallory") + "]", ""},
		{"the carrier under somebody else's login", "[" + comment(7001, carrier, "victim") + "]", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var created bool
			s := actingAs(t, "mallory", "", creating(&created, `[]`, tc.after))

			on := PullRequest{IssueLoc: IssueLoc{Owner: "acme", Repo: "lab", Number: 7}}
			_, err := commentCreate(t.Context(), s, commentCreateParams{Body: carrier},
				Inputs{ports: map[string]Handle{"on": on}})

			if !errors.Is(err, github.ErrAmbiguous) {
				t.Fatalf("an unknown outcome must still fail the step, got %v", err)
			}
			undoneBy(t, s, tc.undo)
		})
	}
}
