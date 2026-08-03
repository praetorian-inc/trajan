package attack

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/praetorian-inc/trajan/internal/github"
)

// stubAPI answers a fixed route table, so a primitive's real read path runs
// without a network. internal/github.apiBase is package-private and a
// *github.Client cannot be repointed at a test server from here; the exported
// github.GitHub interface is the seam that is reachable, which is why the read
// helpers take it. An unrouted path answers 404, the way GitHub does.
type stubAPI struct {
	routes map[string]stubReply
	asked  []string
}

type stubReply struct {
	status int // 0 is 200
	body   string
}

func (a *stubAPI) reply(path string) (json.RawMessage, error) {
	a.asked = append(a.asked, path)
	r, routed := a.routes[path]
	switch {
	case !routed:
		return nil, &github.GhError{Status: http.StatusNotFound, URL: path, Body: `{"message":"Not Found"}`}
	case r.status != 0 && r.status != http.StatusOK:
		return nil, &github.GhError{Status: r.status, URL: path, Body: r.body}
	}
	return json.RawMessage(r.body), nil
}

func (a *stubAPI) Get(_ context.Context, path string, _ url.Values, _ bool) (json.RawMessage, http.Header, error) {
	raw, err := a.reply(path)
	return raw, http.Header{}, err
}

func (a *stubAPI) Paginate(_ context.Context, path string, _ url.Values, _ int) ([]json.RawMessage, error) {
	raw, err := a.reply(path)
	if err != nil {
		return nil, err
	}
	var items []json.RawMessage
	return items, json.Unmarshal(raw, &items)
}

func (a *stubAPI) GetRaw(context.Context, string, url.Values, string) ([]byte, http.Header, error) {
	panic("stubAPI: GetRaw is not part of any path under test")
}

func (a *stubAPI) GetContentWithSHA(context.Context, string, string, bool) ([]byte, string, bool, error) {
	panic("stubAPI: GetContentWithSHA is not part of any path under test")
}

func (a *stubAPI) ResolveRefCommitSHA(context.Context, string, string, string) (string, error) {
	panic("stubAPI: ResolveRefCommitSHA is not part of any path under test")
}

func (a *stubAPI) sawPath(want string) bool { return slices.Contains(a.asked, want) }

// A Pull Request Simple item, which is what GET /repos/{owner}/{repo}/pulls
// returns: merge_commit_sha and draft are on it, mergeable_state is not.
const listedPullRequest = `{
  "number": 7,
  "title": "chore: bump lockfile",
  "state": "open",
  "draft": false,
  "merge_commit_sha": "0000000000000000000000000000000000000000",
  "head": {"ref": "chore/dep-bump", "label": "range-attacker:chore/dep-bump"},
  "base": {"ref": "main"},
  "created_at": "2026-08-01T10:00:00Z"
}`

// The list endpoint cannot report mergeability, so pr.list handed every plan a
// PullRequest whose mergeable_state was the empty string: a when: comparing it
// with "clean" never matched and one comparing != "clean" always did, and neither
// measured anything. The oracle is the schema — the field is absent from the list
// item above and present on the singular pull request.
func TestPrListReportsMergeabilityItActuallyRead(t *testing.T) {
	loc := RepoLoc{Owner: "ghektestorg", Repo: "fr-11-07-stale-approval"}

	var listed prListItem
	if err := json.Unmarshal([]byte(listedPullRequest), &listed); err != nil {
		t.Fatalf("decode list item: %v", err)
	}
	if got := listed.handle(loc).MergeableState; got != "" {
		t.Fatalf("the list schema carries no mergeable_state, so it cannot supply one; got %q", got)
	}

	t.Run("the singular read supplies it", func(t *testing.T) {
		api := &stubAPI{routes: map[string]stubReply{
			"/repos/ghektestorg/fr-11-07-stale-approval/pulls/7": {body: `{
			  "number": 7, "state": "open", "merged": false,
			  "mergeable": true, "mergeable_state": "clean",
			  "head": {"ref": "chore/dep-bump", "label": "range-attacker:chore/dep-bump", "sha": "aaaa"},
			  "base": {"ref": "main"}, "created_at": "2026-08-01T10:00:00Z"}`},
		}}
		s := &Session{}

		got := matchedPR(t.Context(), s, api, loc, listed)

		if got.MergeableState != "clean" {
			t.Errorf("mergeable_state = %q, want the value the singular read reported", got.MergeableState)
		}
		if got.Number != 7 || got.Head != "chore/dep-bump" || got.Base != "main" {
			t.Errorf("the re-read must not lose what the list matched on: %+v", got)
		}
	})

	t.Run("a failed re-read says so instead of implying a reading", func(t *testing.T) {
		api := &stubAPI{routes: map[string]stubReply{
			"/repos/ghektestorg/fr-11-07-stale-approval/pulls/7": {status: http.StatusForbidden, body: `{"message":"Resource not accessible"}`},
		}}
		s := &Session{}

		got := matchedPR(t.Context(), s, api, loc, listed)

		if got.Number != 7 || got.HeadLabel != "range-attacker:chore/dep-bump" {
			t.Errorf("a failed re-read must still hand back the pull request the list matched: %+v", got)
		}
		if !strings.Contains(s.acting.note, "mergeable_state") {
			t.Errorf("the step record must say mergeability was not read, note = %q", s.acting.note)
		}
	})
}
