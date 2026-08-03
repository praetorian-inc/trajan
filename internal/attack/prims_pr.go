package attack

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/github"
)

func init() {
	Register(Spec{
		Name:       "pr.open",
		Summary:    "Open a pull request from a head ref — same-repo or cross-fork — into a base branch.",
		Ports:      []Port{Accepts[WritableRef]("head", true), Accepts[RepoScoped]("base", true)},
		Caps:       []Capability{CapPullRequests},
		Mutating:   true,
		Reversible: true,
		CrossRepo:  true,
		OriginFrom: "base",
	}, prOpen)

	Register(Spec{
		Name:       "pr.close",
		Summary:    "Close a pull request.",
		Ports:      []Port{Accepts[PullRequest]("pr", true)},
		Caps:       []Capability{CapPullRequests},
		Mutating:   true,
		OriginFrom: "pr",
	}, prClose)

	Register(Spec{
		Name:       "pr.review.await",
		Summary:    "Block until a review decision — an approval or a change request — arrives on a pull request, checkpointing the poll cursor.",
		Ports:      []Port{Accepts[PullRequest]("on", true)},
		OriginFrom: "on",
	}, prReviewAwait)

	Register(Spec{
		Name:       "pr.merge.await",
		Summary:    "Block until a pull request reaches a terminal merged or closed state.",
		Ports:      []Port{Accepts[PullRequest]("on", true)},
		OriginFrom: "on",
	}, prMergeAwait)

	Register(Spec{
		Name:       "pr.mergeability.await",
		Summary:    "Poll until GitHub has computed a pull request's mergeability and required-check state.",
		Ports:      []Port{Accepts[PullRequest]("on", true)},
		OriginFrom: "on",
	}, prMergeabilityAwait)

	Register(Spec{
		Name:        "pr.merge",
		Summary:     "Merge a pull request via the API with an expected-head SHA guard.",
		Ports:       []Port{Accepts[PullRequest]("pr", true), Accepts[Commit]("expected", false)},
		Caps:        []Capability{CapContentsWrite},
		Mutating:    true,
		Destructive: true,
		OriginFrom:  "pr",
	}, prMerge)

	Register(Spec{
		Name:       "pr.review.state",
		Summary:    "Read a pull request's aggregate review decision and per-review staleness in one record.",
		Ports:      []Port{Accepts[PullRequest]("on", true)},
		OriginFrom: "on",
	}, prReviewState)

	Register(Spec{
		Name:       "pr.review.submit",
		Summary:    "Submit a review — APPROVE, REQUEST_CHANGES or COMMENT — against a specific commit of a PR.",
		Ports:      []Port{Accepts[PullRequest]("pr", true), Accepts[Commit]("commit", false)},
		Caps:       []Capability{CapPullRequests},
		Mutating:   true,
		OriginFrom: "pr",
	}, prReviewSubmit)
}

type prMergeParams struct {
	Method string `yaml:"method"`
}

type prReviewStateParams struct{}

type prReviewSubmitParams struct {
	Decision string `yaml:"decision"`
	Body     string `yaml:"body"`
}

const (
	reviewPollInterval = 30 * time.Second
	mergePollInterval  = 30 * time.Second
	// Mergeability is computed asynchronously and the read itself schedules the
	// computation, so this poll is tight and short-lived rather than human-paced.
	mergeabilityPollInterval = 3 * time.Second
)

// prCursor is what a pull-request wait checkpoints: enough to see progress
// during a multi-day watch, and enough to know the watch was already running.
type prCursor struct {
	Subject string `json:"subject"`
	Waiting string `json:"waiting_for"`
	Since   string `json:"since"`
	Seen    string `json:"seen,omitempty"`
	Polls   int    `json:"polls"`
	At      string `json:"at"`
}

func newPRCursor(pr PullRequest, waitingFor string) prCursor {
	return prCursor{
		Subject: fmt.Sprintf("%s/%s#%d", pr.Owner, pr.Repo, pr.Number),
		Waiting: waitingFor,
		Since:   engine.IsoformatUTC(time.Now()),
	}
}

type prReviewAwaitParams struct {
	Timeout string `yaml:"timeout"`
}

// prReviewAwait ends on a decision — an approval or a change request. A
// COMMENTED review is not one: every review bot posts those, and unblocking on
// one would defeat the wait the chain exists to make.
func prReviewAwait(ctx context.Context, s *Session, p prReviewAwaitParams, in Inputs) (Review, error) {
	pr := In[PullRequest](in, "on")
	out := Review{RepoLoc: pr.RepoRef(), Number: pr.Number}
	client, timeout, live, err := awaitStart(s, pr.RepoRef(), p.Timeout,
		fmt.Sprintf("an approval or change request on %s/%s#%d", pr.Owner, pr.Repo, pr.Number))
	if err != nil || !live {
		return out, err
	}
	if pr.Number == 0 {
		return out, errors.New("no pull request to watch")
	}

	cur := newPRCursor(pr, "a review decision")
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d", pr.Owner, pr.Repo, pr.Number)
	found, err := poll(ctx, reviewPollInterval, timeout, s.Checkpoint,
		func(ctx context.Context) (reviewBody, bool, any, error) {
			cur.Polls++
			cur.At = engine.IsoformatUTC(time.Now())
			reviews, err := listReviews(ctx, client, path)
			if err != nil {
				return reviewBody{}, false, cur, err
			}
			var decisive reviewBody
			states := make([]string, 0, len(reviews))
			for _, rb := range reviews {
				states = append(states, rb.User.Login+":"+rb.State)
				if rb.State == "APPROVED" || rb.State == "CHANGES_REQUESTED" {
					decisive = rb
				}
			}
			cur.Seen = fmt.Sprintf("%d review(s) [%s]", len(reviews), strings.Join(states, " "))
			return decisive, decisive.ID != 0, cur, nil
		})
	if errors.Is(err, errTimedOut) {
		s.MarkEmpty(fmt.Sprintf("no approval or change request arrived within %s: %s", timeout, cur.Seen))
		return out, nil
	}
	if err != nil {
		return out, err
	}

	out.ID, out.State, out.Reviewer, out.CommitSHA = found.ID, found.State, found.User.Login, found.CommitID
	if head, err := prHead(ctx, client, path); err != nil {
		out.Stale = Unmeasured(fmt.Sprintf("the head of #%d is unreadable (%s), so the commit review %d covers could not be compared with it",
			pr.Number, apiMessage(err), found.ID))
	} else {
		out.Stale = staleness(pr.Number, found.ID, head, found.CommitID)
	}
	if why := out.Stale.Reason; why != "" {
		s.Note(why + "; stale is recorded as unestablished rather than false, because false is what a review that does cover the head looks like")
	}
	return out, nil
}

// staleness answers whether a review covers the head it was read against. Either
// side of the comparison can be missing, and the answer is then unestablished
// rather than false — false is the reading that says an approval is still valid.
func staleness(prNumber int, reviewID int64, head, reviewCommit string) Measurement {
	switch {
	case head == "":
		return Unmeasured(fmt.Sprintf("#%d reports no head sha, so there was nothing to compare review %d against", prNumber, reviewID))
	case reviewCommit == "":
		return Unmeasured(fmt.Sprintf("review %d names no commit, so there was nothing to compare with the head of #%d", reviewID, prNumber))
	}
	return Measured(reviewCommit != head)
}

type prMergeAwaitParams struct {
	Timeout string `yaml:"timeout"`
}

func prMergeAwait(ctx context.Context, s *Session, p prMergeAwaitParams, in Inputs) (PullRequest, error) {
	pr := In[PullRequest](in, "on")
	client, timeout, live, err := awaitStart(s, pr.RepoRef(), p.Timeout,
		fmt.Sprintf("%s/%s#%d to merge or close", pr.Owner, pr.Repo, pr.Number))
	if err != nil || !live {
		return pr, err
	}
	if pr.Number == 0 {
		return pr, errors.New("no pull request to watch")
	}

	cur := newPRCursor(pr, "a merge or a close")
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d", pr.Owner, pr.Repo, pr.Number)
	found, err := poll(ctx, mergePollInterval, timeout, s.Checkpoint,
		func(ctx context.Context) (prBody, bool, any, error) {
			cur.Polls++
			cur.At = engine.IsoformatUTC(time.Now())
			body, err := readPR(ctx, client, path)
			if err != nil {
				return prBody{}, false, cur, err
			}
			cur.Seen = fmt.Sprintf("state=%s merged=%t", body.State, body.Merged)
			return body, body.State == "closed", cur, nil
		})
	if errors.Is(err, errTimedOut) {
		s.MarkEmpty(fmt.Sprintf("pull request #%d did not merge or close within %s: %s", pr.Number, timeout, cur.Seen))
		return pr, nil
	}
	if err != nil {
		return pr, err
	}
	if found.Merged {
		s.Note(fmt.Sprintf("pull request #%d merged; a merge has no inverse", pr.Number))
	}
	return found.handle(pr.RepoRef()), nil
}

type prMergeabilityAwaitParams struct {
	Timeout string `yaml:"timeout"`
}

// prMergeabilityAwait exists because mergeable/mergeable_state are computed
// asynchronously: the first read returns null and schedules the computation, so
// a plan that reads once and branches on the answer is racing.
func prMergeabilityAwait(ctx context.Context, s *Session, p prMergeabilityAwaitParams, in Inputs) (Mergeability, error) {
	pr := In[PullRequest](in, "on")
	out := Mergeability{RepoLoc: pr.RepoRef(), Number: pr.Number}
	client, timeout, live, err := awaitStart(s, pr.RepoRef(), p.Timeout,
		fmt.Sprintf("GitHub to compute mergeability of %s/%s#%d", pr.Owner, pr.Repo, pr.Number))
	if err != nil || !live {
		return out, err
	}
	if pr.Number == 0 {
		return out, errors.New("no pull request to watch")
	}

	cur := newPRCursor(pr, "a computed mergeable")
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d", pr.Owner, pr.Repo, pr.Number)
	found, err := poll(ctx, mergeabilityPollInterval, timeout, s.Checkpoint,
		func(ctx context.Context) (prBody, bool, any, error) {
			cur.Polls++
			cur.At = engine.IsoformatUTC(time.Now())
			body, err := readPR(ctx, client, path)
			if err != nil {
				return prBody{}, false, cur, err
			}
			cur.Seen = fmt.Sprintf("state=%s mergeable_state=%s computed=%t", body.State, body.MergeableState, body.Mergeable != nil)
			// mergeable is the documented signal: null means the background job is
			// still running and the read that returned it scheduled the work. Waiting
			// on mergeable_state as well would poll to timeout on a pull request whose
			// mergeability was computed, because that field carries no documented value
			// set at all — "clean" appears only in an example.
			return body, body.Mergeable != nil || body.State == "closed", cur, nil
		})
	if errors.Is(err, errTimedOut) {
		s.MarkEmpty(fmt.Sprintf("mergeability of #%d was still uncomputed after %s: %s", pr.Number, timeout, cur.Seen))
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.MergeableState = found.MergeableState
	out.Mergeable = found.Mergeable != nil && *found.Mergeable
	// Any unrecognised mergeable_state is treated as not clean: the value set is
	// not guaranteed stable, and "not clean" is the safe reading for a gate.
	out.Clean = found.MergeableState == "clean"
	out.Computed = found.Mergeable != nil
	return out, nil
}

func readPR(ctx context.Context, c github.GitHub, path string) (prBody, error) {
	raw, _, err := c.Get(ctx, path, nil, false)
	if err != nil {
		return prBody{}, err
	}
	var body prBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return prBody{}, err
	}
	return body, nil
}

// listReviews drops an item that does not parse instead of failing the whole
// read: one malformed review must not decide whether a chain sees an approval.
func listReviews(ctx context.Context, c github.GitHub, path string) ([]reviewBody, error) {
	items, err := c.Paginate(ctx, path+"/reviews", url.Values{"per_page": []string{"100"}}, 100)
	if err != nil {
		return nil, err
	}
	out := make([]reviewBody, 0, len(items))
	for _, item := range items {
		var rb reviewBody
		if err := json.Unmarshal(item, &rb); err != nil {
			continue
		}
		out = append(out, rb)
	}
	return out, nil
}

func prHead(ctx context.Context, c github.GitHub, path string) (string, error) {
	body, err := readPR(ctx, c, path)
	if err != nil {
		return "", err
	}
	return body.Head.SHA, nil
}

type reviewBody struct {
	ID       int64  `json:"id"`
	State    string `json:"state"`
	CommitID string `json:"commit_id"`
	User     struct {
		Login string `json:"login"`
	} `json:"user"`
	SubmittedAt string `json:"submitted_at"`
}

type prOpenParams struct {
	Title   string `yaml:"title"`
	Body    string `yaml:"body"`
	BaseRef string `yaml:"base_ref"`
	Draft   bool   `yaml:"draft"`
}

// prOpen is the one legitimately cross-repository primitive: a fork pull request
// has its head and its base in different repositories. It detects an existing
// open pull request by head rather than opening a second one.
func prOpen(ctx context.Context, s *Session, p prOpenParams, in Inputs) (PullRequest, error) {
	headHandle := In[WritableRef](in, "head")
	head := headHandle.WriteRef()
	baseHandle := In[RepoScoped](in, "base")
	base := baseHandle.RepoRef()

	if p.Title == "" {
		return PullRequest{}, errors.New("pr.open needs a title")
	}
	branch := strings.TrimPrefix(head.Ref, "refs/heads/")
	label := branch
	if head.Owner != base.Owner {
		label = head.Owner + ":" + branch
	}
	baseRef := p.BaseRef
	if baseRef == "" {
		var err error
		if baseRef, err = defaultBranch(ctx, s, baseHandle); err != nil {
			return PullRequest{}, err
		}
	}
	pr := PullRequest{
		IssueLoc:  IssueLoc{Owner: base.Owner, Repo: base.Repo},
		Head:      branch,
		HeadLabel: label,
		Base:      baseRef,
		State:     "open",
	}

	client, err := s.Client()
	if err != nil && s.Execute {
		return PullRequest{}, err
	}
	// The response spells a head as owner:branch whether or not the create body
	// did, so every read of it below uses that form.
	headLabel := head.Owner + ":" + branch
	if client != nil {
		existing, mine, err := findOpenPR(ctx, client, base, headLabel, baseRef)
		if err := s.SoftRead(err, "list pull requests"); err != nil {
			return PullRequest{}, err
		}
		if mine {
			s.Note(fmt.Sprintf("adopted pull request #%d: it is open from %s into %s, so it is the one this step would have opened and nothing was created",
				existing.Number, headLabel, baseRef))
			return existing.handle(base), nil
		}
	}

	raw, _, err := s.Mutate(ctx, Mutation{
		Method: http.MethodPost,
		Path:   fmt.Sprintf("/repos/%s/%s/pulls", base.Owner, base.Repo),
		Body: map[string]any{
			"title": p.Title, "body": p.Body, "head": label, "base": baseRef, "draft": p.Draft,
		},
		Target: base.Owner + "/" + base.Repo,
		Note:   "creates refs/pull/N/head on the base, which persists after the pull request is closed",
		InverseFrom: func(raw json.RawMessage) []UndoStep {
			var made prBody
			if err := json.Unmarshal(raw, &made); err != nil || made.Number == 0 {
				return nil
			}
			return prCloseUndo(base, made.Number)
		},
		// The same read the adopt above already made, which found nothing: head and
		// base are a unique key for an open pull request, so one standing there now
		// is the one this call created.
		ReadBack: func(ctx context.Context) ([]UndoStep, error) {
			client, err := s.Client()
			if err != nil {
				return nil, err
			}
			existing, mine, err := findOpenPR(ctx, client, base, headLabel, baseRef)
			if err != nil || !mine {
				return nil, err
			}
			return prCloseUndo(base, existing.Number), nil
		},
	})
	if err != nil {
		return pr, err
	}
	var made prBody
	if err := json.Unmarshal(raw, &made); err != nil {
		return pr, err
	}
	out := made.handle(base)
	out.Head, out.HeadLabel, out.Base = cmp.Or(out.Head, branch), cmp.Or(out.HeadLabel, label), cmp.Or(out.Base, baseRef)
	return out, nil
}

func findOpenPR(ctx context.Context, c github.GitHub, base RepoLoc, headLabel, baseRef string) (prBody, bool, error) {
	params := url.Values{"state": []string{"open"}, "head": []string{headLabel}, "per_page": []string{"100"}}
	items, err := c.Paginate(ctx, fmt.Sprintf("/repos/%s/%s/pulls", base.Owner, base.Repo), params, 100)
	if err != nil {
		return prBody{}, false, err
	}
	existing, mine := adoptablePR(items, headLabel, baseRef)
	return existing, mine, nil
}

func prCloseUndo(base RepoLoc, number int) []UndoStep {
	return []UndoStep{{
		Method:  http.MethodPatch,
		Path:    fmt.Sprintf("/repos/%s/%s/pulls/%d", base.Owner, base.Repo, number),
		Body:    map[string]any{"state": "closed"},
		Note:    "closes but does not delete: the number, the timeline and any runs it triggered persist",
		Partial: true,
	}}
}

// adoptablePR picks the open pull request this step would otherwise have opened.
// The head and the base are checked here rather than trusted to the server-side
// head= filter: a pull request from the same head into a different base is not
// the one this chain wants, and adopting whatever the filter returned would hand
// the rest of the chain somebody else's pull request to measure.
func adoptablePR(items []json.RawMessage, headLabel, baseRef string) (prBody, bool) {
	for _, item := range items {
		var existing prBody
		if err := json.Unmarshal(item, &existing); err != nil || existing.Number == 0 {
			continue
		}
		if existing.State == "open" && existing.Head.Label == headLabel && existing.Base.Ref == baseRef {
			return existing, true
		}
	}
	return prBody{}, false
}

type prCloseParams struct{}

func prClose(ctx context.Context, s *Session, _ prCloseParams, in Inputs) (PullRequest, error) {
	pr := In[PullRequest](in, "pr")
	if pr.Number == 0 {
		if s.Execute {
			return pr, errors.New("no pull request to close")
		}
		s.Note("the pull request this closes was rendered, not created, so the request renders with number 0")
	}
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d", pr.Owner, pr.Repo, pr.Number)

	client, err := s.Client()
	if err != nil && s.Execute {
		return pr, err
	}
	if client != nil && pr.Number != 0 {
		raw, _, err := client.Get(ctx, path, nil, false)
		if err := s.SoftRead(err, "read pull request"); err != nil {
			return pr, err
		}
		var current prBody
		if err := json.Unmarshal(raw, &current); err == nil && current.State == "closed" {
			s.Note("pull request is already closed, so nothing was sent")
			return current.handle(pr.RepoRef()), nil
		}
	}

	if _, _, err := s.Mutate(ctx, Mutation{
		Method: http.MethodPatch, Path: path, Body: map[string]any{"state": "closed"},
		Target: pr.Owner + "/" + pr.Repo,
		Note:   "the pull request closes; any runs it triggered already happened",
		Inverse: []UndoStep{{
			Method: http.MethodPatch, Path: path, Body: map[string]any{"state": "open"},
			Note: "reopens the pull request, restoring the state this run found it in; GitHub refuses it once the head ref " +
				"is gone, and a refusal is reported as a failed reversal rather than assumed here",
		}},
	}); err != nil {
		return pr, err
	}
	pr.State = "closed"
	return pr, nil
}

// prReviewState is a one-shot read rather than a wait: it answers whether an
// approval is standing right now. mergeability cannot answer it, because
// mergeable_state collapses a dismissed approval and an unsatisfied required
// check into the same "blocked" — and a chain that has itself replaced the
// repository's workflow set would be reading its own side effect out of it.
//
// The handle carries dismiss_stale_reviews beside the decision because whether
// an approval survives a later push is the repository's setting, not a property
// of the review.
func prReviewState(ctx context.Context, s *Session, _ prReviewStateParams, in Inputs) (ReviewState, error) {
	pr := In[PullRequest](in, "on")
	out := ReviewState{RepoLoc: pr.RepoRef(), Reviews: []Review{}}

	client, err := s.Client()
	if err != nil {
		if err := s.SoftRead(err, "read review state"); err != nil {
			return ReviewState{}, err
		}
		return out, nil
	}
	if pr.Number == 0 {
		if s.Execute {
			return ReviewState{}, errors.New("no pull request to read reviews from")
		}
		s.MarkEmpty("the pull request these reviews belong to was rendered, not created, so it has no number yet")
		return out, nil
	}

	path := fmt.Sprintf("/repos/%s/%s/pulls/%d", pr.Owner, pr.Repo, pr.Number)
	current, err := readPR(ctx, client, path)
	if err := s.SoftRead(err, "read pull request"); err != nil {
		return ReviewState{}, err
	}
	head := current.Head.SHA
	base := cmp.Or(current.Base.Ref, pr.Base)

	reviews, err := listReviews(ctx, client, path)
	if err != nil {
		if softFail(s, err, "reviews") {
			return out, nil
		}
		return ReviewState{}, err
	}

	if head == "" && len(reviews) > 0 {
		s.Note(fmt.Sprintf("the head of #%d could not be read, so no review below carries a stale reading at all: there was no commit to compare them against, and false is what a review that does cover the head looks like",
			pr.Number))
	}

	standing := map[string]string{}
	for _, rb := range reviews {
		stale := staleness(pr.Number, rb.ID, head, rb.CommitID)
		if head != "" && !stale.Known {
			s.Note(stale.Reason + "; its stale is unestablished rather than false")
		}
		out.Reviews = append(out.Reviews, Review{
			RepoLoc:   pr.RepoRef(),
			Number:    pr.Number,
			ID:        rb.ID,
			State:     rb.State,
			Reviewer:  rb.User.Login,
			CommitSHA: rb.CommitID,
			Stale:     stale,
			Dismissed: rb.State == "DISMISSED",
		})
		if rb.State != "COMMENTED" {
			standing[rb.User.Login] = rb.State
		}
	}
	out.ReviewDecision = reviewDecision(standing)
	out.DismissStaleReviews = dismissStaleReviews(ctx, s, client, pr.RepoRef(), base)
	return out, nil
}

// reviewDecision derives the aggregate decision REST does not expose: a
// reviewer's latest non-COMMENTED review is their standing, a dismissal clears
// it, and one outstanding change request outranks any number of approvals. An
// approval left standing against an older commit still reads APPROVED — that it
// is stale is a separate fact, and conflating the two would hide the very
// window this record exists to measure.
func reviewDecision(standing map[string]string) string {
	approved := false
	for _, state := range standing {
		switch state {
		case "CHANGES_REQUESTED":
			return "CHANGES_REQUESTED"
		case "APPROVED":
			approved = true
		}
	}
	if approved {
		return "APPROVED"
	}
	return "REVIEW_REQUIRED"
}

// dismissStaleReviews answers whether an approval survives a later push, which
// two independent surfaces can enforce. A branch protection rule is one; a ruleset
// is the other, and a branch a ruleset gates answers 404 on the protection
// endpoint — so reading that 404 alone as "nothing dismisses an approval" tells
// the customer a gate they have is absent, on exactly the fact a stale-approval
// chain rests on. Both are read and the answers combined.
//
// They are notes rather than empty marks because the step around this read
// produces a populated review state either way.
func dismissStaleReviews(ctx context.Context, s *Session, client github.GitHub, loc RepoLoc, branch string) Measurement {
	if branch == "" {
		why := "the pull request names no base branch, so dismiss_stale_reviews could not be read"
		s.Note(why)
		return Unmeasured(why)
	}
	out := combineDismissal(
		protectionDismissal(ctx, client, loc, branch),
		rulesetDismissal(ctx, client, loc, branch),
	)
	if why := out.Reason; why != "" {
		s.Note(why + "; dismiss_stale_reviews is recorded as unestablished rather than off, because off is what a base " +
			"branch that keeps an approval across a push looks like")
	}
	return out
}

// combineDismissal takes the two surfaces together. Either one enforcing
// dismissal settles it, so a positive needs no agreement from the other; a
// negative needs both to have been read, because a surface nobody could read
// cannot be the difference between an approval that survives a push and one that
// does not.
func combineDismissal(protection, ruleset Measurement) Measurement {
	switch {
	case protection.Known && protection.Value, ruleset.Known && ruleset.Value:
		return Measured(true)
	case protection.Known && ruleset.Known:
		return Measured(false)
	case !protection.Known && !ruleset.Known:
		return Unmeasured(protection.Reason + ", and " + ruleset.Reason)
	case !protection.Known:
		return Unmeasured(protection.Reason)
	default:
		return Unmeasured(ruleset.Reason)
	}
}

// protectionDismissal reads the classic branch protection rule. 404 is the only
// documented answer besides 200 and is what a branch carrying no protection rule
// returns, so it is a reading of this surface; anything else — the read needs
// administration:read, which most engagement credentials do not hold — is not.
func protectionDismissal(ctx context.Context, client github.GitHub, loc RepoLoc, branch string) Measurement {
	raw, _, err := client.Get(ctx, fmt.Sprintf("/repos/%s/%s/branches/%s/protection", loc.Owner, loc.Repo, branch), nil, false)
	if err != nil {
		if statusOf(err) == http.StatusNotFound {
			return Measured(false)
		}
		return Unmeasured(fmt.Sprintf("the branch protection rule on %q is unreadable (%s), and the read needs administration:read", branch, apiMessage(err)))
	}
	var body struct {
		RequiredPullRequestReviews struct {
			DismissStaleReviews bool `json:"dismiss_stale_reviews"`
		} `json:"required_pull_request_reviews"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return Unmeasured(fmt.Sprintf("the branch protection rule on %q did not parse, so its dismiss_stale_reviews was never read: %s", branch, err))
	}
	return Measured(body.RequiredPullRequestReviews.DismissStaleReviews)
}

// rulesetDismissal reads the other surface. This endpoint needs only metadata
// read, returns the rules of every active ruleset that applies at any level, and
// is the only place a ruleset-enforced dismissal appears at all.
func rulesetDismissal(ctx context.Context, client github.GitHub, loc RepoLoc, branch string) Measurement {
	items, err := client.Paginate(ctx, fmt.Sprintf("/repos/%s/%s/rules/branches/%s", loc.Owner, loc.Repo, branch),
		url.Values{"per_page": []string{"100"}}, 100)
	if err != nil {
		return Unmeasured(fmt.Sprintf("the rulesets that apply to %q are unreadable (%s)", branch, apiMessage(err)))
	}
	return dismissalFromRules(items)
}

// dismissalFromRules reads the pull_request rules of the active rulesets. A
// ruleset that requires no pull request review dismisses none, so no pull_request
// rule at all is an answer rather than a gap; a pull_request rule carrying no
// dismiss_stale_reviews_on_push is not.
func dismissalFromRules(items []json.RawMessage) Measurement {
	silent := ""
	for _, item := range items {
		var rule struct {
			Type       string `json:"type"`
			Source     string `json:"ruleset_source"`
			RulesetID  int64  `json:"ruleset_id"`
			Parameters struct {
				DismissStaleReviewsOnPush *bool `json:"dismiss_stale_reviews_on_push"`
			} `json:"parameters"`
		}
		if err := json.Unmarshal(item, &rule); err != nil || rule.Type != "pull_request" {
			continue
		}
		switch {
		case rule.Parameters.DismissStaleReviewsOnPush == nil:
			silent = fmt.Sprintf("the pull_request rule from ruleset %d (%s) declares no dismiss_stale_reviews_on_push",
				rule.RulesetID, cmp.Or(rule.Source, "source unnamed"))
		case *rule.Parameters.DismissStaleReviewsOnPush:
			return Measured(true)
		}
	}
	if silent != "" {
		return Unmeasured(silent)
	}
	return Measured(false)
}

// reviewStates maps the event a plan asks for onto the state the submitted
// review will carry, which is what a downstream when: reads off the handle.
var reviewStates = map[string]string{
	"APPROVE":         "APPROVED",
	"REQUEST_CHANGES": "CHANGES_REQUESTED",
	"COMMENT":         "COMMENTED",
}

func prReviewSubmit(ctx context.Context, s *Session, p prReviewSubmitParams, in Inputs) (Review, error) {
	pr := In[PullRequest](in, "pr")
	event := strings.ToUpper(strings.TrimSpace(p.Decision))
	state, known := reviewStates[event]
	if !known {
		return Review{}, fmt.Errorf("decision %q must be APPROVE, REQUEST_CHANGES or COMMENT", p.Decision)
	}
	if event != "APPROVE" && strings.TrimSpace(p.Body) == "" {
		return Review{}, fmt.Errorf("a %s review must set a body; GitHub rejects one without", event)
	}
	if pr.Number == 0 && s.Execute {
		return Review{}, errors.New("no pull request to review")
	}
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d", pr.Owner, pr.Repo, pr.Number)
	out := Review{RepoLoc: pr.RepoRef(), Number: pr.Number, State: state, Reviewer: s.Login()}

	commitID := ""
	if c, bound := InOpt[Commit](in, "commit"); bound {
		commitID = c.SHA
	}

	author := ""
	client, err := s.Client()
	if err != nil && s.Execute {
		return Review{}, err
	}
	// api is the interface rather than the concrete client so that "no client" stays
	// a nil interface: a typed nil handed to the guard below would read as present.
	var api github.GitHub
	var priorReviews []int64
	if client != nil {
		api = client
		current, err := readPR(ctx, api, path)
		if err := s.SoftRead(err, "read pull request"); err != nil {
			return Review{}, err
		}
		author = current.User.Login
		if commitID == "" {
			commitID = current.Head.SHA
		}
		// The reviews already standing are the baseline a read-back has to compare
		// against: a review names its author and nothing else, and an installation
		// token — the class GITHUB_TOKEN belongs to — reports no login to match that
		// against, so being absent beforehand is the only thing that attributes one.
		prior, err := listReviews(ctx, api, path)
		if err := s.SoftRead(err, "list reviews"); err != nil {
			return Review{}, fmt.Errorf("the reviews already on #%d are the baseline that names this call's own review if its answer never comes: %w", pr.Number, err)
		}
		for _, rb := range prior {
			priorReviews = append(priorReviews, rb.ID)
		}
	}
	// commit_id is sent on every submission: a review posted without one attaches
	// to whatever the head is at that instant, so an approval this chain measures
	// could silently cover a commit nobody named.
	if commitID == "" {
		if s.Execute {
			return Review{}, errors.New("no commit to attach the review to: bind commit: or make the pull request's head readable")
		}
		commitID = plannedSHA
	}
	if err := selfReviewGuard(ctx, s, api, event, author, pr); err != nil {
		return Review{}, err
	}
	out.CommitSHA = commitID

	body := map[string]any{"commit_id": commitID, "event": event}
	if p.Body != "" {
		body["body"] = p.Body
	}
	raw, _, err := s.Mutate(ctx, Mutation{
		Method: http.MethodPost,
		Path:   path + "/reviews",
		Body:   body,
		Target: pr.Owner + "/" + pr.Repo,
		Note:   "fires pull_request_review and delivers review notifications immediately; a submitted review can only be dismissed, never deleted",
		InverseFrom: func(raw json.RawMessage) []UndoStep {
			return reviewDismissal(path, event, raw)
		},
		ReadBack: reviewReadBack(s, path, event, commitID, state, priorReviews),
	})
	if err != nil {
		return out, err
	}
	var made reviewBody
	if err := json.Unmarshal(raw, &made); err != nil {
		return out, err
	}
	out.ID = made.ID
	out.State = cmp.Or(made.State, state)
	out.Reviewer = cmp.Or(made.User.Login, out.Reviewer)
	out.CommitSHA = cmp.Or(made.CommitID, commitID)
	return out, nil
}

// reviewDismissal is the inverse of a submitted review, resolved once the review
// id exists. It is real but partial: dismissal sets the state to DISMISSED and
// leaves the review, its body and its author on the timeline permanently, so an
// approval is never actually withdrawn. A COMMENT review has no inverse at all —
// the dismissal endpoint rejects one — and recording a request that must fail
// would report an honest "irreversible" as a failed reversal instead.
func reviewDismissal(path, event string, raw json.RawMessage) []UndoStep {
	if event == "COMMENT" {
		return nil
	}
	var made reviewBody
	if err := json.Unmarshal(raw, &made); err != nil || made.ID == 0 {
		return nil
	}
	return reviewDismissUndo(path, made.ID)
}

func reviewDismissUndo(path string, id int64) []UndoStep {
	return []UndoStep{{
		Method: http.MethodPut,
		Path:   fmt.Sprintf("%s/reviews/%d/dismissals", path, id),
		Body:   map[string]any{"message": "dismissed by trajan cleanup", "event": "DISMISS"},
		Note: "sets the review's state to DISMISSED; the review, its body and its author stay on the timeline permanently, " +
			"and anything the submission already triggered still happened",
		Partial: true,
	}}
}

// reviewReadBack names the review a submission whose answer never came may have
// left. A review carries nothing that identifies the credential that submitted
// it, so the discriminator is threefold: the commit this call named, the state it
// asked for, and absence from the reviews read off the pull request beforehand.
// Two candidates are no answer — dismissing the wrong one of a pair would leave
// this run's own approval standing — and a COMMENT review gets no read-back at
// all, because there is no inverse for one to record.
func reviewReadBack(s *Session, path, event, commitID, state string, prior []int64) func(context.Context) ([]UndoStep, error) {
	if event == "COMMENT" {
		return nil
	}
	return func(ctx context.Context) ([]UndoStep, error) {
		client, err := s.Client()
		if err != nil {
			return nil, err
		}
		reviews, err := listReviews(ctx, client, path)
		if err != nil {
			return nil, err
		}
		login := s.Login()
		var mine []reviewBody
		for _, rb := range reviews {
			if rb.ID == 0 || slices.Contains(prior, rb.ID) {
				continue
			}
			if rb.CommitID != commitID || rb.State != state {
				continue
			}
			if login != "" && rb.User.Login != login {
				continue
			}
			mine = append(mine, rb)
		}
		switch len(mine) {
		case 0:
			return nil, nil
		case 1:
			return reviewDismissUndo(path, mine[0].ID), nil
		}
		return nil, fmt.Errorf("%d reviews carrying %s on %s appeared on %s since the call, so which of them it submitted cannot be told apart",
			len(mine), state, shortSHA(commitID), path)
	}
}

// selfReviewGuard refuses locally what would be refused on the customer's system:
// a rejected approval is a 4xx in their audit log that produces no evidence. It
// keys on the credential's class, because the two classes are refused for
// unrelated reasons — a user is refused for authoring the pull request, an Actions
// credential by a repository setting that has nothing to do with authorship. An
// unclassifiable credential is treated as a user: failing here costs nothing.
//
// GitHub's refusal of a user's approval of their own pull request is real but is
// documented nowhere — not on the reviews endpoint, whose only relevant answers
// are a bare 403 and a 422 that reads "Validation failed, or the endpoint has been
// spammed" — so it is not stated here as documented behaviour.
func selfReviewGuard(ctx context.Context, s *Session, client github.GitHub, event, author string, pr PullRequest) error {
	if event != "APPROVE" {
		return nil
	}
	switch s.ActingKind() {
	case kindAppInstallation, kindOIDC:
		if client == nil {
			s.Note(fmt.Sprintf("nothing was read, so whether %s/%s allows GitHub Actions to approve pull requests is unestablished; the acting %s credential is a principal distinct from the author %s, but that setting is what decides whether it may approve at all",
				pr.Owner, pr.Repo, s.ActingKind(), cmp.Or(author, "of the pull request")))
			return nil
		}
		return actionsApprovalGuard(ctx, s, client, author, pr)
	}
	if login := s.Login(); login != "" && login == author {
		return fmt.Errorf("identity %q is the user %q who authored %s/%s#%d, and GitHub refuses a user's approval of their own pull request: "+
			"this plan named one identity where the chain needs two — declare a second under identities: and name it in this step's as:",
			s.ActingName(), login, pr.Owner, pr.Repo, pr.Number)
	}
	return nil
}

// actionsApprovalGuard reads the setting instead of assuming authorship is what
// decides. An Actions credential is a principal distinct from the author, so it is
// not refused for authoring anything — but GITHUB_TOKEN is an App installation
// token, and "Allow GitHub Actions to create and approve pull requests" decides
// whether it may approve at all. That setting is off by default on a repository
// created in a personal account, so an approval sent without reading it fails on
// the customer's system rather than here. The state is itself worth reporting: it
// is the configuration that decides whether this weakness class is reachable.
func actionsApprovalGuard(ctx context.Context, s *Session, client github.GitHub, author string, pr PullRequest) error {
	kind, distinct := s.ActingKind(), cmp.Or(author, "of the pull request")
	allowed, err := actionsCanApprove(ctx, client, pr.RepoRef())
	switch {
	case err != nil:
		s.Note(fmt.Sprintf("whether %s/%s allows GitHub Actions to approve pull requests is unreadable (%s), and the read needs administration:read, so it is unestablished rather than assumed: the acting %s credential is a principal distinct from the author %s, but that setting is what decides whether it may approve at all",
			pr.Owner, pr.Repo, apiMessage(err), kind, distinct))
	case !allowed:
		return fmt.Errorf("%s/%s reports can_approve_pull_request_reviews false — \"Allow GitHub Actions to create and approve pull requests\" is off, which is the default for a repository created in a personal account — and the acting %s credential is the class GITHUB_TOKEN belongs to, so this approval would be refused on the customer's system and establishes nothing there. Name a user identity in this step's as:, or record the setting as the control that already blocks this chain",
			pr.Owner, pr.Repo, kind)
	default:
		s.Note(fmt.Sprintf("%s/%s allows GitHub Actions to create and approve pull requests, and the acting %s credential is a principal distinct from the author %s, so neither the setting nor authorship refuses this approval",
			pr.Owner, pr.Repo, kind, distinct))
	}
	return nil
}

func actionsCanApprove(ctx context.Context, client github.GitHub, loc RepoLoc) (bool, error) {
	raw, _, err := client.Get(ctx, fmt.Sprintf("/repos/%s/%s/actions/permissions/workflow", loc.Owner, loc.Repo), nil, false)
	if err != nil {
		return false, err
	}
	var body struct {
		CanApprovePullRequestReviews bool `json:"can_approve_pull_request_reviews"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return false, err
	}
	return body.CanApprovePullRequestReviews, nil
}

// The sha a merge guards on is only the commit a review covered when a plan bound
// one. Read back off the pull request seconds before the call, it is whatever the
// head was at that instant and no review is attached to it, so the evidence says
// which of the two it was rather than calling both "the reviewed commit".
const (
	guardBound    = "the commit bound to expected:"
	guardReadBack = "the head this run read off the pull request immediately before the merge, which no review is tied to"
	guardRendered = "a rendered placeholder: no head was read, and nothing was sent"
)

// prMerge has no inverse and writes none. Force-updating the base back to its
// pre-merge sha is refused by non_fast_forward or required_linear_history on any
// protected base, and a revert is a new commit rather than a restoration — so
// the ledger records the call with no undo, which is what puts it in cleanup's
// irreversible bucket instead of implying it was reversed.
func prMerge(ctx context.Context, s *Session, p prMergeParams, in Inputs) (Commit, error) {
	pr := In[PullRequest](in, "pr")
	method := cmp.Or(p.Method, "merge")
	switch method {
	case "merge", "squash", "rebase":
	default:
		return Commit{}, fmt.Errorf("method %q must be merge, squash or rebase", method)
	}
	if pr.Number == 0 && s.Execute {
		return Commit{}, errors.New("no pull request to merge")
	}
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d", pr.Owner, pr.Repo, pr.Number)
	out := Commit{RefLoc: RefLoc{Owner: pr.Owner, Repo: pr.Repo}}
	base := pr.Base

	expected, guardedOn := "", ""
	if c, bound := InOpt[Commit](in, "expected"); bound && c.SHA != "" {
		expected, guardedOn = c.SHA, guardBound
	}

	client, err := s.Client()
	if err != nil && s.Execute {
		return Commit{}, err
	}
	if client != nil {
		current, err := readPR(ctx, client, path)
		if err := s.SoftRead(err, "read pull request"); err != nil {
			return Commit{}, err
		}
		base = cmp.Or(current.Base.Ref, base)
		if current.Merged {
			s.Note(fmt.Sprintf("pull request #%d is already merged as %s", pr.Number, shortSHA(current.MergeCommitSHA)))
			out.SHA, out.Ref = current.MergeCommitSHA, headRef(base)
			return out, nil
		}
		if current.State == "closed" {
			s.MarkEmpty(fmt.Sprintf("pull request #%d is closed and unmerged, so there is nothing to merge", pr.Number))
			return out, nil
		}
		if expected == "" {
			expected, guardedOn = current.Head.SHA, guardReadBack
		}
	}
	if expected == "" {
		if s.Execute {
			return Commit{}, errors.New("refusing to merge without an expected head sha: bind expected: or make the pull request's head readable")
		}
		expected, guardedOn = plannedSHA, guardRendered
	}
	out.Ref = headRef(base)

	raw, status, err := s.Mutate(ctx, Mutation{
		Method: http.MethodPut,
		Path:   path + "/merge",
		Body:   map[string]any{"merge_method": method, "sha": expected},
		Target: pr.Owner + "/" + pr.Repo,
		Note: "a merge has no inverse: restoring the base needs a force-update a protected branch refuses, " +
			"and a revert is an additional commit rather than a restoration",
	})
	switch {
	case err == nil:
	case status == http.StatusMethodNotAllowed:
		s.MarkEmpty(fmt.Sprintf("GitHub refused the merge as not mergeable (HTTP 405), so nothing was merged: %s", apiMessage(err)))
		return out, nil
	case status == http.StatusConflict:
		s.MarkEmpty(fmt.Sprintf("the expected-head guard refused the merge (HTTP 409): %s is no longer the head of #%d, so nothing was merged and what would have landed is not what this run guarded on — %s. The guard sha was %s",
			shortSHA(expected), pr.Number, apiMessage(err), guardedOn))
		return out, nil
	default:
		return out, err
	}

	var made struct {
		SHA    string `json:"sha"`
		Merged bool   `json:"merged"`
	}
	if err := json.Unmarshal(raw, &made); err != nil {
		return out, err
	}
	// squash and rebase rewrite the commits, so the merged sha is a commit no
	// review ever saw: it is read back off the response rather than assumed.
	out.SHA = made.SHA
	// The effect record hangs off GitHub's own merged:true rather than off the
	// status, so a dry run's synthetic response never lands a consequence in the
	// ledger that this run did not cause.
	if !made.Merged {
		return out, nil
	}
	out.MergedAt = engine.IsoformatUTC(time.Now())
	summary := fmt.Sprintf("pull request #%d was merged into %s of %s/%s as %s by %s method; a merge cannot be undone",
		pr.Number, base, pr.Owner, pr.Repo, shortSHA(made.SHA), method)
	if method != "merge" {
		summary += fmt.Sprintf(", and %s rewrote the commits, so %s — %s — is not in the base's history",
			method, shortSHA(expected), guardedOn)
	}
	if err := s.RecordEffect(Effect{
		Class:   "merge",
		Summary: summary,
		Detail: map[string]any{
			"repository":           pr.Owner + "/" + pr.Repo,
			"pull_request":         pr.Number,
			"base":                 base,
			"merge_method":         method,
			"expected_head":        expected,
			"expected_head_source": guardedOn,
			"merged_sha":           made.SHA,
		},
	}); err != nil {
		return out, err
	}
	return out, nil
}

func headRef(branch string) string {
	if branch == "" {
		return ""
	}
	return "refs/heads/" + branch
}

// apiMessage is GitHub's own explanation of a refusal, which is the part of a
// 405 or a 409 the operator needs; GhError.Error() buries it behind the status
// and the request URL.
func apiMessage(err error) string {
	var ghErr *github.GhError
	if errors.As(err, &ghErr) {
		if msg, ferr := field(json.RawMessage(ghErr.Body), "message"); ferr == nil && msg != "" {
			return msg
		}
	}
	return err.Error()
}

type prBody struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	Head   struct {
		Ref   string `json:"ref"`
		Label string `json:"label"`
		SHA   string `json:"sha"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
	User struct {
		Login string `json:"login"`
	} `json:"user"`
	Merged         bool   `json:"merged"`
	MergeCommitSHA string `json:"merge_commit_sha"`
	// Mergeable is a pointer because null means "not computed yet", which is a
	// different fact from "cannot be merged".
	Mergeable      *bool  `json:"mergeable"`
	MergeableState string `json:"mergeable_state"`
	CreatedAt      string `json:"created_at"`
}

func (b prBody) handle(base RepoLoc) PullRequest {
	return PullRequest{
		IssueLoc:       IssueLoc{Owner: base.Owner, Repo: base.Repo, Number: b.Number},
		Head:           b.Head.Ref,
		HeadLabel:      b.Head.Label,
		Base:           b.Base.Ref,
		State:          b.State,
		Merged:         b.Merged,
		MergeableState: b.MergeableState,
		CreatedAt:      b.CreatedAt,
	}
}

// defaultBranch prefers what the bound handle already carries: a chain that
// resolved the repository should not pay for a second read.
func defaultBranch(ctx context.Context, s *Session, h RepoScoped) (string, error) {
	switch t := h.(type) {
	case Repo:
		if t.DefaultBranch != "" {
			return t.DefaultBranch, nil
		}
	case WritableRepo:
		if t.DefaultBranch != "" {
			return t.DefaultBranch, nil
		}
	case Fork:
		if t.DefaultBranch != "" {
			return t.DefaultBranch, nil
		}
	}
	loc := h.RepoRef()
	client, err := s.Client()
	if err != nil {
		return "", s.SoftRead(err, "read default branch")
	}
	body, _, err := readRepo(ctx, client, loc.Owner, loc.Repo)
	if err := s.SoftRead(err, "read default branch"); err != nil {
		return "", err
	}
	return body.DefaultBranch, nil
}
