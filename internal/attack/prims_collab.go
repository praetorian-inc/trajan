package attack

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/praetorian-inc/trajan/internal/attack/payload"
	"github.com/praetorian-inc/trajan/internal/github"
)

func init() {
	Register(Spec{
		Name:       "comment.create",
		Summary:    "Post a comment on an issue or a pull request.",
		Ports:      []Port{Accepts[Commentable]("on", true)},
		Caps:       []Capability{CapIssues},
		Mutating:   true,
		Reversible: true,
		OriginFrom: "on",
	}, commentCreate)

	Register(Spec{
		Name:       "comment.delete",
		Summary:    "Delete a comment.",
		Ports:      []Port{Accepts[Comment]("comment", true)},
		Caps:       []Capability{CapIssues},
		Mutating:   true,
		OriginFrom: "comment",
	}, commentDelete)

	Register(Spec{
		Name: "label.add",
		Summary: "Add an existing label to a pull request or an issue. The labeled event fires immediately, " +
			"which is the trigger a plan measuring on: pull_request: types: [labeled] is after.",
		Ports:      []Port{Accepts[Commentable]("on", true)},
		Caps:       []Capability{CapIssues},
		Mutating:   true,
		Reversible: true,
		OriginFrom: "on",
	}, labelAdd)

	Register(Spec{
		Name:       "issue.open",
		Summary:    "Open an issue — the cheapest comment target for the injection chain.",
		Ports:      []Port{Accepts[Repo]("repo", true)},
		Caps:       []Capability{CapIssues},
		Mutating:   true,
		Reversible: true,
		OriginFrom: "repo",
	}, issueOpen)
}

type commentCreateParams struct {
	Body     string         `yaml:"body"`
	Template string         `yaml:"template"`
	Params   map[string]any `yaml:"params"`
}

// commentCreate is the one create primitive that does not read for an existing
// resource first, deliberately: a comment has no key to read by. The same body
// posted twice is two comments, and a rendered carrier embeds this run's own
// public key, so it differs between processes and only a literal body could ever
// match. Nothing is lost by it — a resume never re-runs a step whose write-ahead
// intent is in the ledger, it stops and tells the operator to reverse the run.
func commentCreate(ctx context.Context, s *Session, p commentCreateParams, in Inputs) (Comment, error) {
	on := In[Commentable](in, "on").IssueRef()
	body, err := carrierText(s, p.Body, p.Template, p.Params)
	if err != nil {
		return Comment{}, err
	}
	loc := RepoLoc{Owner: on.Owner, Repo: on.Repo}
	comment := Comment{RepoLoc: loc, Number: on.Number, Author: s.Login(), BodySHA: bodySHA(body)}
	if on.Number == 0 {
		if s.Execute {
			return Comment{}, errors.New("no issue or pull request to comment on")
		}
		// The render carries on with 0 in the path. Returning here would leave the
		// document with no request for this step and the payload it carries nowhere
		// in it, which is the one thing the operator reviews before --execute.
		s.Note("the issue this comments on was rendered, not created, so the request renders with number 0")
	}

	raw, _, err := s.Mutate(ctx, Mutation{
		Method: http.MethodPost,
		Path:   fmt.Sprintf("/repos/%s/%s/issues/%d/comments", on.Owner, on.Repo, on.Number),
		Body:   map[string]any{"body": body},
		Target: on.Owner + "/" + on.Repo,
		Note:   "the notification email carrying the full body is delivered immediately and cannot be recalled",
		InverseFrom: func(raw json.RawMessage) []UndoStep {
			var made commentBody
			if err := json.Unmarshal(raw, &made); err != nil || made.ID == 0 {
				return nil
			}
			return commentDeleteUndo(loc, made.ID)
		},
		ReadBack: func(ctx context.Context) ([]UndoStep, error) {
			client, err := s.Client()
			if err != nil {
				return nil, err
			}
			existing, mine, err := ownComment(ctx, client, on, s.Login(), body)
			if err != nil || !mine {
				return nil, err
			}
			return commentDeleteUndo(loc, existing.ID), nil
		},
	})
	if err != nil {
		return comment, err
	}
	var made commentBody
	if err := json.Unmarshal(raw, &made); err != nil {
		return comment, err
	}
	comment.ID, comment.HTMLURL, comment.CreatedAt = made.ID, made.HTMLURL, made.CreatedAt
	if made.User.Login != "" {
		comment.Author = made.User.Login
	}
	return comment, nil
}

func commentDeleteUndo(loc RepoLoc, id int64) []UndoStep {
	return []UndoStep{{
		Method: http.MethodDelete,
		Path:   fmt.Sprintf("/repos/%s/%s/issues/comments/%d", loc.Owner, loc.Repo, id),
		Note: "removes the comment from the thread; the notification email carrying the whole body was delivered " +
			"when it was posted and no request recalls it, and posting fired issue_comment",
		Partial: true,
	}}
}

// ownComment finds the comment a post whose answer never came may have left. The
// body is the discriminator: it is byte-identical to what this step rendered, and
// a rendered carrier embeds this run's own public key, so no other process can
// have written it. Two of them is no answer — deleting the wrong one of a pair
// leaves a comment this run posted standing with nothing naming it.
func ownComment(ctx context.Context, c github.GitHub, on IssueLoc, login, body string) (commentBody, bool, error) {
	items, err := c.Paginate(ctx, fmt.Sprintf("/repos/%s/%s/issues/%d/comments", on.Owner, on.Repo, on.Number),
		url.Values{"per_page": []string{"100"}}, 100)
	if err != nil {
		return commentBody{}, false, err
	}
	want := bodySHA(body)
	var mine []commentBody
	for _, item := range items {
		var existing commentBody
		if err := json.Unmarshal(item, &existing); err != nil || existing.ID == 0 {
			continue
		}
		if bodySHA(existing.Body) != want || (login != "" && existing.User.Login != login) {
			continue
		}
		mine = append(mine, existing)
	}
	switch len(mine) {
	case 0:
		return commentBody{}, false, nil
	case 1:
		return mine[0], true, nil
	}
	return commentBody{}, false, fmt.Errorf("%d comments on #%d carry the body this step rendered, so which one it posted cannot be told apart",
		len(mine), on.Number)
}

type commentDeleteParams struct{}

func commentDelete(ctx context.Context, s *Session, _ commentDeleteParams, in Inputs) (None, error) {
	c := In[Comment](in, "comment")
	if c.ID == 0 {
		if s.Execute {
			s.MarkEmpty("no comment id to delete")
			return None{}, nil
		}
		s.Note("the comment this deletes was rendered, not created, so the request renders with id 0")
	}
	path := fmt.Sprintf("/repos/%s/%s/issues/comments/%d", c.Owner, c.Repo, c.ID)

	client, err := s.Client()
	if err != nil && s.Execute {
		return None{}, err
	}
	// An id of 0 came from a render, not from the target: reading it is a request
	// that can only 404, and the mark it would leave says nothing about the comment.
	if client != nil && c.ID != 0 {
		if _, _, err := client.Get(ctx, path, nil, false); err != nil && statusOf(err) == http.StatusNotFound {
			s.MarkEmpty("comment is already deleted")
			return None{}, nil
		}
	}

	_, _, err = s.Mutate(ctx, Mutation{
		Method: http.MethodDelete, Path: path, Target: c.Owner + "/" + c.Repo,
		Note: "fires issue_comment(deleted); any run that already consumed the body is unaffected",
	})
	return None{}, err
}

type labelAddParams struct {
	Label string `yaml:"label"`
}

// labelAdd produces the issue view of what it labeled. The labels endpoint is
// /issues/{n}/labels for a pull request too, and a primitive produces exactly one
// handle type, so a labeled pull request comes back as the issue it also is —
// IsPull records which it was, and a chain needing the pull request binds the step
// that opened it.
func labelAdd(ctx context.Context, s *Session, p labelAddParams, in Inputs) (Issue, error) {
	on := In[Commentable](in, "on").IssueRef()
	label := strings.TrimSpace(p.Label)
	if label == "" {
		return Issue{}, errors.New("label.add needs label: the name of a label the repository already carries")
	}
	out := Issue{IssueLoc: on}
	if on.Number == 0 {
		if s.Execute {
			return Issue{}, errors.New("no pull request or issue to label")
		}
		s.Note("the pull request or issue this labels was rendered, not created, so its number renders as 0")
	}
	issuePath := fmt.Sprintf("/repos/%s/%s/issues/%d", on.Owner, on.Repo, on.Number)

	client, err := s.Client()
	if err != nil && s.Execute {
		return Issue{}, err
	}
	if client != nil {
		if on.Number != 0 {
			raw, _, err := client.Get(ctx, issuePath, nil, false)
			if err := s.SoftRead(err, "read issue"); err != nil {
				return Issue{}, err
			}
			var current issueBody
			if err := json.Unmarshal(raw, &current); err == nil && current.Number != 0 {
				out.Title, out.State, out.IsPull = current.Title, current.State, len(current.PullRequest) > 0
				if slices.ContainsFunc(current.Labels, func(l labelBody) bool { return l.Name == label }) {
					s.Note(fmt.Sprintf("%q is already on #%d, and GitHub fires no labeled event for a label it already holds, so nothing was sent", label, on.Number))
					return out, nil
				}
			}
		}
		// POST /labels silently creates a repository label that does not exist, and
		// deleting that label again strips it from every issue that has it. A plan
		// measures a trigger the customer's workflows already key on, so an unknown
		// name is refused rather than invented.
		labelPath := fmt.Sprintf("/repos/%s/%s/labels/%s", on.Owner, on.Repo, url.PathEscape(label))
		if _, _, err := client.Get(ctx, labelPath, nil, false); err != nil && statusOf(err) == http.StatusNotFound {
			return Issue{}, fmt.Errorf("%s/%s has no label %q: adding it would create it repository-wide, and removing it afterwards would strip it from every issue that carries it — name a label the repository already has",
				on.Owner, on.Repo, label)
		}
	}

	if _, _, err := s.Mutate(ctx, Mutation{
		Method: http.MethodPost,
		Path:   issuePath + "/labels",
		Body:   map[string]any{"labels": []string{label}},
		Target: on.Owner + "/" + on.Repo,
		Note:   "the labeled event fires immediately and cannot be recalled",
		Inverse: []UndoStep{{
			Method: http.MethodDelete,
			Path:   issuePath + "/labels/" + url.PathEscape(label),
			Note: "removes the label, restoring the label set this run found; the labeled event, the timeline entry and " +
				"any workflow it started are not retractable",
		}},
	}); err != nil {
		return out, err
	}
	s.Note(fmt.Sprintf("adding %q to #%d fires the labeled event on the spot: a workflow subscribed to types: [labeled] starts before the call returns, and removing the label again does not stop it",
		label, on.Number))
	return out, nil
}

type issueOpenParams struct {
	Title    string         `yaml:"title"`
	Body     string         `yaml:"body"`
	Template string         `yaml:"template"`
	Params   map[string]any `yaml:"params"`
}

func issueOpen(ctx context.Context, s *Session, p issueOpenParams, in Inputs) (Issue, error) {
	target := In[Repo](in, "repo")
	if p.Title == "" {
		return Issue{}, errors.New("issue.open needs a title")
	}
	body, err := carrierText(s, p.Body, p.Template, p.Params)
	if err != nil {
		return Issue{}, err
	}
	issue := Issue{IssueLoc: IssueLoc{Owner: target.Owner, Repo: target.Repo}, Title: p.Title, State: "open"}

	client, err := s.Client()
	if err != nil && s.Execute {
		return Issue{}, err
	}
	if client != nil {
		existing, mine, err := findOpenIssue(ctx, client, target.RepoRef(), s.Login(), p.Title, body)
		if err := s.SoftRead(err, "list issues"); err != nil {
			return Issue{}, err
		}
		if mine {
			s.Note(fmt.Sprintf("adopted issue #%d: it is open under this title and its body is byte-identical to the carrier this step renders, so nothing was created and the carrier that is there is the one this step would have posted",
				existing.Number))
			issue.Number, issue.State = existing.Number, existing.State
			return issue, nil
		}
	}

	raw, _, err := s.Mutate(ctx, Mutation{
		Method: http.MethodPost,
		Path:   fmt.Sprintf("/repos/%s/%s/issues", target.Owner, target.Repo),
		Body:   map[string]any{"title": p.Title, "body": body},
		Target: target.Owner + "/" + target.Repo,
		Note:   "issues cannot be deleted through the API; the number and body history persist",
		InverseFrom: func(raw json.RawMessage) []UndoStep {
			var made issueBody
			if err := json.Unmarshal(raw, &made); err != nil || made.Number == 0 {
				return nil
			}
			return issueCloseUndo(target.RepoRef(), made.Number)
		},
		// The same read the adopt above already made, which found nothing: a byte-
		// identical body under this title was not there before the call, so one there
		// now is what the call created.
		ReadBack: func(ctx context.Context) ([]UndoStep, error) {
			client, err := s.Client()
			if err != nil {
				return nil, err
			}
			existing, mine, err := findOpenIssue(ctx, client, target.RepoRef(), s.Login(), p.Title, body)
			if err != nil || !mine {
				return nil, err
			}
			return issueCloseUndo(target.RepoRef(), existing.Number), nil
		},
	})
	if err != nil {
		return issue, err
	}
	var made issueBody
	if err := json.Unmarshal(raw, &made); err != nil {
		return issue, err
	}
	issue.Number = made.Number
	return issue, nil
}

func findOpenIssue(ctx context.Context, c github.GitHub, loc RepoLoc, login, title, body string) (issueBody, bool, error) {
	params := url.Values{"state": []string{"open"}, "per_page": []string{"100"}}
	// creator is sent only when the acting credential has a login to filter by: an
	// App installation token reports none, and creator= is then either rejected or
	// ignored.
	if login != "" {
		params.Set("creator", login)
	}
	items, err := c.Paginate(ctx, fmt.Sprintf("/repos/%s/%s/issues", loc.Owner, loc.Repo), params, 100)
	if err != nil {
		return issueBody{}, false, err
	}
	existing, mine := adoptableIssue(items, title, body)
	return existing, mine, nil
}

func issueCloseUndo(loc RepoLoc, number int) []UndoStep {
	return []UndoStep{{
		Method:  http.MethodPatch,
		Path:    fmt.Sprintf("/repos/%s/%s/issues/%d", loc.Owner, loc.Repo, number),
		Body:    map[string]any{"state": "closed"},
		Note:    "closes but does not delete: an issue cannot be removed through the API",
		Partial: true,
	}}
}

// adoptableIssue picks the open issue this step may claim as already posted: the
// same title and a byte-identical body. A title is not a key — a repository's own
// issue can carry any title a plan spells — and adopting one on the title alone
// reports a carrier as delivered while the issue standing there holds text this
// run never wrote and the rendered payload went nowhere.
func adoptableIssue(items []json.RawMessage, title, body string) (issueBody, bool) {
	for _, item := range items {
		var existing issueBody
		if err := json.Unmarshal(item, &existing); err != nil || len(existing.PullRequest) > 0 {
			continue
		}
		if existing.Number != 0 && existing.Title == title && existing.Body == body {
			return existing, true
		}
	}
	return issueBody{}, false
}

type commentBody struct {
	ID        int64  `json:"id"`
	Body      string `json:"body"`
	HTMLURL   string `json:"html_url"`
	CreatedAt string `json:"created_at"`
	User      struct {
		Login string `json:"login"`
	} `json:"user"`
}

type issueBody struct {
	Number      int             `json:"number"`
	Title       string          `json:"title"`
	Body        string          `json:"body"`
	State       string          `json:"state"`
	PullRequest json.RawMessage `json:"pull_request"`
	Labels      []labelBody     `json:"labels"`
}

type labelBody struct {
	Name string `json:"name"`
}

// carrierText is the comment channel's payload stage: a literal body, or a
// rendered fragment so an injection carrier gets the same schema, quoting and
// evidence marker as every other channel.
func carrierText(s *Session, body, template string, params map[string]any) (string, error) {
	switch {
	case template != "" && body != "":
		return "", errors.New("set body: or template:, not both")
	case template != "":
		return payload.Render(template, params, s.PayloadEnv())
	case body != "":
		return body, nil
	default:
		return "", errors.New("needs a body: or a template:")
	}
}

func bodySHA(body string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(body)))[:16]
}
