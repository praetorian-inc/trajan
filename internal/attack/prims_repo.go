package attack

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/praetorian-inc/trajan/internal/github"
)

func init() {
	Register(Spec{
		Name: "repo.fork",
		Summary: "Fork a repository into an attacker-controlled owner to obtain a writable low-trust head. Needs " +
			"administration:write on the source alongside contents:read, and a GitHub App must be installed on the " +
			"destination account with access to all repositories and on the source account with access to the source.",
		Ports: []Port{Accepts[Repo]("repo", true)},
		// administration:write is the same large grant repo.delete gates behind
		// delete_repo. Undeclared, the preflight would report that the fork needs
		// nothing and the step would fail at the call instead of in validation.
		Caps:       []Capability{CapAdministration},
		Mutating:   true,
		Reversible: true,
	}, repoFork)

	Register(Spec{
		Name:        "repo.delete",
		Summary:     "Delete a repository this run created — the inverse of repo.fork.",
		Ports:       []Port{Accepts[RepoScoped]("repo", true)},
		Caps:        []Capability{CapDeleteRepo},
		Mutating:    true,
		Destructive: true,
		OriginFrom:  "repo",
	}, repoDelete)
}

type repoForkParams struct {
	Timeout string `yaml:"timeout"`
}

// repoFork adopts an existing fork rather than failing, and refuses a same-named
// repository that is not a fork of this upstream: GitHub answers POST /forks with
// that unrelated repository instead of erroring, and pushing into it would put
// the payload somewhere the plan never named.
func repoFork(ctx context.Context, s *Session, p repoForkParams, in Inputs) (Fork, error) {
	up := In[Repo](in, "repo")
	owner := s.Login()
	if owner == "" {
		if s.Execute {
			return Fork{}, errors.New("the acting identity has no login, so a fork has no namespace to land in")
		}
		owner = "<" + cmp.Or(s.ActingName(), "acting-identity") + ">"
	}
	fork := Fork{
		RepoLoc:       RepoLoc{Owner: owner, Repo: up.Repo},
		Upstream:      up.RepoLoc,
		DefaultBranch: up.DefaultBranch,
	}
	if err := s.AllowFork(fork.RepoLoc, up.RepoLoc); err != nil {
		return Fork{}, err
	}

	client, err := s.Client()
	if err != nil && s.Execute {
		return Fork{}, err
	}
	if client != nil {
		existing, status, err := readRepo(ctx, client, owner, up.Repo)
		switch {
		case err != nil && status != http.StatusNotFound:
			if err := s.SoftRead(err, "read fork"); err != nil {
				return Fork{}, err
			}
		case err == nil && existing.Parent.FullName == up.Owner+"/"+up.Repo:
			s.Note(fmt.Sprintf("adopted %s/%s: it already exists and is a fork of %s/%s, so nothing was created", owner, up.Repo, up.Owner, up.Repo))
			fork.DefaultBranch = cmp.Or(existing.DefaultBranch, fork.DefaultBranch)
			return fork, nil
		case err == nil:
			return Fork{}, fmt.Errorf("%s/%s already exists and is not a fork of %s/%s", owner, up.Repo, up.Owner, up.Repo)
		}
	}

	// An installation token is scoped per account, and a fork crosses two: the
	// destination is a namespace the source's installation says nothing about. It is a
	// note rather than a refusal because nothing readable from here confirms where the
	// App is installed, and the 403 it produces is otherwise unexplained.
	if s.ActingKind() == kindAppInstallation {
		s.Note(fmt.Sprintf("the acting credential is an App installation token: this fork needs the App installed on %s with access to all repositories and on %s with access to %s, and a gap in either is a 403 on the call below",
			owner, up.Owner, up.Repo))
	}

	if _, _, err := s.Mutate(ctx, Mutation{
		Method: http.MethodPost,
		Path:   fmt.Sprintf("/repos/%s/%s/forks", up.Owner, up.Repo),
		Target: up.Owner + "/" + up.Repo,
		Note:   "creates " + owner + "/" + up.Repo + "; the upstream fork event is not retractable",
		Inverse: []UndoStep{{
			Method: http.MethodDelete,
			Path:   fmt.Sprintf("/repos/%s/%s", owner, up.Repo),
			Note: "removes the fork this run created; it needs delete_repo or administration:write and is commonly refused, " +
				"which is reported as a failed reversal rather than assumed here. The upstream's fork event and its fork " +
				"count are not retractable",
		}},
	}); err != nil {
		return Fork{}, err
	}
	fork.Created = true
	if !s.Execute {
		return fork, nil
	}

	// POST /forks answers 202 and the documented lag is on the git objects, not on
	// the repository record, so the primitive polls for a resolvable default-branch
	// ref rather than handing the next step a repository with no refs in it.
	ready, err := awaitFork(ctx, client, owner, up.Repo, p.Timeout)
	if err != nil {
		return Fork{}, err
	}
	fork.DefaultBranch = cmp.Or(ready.DefaultBranch, fork.DefaultBranch)
	return fork, nil
}

const forkPollInterval = 2 * time.Second

// awaitFork waits for the fork's refs, not for its repository record. Forking is
// asynchronous and the documented warning is that "you may have to wait a short
// period of time before you can access the git objects", so a poll that returns on
// the first 200 from /repos hands ref.create or commit.code a repository whose
// default branch does not resolve yet — an intermittent failure at the head of
// every fork chain. Both signals are read in one loop so they share one deadline.
func awaitFork(ctx context.Context, client github.GitHub, owner, name, timeout string) (repoBody, error) {
	bound, err := parseTimeout(timeout)
	if err != nil {
		return repoBody{}, err
	}
	var deadline time.Time
	if bound > 0 {
		deadline = time.Now().Add(bound)
	}
	seen := ""
	for {
		body, status, err := readRepo(ctx, client, owner, name)
		switch {
		case err != nil && status != http.StatusNotFound:
			return repoBody{}, err
		case err != nil:
			seen = "the repository record does not exist yet"
		case body.DefaultBranch == "":
			// A fork of a repository with no commits never grows a ref, so there is
			// nothing here to wait for and the caller decides what to do with it.
			return body, nil
		default:
			ready, err := refResolves(ctx, client, owner, name, body.DefaultBranch)
			if err != nil {
				return repoBody{}, err
			}
			if ready {
				return body, nil
			}
			seen = fmt.Sprintf("the repository record exists but refs/heads/%s does not resolve yet", body.DefaultBranch)
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return repoBody{}, fmt.Errorf("fork %s/%s was not usable within %s: %s", owner, name, timeout, seen)
		}
		select {
		case <-ctx.Done():
			return repoBody{}, ctx.Err()
		case <-time.After(forkPollInterval):
		}
	}
}

// refResolves asks for one ref and reads the object sha off it. The read answers
// 404 until the ref exists, which is the signal the fork warning is about, 409
// while the repository is still empty, and an empty sha is the same "not yet" as
// either.
func refResolves(ctx context.Context, c github.GitHub, owner, name, branch string) (bool, error) {
	raw, _, err := c.Get(ctx, gitRefReadPath(owner, name, "refs/heads/"+branch), nil, false)
	if err != nil {
		if status := statusOf(err); status == http.StatusNotFound || status == http.StatusConflict {
			return false, nil
		}
		return false, err
	}
	var body struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return false, err
	}
	return body.Object.SHA != "", nil
}

type repoDeleteParams struct{}

// repoDelete refuses a repository this run did not create. Deletion has no
// inverse, and the ledger must be able to record provenance rather than only a
// handle.
func repoDelete(ctx context.Context, s *Session, _ repoDeleteParams, in Inputs) (None, error) {
	bound := In[RepoScoped](in, "repo")
	target := bound.RepoRef()
	fork, isFork := bound.(Fork)
	if !isFork || !fork.Created {
		return None{}, fmt.Errorf("refusing to delete %s/%s: this run did not create it", target.Owner, target.Repo)
	}

	client, err := s.Client()
	if err != nil && s.Execute {
		return None{}, err
	}
	if client != nil {
		if _, status, err := readRepo(ctx, client, target.Owner, target.Repo); err != nil && status == http.StatusNotFound {
			s.MarkEmpty("repository is already absent")
			return None{}, nil
		}
	}

	_, _, err = s.Mutate(ctx, Mutation{
		Method: http.MethodDelete,
		Path:   fmt.Sprintf("/repos/%s/%s", target.Owner, target.Repo),
		Target: target.Owner + "/" + target.Repo,
		Note:   "irreversible; needs delete_repo or administration:write",
	})
	return None{}, err
}

type repoBody struct {
	Name          string `json:"name"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	Fork          bool   `json:"fork"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
	Parent struct {
		FullName string `json:"full_name"`
	} `json:"parent"`
	Permissions struct {
		Admin bool `json:"admin"`
		Push  bool `json:"push"`
		Pull  bool `json:"pull"`
	} `json:"permissions"`
}

func readRepo(ctx context.Context, c github.GitHub, owner, name string) (repoBody, int, error) {
	raw, _, err := c.Get(ctx, "/repos/"+owner+"/"+name, nil, false)
	if err != nil {
		return repoBody{}, statusOf(err), err
	}
	var body repoBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return repoBody{}, 0, err
	}
	return body, http.StatusOK, nil
}

func statusOf(err error) int {
	var ghErr *github.GhError
	if errors.As(err, &ghErr) {
		return ghErr.Status
	}
	return 0
}
