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
		Name: "repo.create",
		Summary: "Create a private repository the run owns, to establish what a credential reaches through an " +
			"organization it is only a member of — a runner group whose visibility is all, most of all. Needs " +
			"administration:write on the organization and its members_can_create_private_repositories setting, " +
			"which this reads before the call.",
		Caps:       []Capability{CapAdministration},
		Mutating:   true,
		Reversible: true,
	}, repoCreate)

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

type repoCreateParams struct {
	Owner string `yaml:"owner"`
	Repo  string `yaml:"repo"`
}

// repoCreate names its repository in owner:/repo: rather than binding an Org
// handle, so the name is plan text: computeOrigin then reads the same concrete
// origin it reads off repo.resolve and Validate refuses an out-of-scope creation
// offline, where a name derived from a bound handle would be opaque until the call.
//
// It produces WritableRepo rather than a Repo a repo.writable step then confirms.
// The confirming read is what repo.writable exists for on a repository the plan did
// not create; here the creating call's own response carries Perms.Push, so the read
// would be redundant under --execute and unavailable without it — a dry run skips a
// read that depends on a mutation it only rendered, which would leave every commit
// below unrendered and the sequence half-documented.
//
// The repository is private unconditionally. A verification run must not add
// public attack surface to the organization it is measuring, and nothing needs a
// public one.
func repoCreate(ctx context.Context, s *Session, p repoCreateParams, _ Inputs) (WritableRepo, error) {
	if p.Owner == "" || p.Repo == "" {
		return WritableRepo{}, errors.New("owner and repo are required")
	}
	target := p.Owner + "/" + p.Repo
	created := WritableRepo{RepoLoc: RepoLoc(p), DefaultBranch: "main"}

	client, err := s.Client()
	if err != nil && s.Execute {
		return WritableRepo{}, err
	}
	if client != nil {
		if err := repoNameIsFree(ctx, s, client, p.Owner, p.Repo); err != nil {
			return WritableRepo{}, err
		}
		if err := orgAllowsPrivateRepos(ctx, s, client, p.Owner); err != nil {
			return WritableRepo{}, err
		}
	}

	raw, _, err := s.Mutate(ctx, Mutation{
		Method: http.MethodPost,
		Path:   "/orgs/" + p.Owner + "/repos",
		Body: map[string]any{
			"name":    p.Repo,
			"private": true,
			// A repository created with no commits has no default-branch ref, so every
			// write port downstream would bind a ref that does not resolve.
			"auto_init":   true,
			"description": "created by trajan for verification plan " + s.Plan.ID,
		},
		Target: target,
		Note:   "creates the repository " + target,
		Inverse: []UndoStep{{
			Method: http.MethodDelete,
			Path:   "/repos/" + target,
			Note: "deletes the repository this run created; it needs delete_repo or administration:write and is " +
				"refused for a credential holding neither, which is reported as a failed reversal rather than " +
				"assumed here",
		}},
	})
	if err != nil {
		return WritableRepo{}, err
	}
	if !s.Execute {
		return created, nil
	}

	var body repoBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return WritableRepo{}, err
	}
	if !body.Permissions.Push {
		return WritableRepo{}, fmt.Errorf("%s was created but its response reports no push permission for %q, so nothing may bind it as a writable ref", target, s.ActingName())
	}
	created.DefaultBranch = cmp.Or(body.DefaultBranch, created.DefaultBranch)
	return created, nil
}

// repoNameIsFree refuses a name that already resolves instead of reusing it. The
// inverse this primitive writes to the ledger is a delete, so adopting an existing
// repository would arm an undo against something the run did not create — the one
// mistake here that cannot be walked back.
func repoNameIsFree(ctx context.Context, s *Session, c github.GitHub, owner, name string) error {
	if _, status, err := readRepo(ctx, c, owner, name); err == nil {
		return fmt.Errorf("%s/%s already exists, and repo.create does not adopt a repository: the inverse it records is a delete, which must never point at something this run did not create. Remove a leftover of an earlier run, or name a different repository", owner, name)
	} else if status != http.StatusNotFound {
		return s.SoftRead(err, "read the repository name to create")
	}
	return nil
}

// orgAllowsPrivateRepos refuses locally when the organization is known to forbid
// the creation, so a member credential does not spend a 403 in the customer's audit
// trail to learn it. The settings are visible to owners, and a member reading its own
// organization gets a profile without them, so unreadable is a note and not a
// refusal: a negative nothing measured must not be reported as one that was.
func orgAllowsPrivateRepos(ctx context.Context, s *Session, c github.GitHub, org string) error {
	// Two settings, both required: the first is the organization-wide switch, the
	// second narrows it by visibility, and reading only one leaves a configuration
	// where the guard passes and the call is refused anyway.
	var body struct {
		Any     *bool `json:"members_can_create_repositories"`
		Private *bool `json:"members_can_create_private_repositories"`
	}
	raw, _, err := c.Get(ctx, "/orgs/"+org, nil, false)
	if err == nil {
		err = json.Unmarshal(raw, &body)
	}
	off := ""
	switch {
	case body.Any != nil && !*body.Any:
		off = "members_can_create_repositories"
	case body.Private != nil && !*body.Private:
		off = "members_can_create_private_repositories"
	}

	switch {
	case err != nil:
		s.Note(fmt.Sprintf("organization %s is unreadable as this identity (%s), so whether it permits members to create private repositories was not established and the call below is what decides it", org, apiMessage(err)))
	case off != "":
		return fmt.Errorf("%s has %s off, so POST /orgs/%s/repos would be refused; an owner changes the setting, or the plan acts as an identity that holds administration:write on the organization", org, off, org)
	case body.Any == nil && body.Private == nil:
		s.Note(fmt.Sprintf("the repository-creation settings are absent from the profile of %s this identity reads — they are visible to owners — so the call below is what decides it", org))
	}
	return nil
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
