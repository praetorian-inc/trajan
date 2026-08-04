package attack

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"

	"github.com/praetorian-inc/trajan/internal/github"
)

func init() {
	Register(Spec{
		Name:       "pr.list",
		Summary:    "Find an open pull request the chain can reuse instead of opening one.",
		Ports:      []Port{Accepts[Repo]("repo", true)},
		OriginFrom: "repo",
	}, prList)

	Register(Spec{
		Name:       "issue.list",
		Summary:    "Find an existing issue to use as a comment target.",
		Ports:      []Port{Accepts[Repo]("repo", true)},
		OriginFrom: "repo",
	}, issueList)

	Register(Spec{
		Name:    "identity.resolve",
		Summary: "Resolve a credential from env or the identity store into a typed identity, classifying its token class.",
	}, identityResolve)

	Register(Spec{
		Name:    "repo.resolve",
		Summary: "Resolve an owner/name pair into a Repo handle, reading the metadata every downstream port needs.",
	}, repoResolve)

	Register(Spec{
		Name: "org.resolve",
		Summary: "Resolve an organization named directly by owner:, gated on the plan's orgs: allowlist — " +
			"a separate list from scope:, because an organization names no repository.",
	}, orgResolve)

	Register(Spec{
		Name:       "repo.writable",
		Summary:    "Assert and produce write access to a repository the plan did not create, without going through a fork.",
		Ports:      []Port{Accepts[Repo]("repo", true)},
		OriginFrom: "repo",
	}, repoWritable)
}

type identityResolveParams struct {
	From string `yaml:"from"`
}

type repoResolveParams struct {
	Owner string `yaml:"owner"`
	Repo  string `yaml:"repo"`
}

type orgResolveParams struct {
	Owner string `yaml:"owner"`
}

type repoWritableParams struct{}

func identityResolve(ctx context.Context, s *Session, p identityResolveParams, _ Inputs) (Identity, error) {
	ic, err := s.identity(ctx, p.From)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Name: ic.name, IDKind: ic.kind, Login: ic.login, Scopes: ic.scopes}, nil
}

func repoResolve(ctx context.Context, s *Session, p repoResolveParams, _ Inputs) (Repo, error) {
	if p.Owner == "" || p.Repo == "" {
		return Repo{}, errors.New("owner and repo are required")
	}
	bare := Repo{RepoLoc: RepoLoc(p)}
	client, err := s.Client()
	if err != nil {
		if err := s.SoftRead(err, "resolve repository"); err != nil {
			return Repo{}, err
		}
		return bare, nil
	}
	body, _, err := readRepo(ctx, client, p.Owner, p.Repo)
	if err := s.SoftRead(err, "resolve repository"); err != nil {
		return Repo{}, err
	}
	if body.Name == "" {
		return bare, nil
	}
	return Repo{
		RepoLoc:       RepoLoc{Owner: cmp.Or(body.Owner.Login, p.Owner), Repo: cmp.Or(body.Name, p.Repo)},
		DefaultBranch: body.DefaultBranch,
		Private:       body.Private,
		Fork:          body.Fork,
		Perms:         Perms{Admin: body.Permissions.Admin, Push: body.Permissions.Push, Pull: body.Permissions.Pull},
	}, nil
}

// orgResolve takes the organization from owner: rather than deriving it from a
// repository's owner, because the two are different assertions: a plan may be
// authorized to touch one repository without being authorized to enumerate the
// organization that holds it. The allowlist is checked before the read, so an
// out-of-scope organization is refused without a request.
func orgResolve(ctx context.Context, s *Session, p orgResolveParams, _ Inputs) (Org, error) {
	if p.Owner == "" {
		return Org{}, errors.New("org.resolve needs owner: the organization login")
	}
	if err := s.OrgAllowed(p.Owner); err != nil {
		return Org{}, err
	}
	org := Org{Owner: p.Owner}

	client, err := s.Client()
	if err != nil {
		if err := s.SoftRead(err, "resolve organization"); err != nil {
			return Org{}, err
		}
		return org, nil
	}
	login, err := getString(ctx, client, "/orgs/"+url.PathEscape(p.Owner), "login")
	if err != nil {
		if softFail(s, err, "organization "+p.Owner) {
			return org, nil
		}
		if err := s.SoftRead(err, "resolve organization"); err != nil {
			return Org{}, err
		}
		return org, nil
	}
	org.Owner = cmp.Or(login, p.Owner)
	return org, nil
}

// repoWritable re-reads the repository as the acting identity rather than trusting
// the Perms the bound Repo carries, because a step's as: may name a different
// principal than the one that resolved it. Confirming write access with a read is
// also what keeps a rejected write out of the customer's audit log.
func repoWritable(ctx context.Context, s *Session, _ repoWritableParams, in Inputs) (WritableRepo, error) {
	target := In[Repo](in, "repo")
	writable := WritableRepo{RepoLoc: target.RepoLoc, DefaultBranch: target.DefaultBranch}
	client, err := s.Client()
	if err != nil {
		if err := s.SoftRead(err, "confirm write access"); err != nil {
			return WritableRepo{}, err
		}
		return writable, nil
	}
	body, _, err := readRepo(ctx, client, target.Owner, target.Repo)
	if err := s.SoftRead(err, "confirm write access"); err != nil {
		return WritableRepo{}, err
	}
	if !body.Permissions.Push {
		if s.Execute {
			return WritableRepo{}, fmt.Errorf("identity %q has no push permission on %s/%s", s.ActingName(), target.Owner, target.Repo)
		}
		s.MarkEmpty("the acting identity has no push permission on this repository")
	}
	writable.DefaultBranch = cmp.Or(body.DefaultBranch, target.DefaultBranch)
	return writable, nil
}

type prListParams struct {
	State string `yaml:"state"`
	Head  string `yaml:"head"`
	Base  string `yaml:"base"`
	Match string `yaml:"match"`
}

func prList(ctx context.Context, s *Session, p prListParams, in Inputs) (PullRequest, error) {
	target := In[Repo](in, "repo")
	client, err := s.Client()
	if err != nil {
		return PullRequest{}, err
	}
	params := url.Values{"state": []string{cmp.Or(p.State, "open")}, "per_page": []string{"100"}}
	if p.Head != "" {
		params.Set("head", p.Head)
	}
	if p.Base != "" {
		params.Set("base", p.Base)
	}

	items, err := client.Paginate(ctx, fmt.Sprintf("/repos/%s/%s/pulls", target.Owner, target.Repo), params, 100)
	if err != nil {
		if soft := softFail(s, err, "pull requests"); soft {
			return PullRequest{IssueLoc: IssueLoc{Owner: target.Owner, Repo: target.Repo}}, nil
		}
		return PullRequest{}, err
	}

	match, err := compileMatch(p.Match)
	if err != nil {
		return PullRequest{}, err
	}
	for _, item := range items {
		var listed prListItem
		if err := json.Unmarshal(item, &listed); err != nil {
			continue
		}
		if match != nil && !match.MatchString(listed.Title) {
			continue
		}
		return matchedPR(ctx, s, client, target.RepoLoc, listed), nil
	}
	s.MarkEmpty("no pull request matched")
	return PullRequest{IssueLoc: IssueLoc{Owner: target.Owner, Repo: target.Repo}}, nil
}

// prListItem is the part of the list response this primitive reads. The list
// returns the Pull Request Simple schema, which carries neither mergeable_state
// nor merged: those two live only on the singular pull request.
type prListItem struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	State  string `json:"state"`
	Head   struct {
		Ref   string `json:"ref"`
		Label string `json:"label"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
	CreatedAt string `json:"created_at"`
}

func (i prListItem) handle(loc RepoLoc) PullRequest {
	return PullRequest{
		IssueLoc:  IssueLoc{Owner: loc.Owner, Repo: loc.Repo, Number: i.Number},
		Head:      i.Head.Ref,
		Base:      i.Base.Ref,
		HeadLabel: i.Head.Label,
		State:     i.State,
		CreatedAt: i.CreatedAt,
	}
}

// matchedPR re-reads the pull request the list matched, because the handle carries
// mergeable_state and the list schema does not report it. Populating it from the
// list would leave it empty on every pull request, which is not a value a plan can
// read as "not computed": a when: on mergeable_state == "clean" would never match
// and one on != "clean" would always match, neither of them measuring anything. On
// a read that fails, the field stays empty and the note says so, rather than the
// step failing over a field the caller may not gate on.
func matchedPR(ctx context.Context, s *Session, client github.GitHub, loc RepoLoc, listed prListItem) PullRequest {
	out := listed.handle(loc)
	full, err := readPR(ctx, client, fmt.Sprintf("/repos/%s/%s/pulls/%d", loc.Owner, loc.Repo, listed.Number))
	if err != nil {
		s.Note(fmt.Sprintf("pull request #%d matched, but re-reading it failed (%s), so mergeable_state is empty rather than read: the list endpoint returns the Pull Request Simple schema, which does not carry it. pr.mergeability.await is where a plan that gates on mergeability gets it",
			listed.Number, apiMessage(err)))
		return out
	}
	merged := full.handle(loc)
	merged.Head = cmp.Or(merged.Head, out.Head)
	merged.HeadLabel = cmp.Or(merged.HeadLabel, out.HeadLabel)
	merged.Base = cmp.Or(merged.Base, out.Base)
	merged.CreatedAt = cmp.Or(merged.CreatedAt, out.CreatedAt)
	return merged
}

type issueListParams struct {
	State string `yaml:"state"`
	Match string `yaml:"match"`
}

// issueList filters out pull requests: /issues returns both, and handing a
// pr-shaped record to an issue primitive is the documented trap.
func issueList(ctx context.Context, s *Session, p issueListParams, in Inputs) (Issue, error) {
	target := In[Repo](in, "repo")
	client, err := s.Client()
	if err != nil {
		return Issue{}, err
	}
	params := url.Values{"state": []string{cmp.Or(p.State, "open")}, "per_page": []string{"100"}}

	items, err := client.Paginate(ctx, fmt.Sprintf("/repos/%s/%s/issues", target.Owner, target.Repo), params, 100)
	if err != nil {
		if soft := softFail(s, err, "issues"); soft {
			return Issue{IssueLoc: IssueLoc{Owner: target.Owner, Repo: target.Repo}}, nil
		}
		return Issue{}, err
	}

	match, err := compileMatch(p.Match)
	if err != nil {
		return Issue{}, err
	}
	for _, item := range items {
		var issue struct {
			Number      int             `json:"number"`
			Title       string          `json:"title"`
			State       string          `json:"state"`
			PullRequest json.RawMessage `json:"pull_request"`
		}
		if err := json.Unmarshal(item, &issue); err != nil {
			continue
		}
		if len(issue.PullRequest) > 0 {
			continue
		}
		if match != nil && !match.MatchString(issue.Title) {
			continue
		}
		return Issue{
			IssueLoc: IssueLoc{Owner: target.Owner, Repo: target.Repo, Number: issue.Number},
			Title:    issue.Title,
			State:    issue.State,
		}, nil
	}
	s.MarkEmpty("no issue matched")
	return Issue{IssueLoc: IssueLoc{Owner: target.Owner, Repo: target.Repo}}, nil
}

// softFail turns a 403/404 on an optional read into a success producing a
// marked-empty handle. A read the plan chose to make is not a reason to abandon
// the chain when the token simply cannot see the surface.
func softFail(s *Session, err error, what string) bool {
	var ghErr *github.GhError
	if !errors.As(err, &ghErr) || (ghErr.Status != 403 && ghErr.Status != 404) {
		return false
	}
	s.MarkEmpty(fmt.Sprintf("%s unreadable (HTTP %d)", what, ghErr.Status))
	return true
}

func compileMatch(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("match %q: %w", pattern, err)
	}
	return re, nil
}
