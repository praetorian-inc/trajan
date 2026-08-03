package attack

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"strings"
)

func init() {
	Register(Spec{
		Name:       "ref.create",
		Summary:    "Create a branch ref from a start ref.",
		Ports:      []Port{Accepts[WritableRef]("on", true)},
		Caps:       []Capability{CapContentsWrite},
		Mutating:   true,
		Reversible: true,
		OriginFrom: "on",
	}, refCreate)

	// The port is the concrete Branch rather than WritableRef: every writable
	// handle names a ref, and a WritableRepo's is refs/heads/<default branch>, so
	// the wide port would let a well-typed plan spell the deletion of the customer's
	// default branch. Branch is a branch this chain created, which is the only thing
	// a chain has any business deleting.
	Register(Spec{
		Name:       "ref.delete",
		Summary:    "Delete a branch this chain created — cleanup inverse, and an attack step where deletion is unprotected.",
		Ports:      []Port{Accepts[Branch]("ref", true)},
		Caps:       []Capability{CapContentsWrite},
		Mutating:   true,
		OriginFrom: "ref",
	}, refDelete)

	// The target ref is a string field rather than a port: the ref being moved does
	// not exist as a prior handle in any chain that moves a tag, so a signature
	// taking both a Ref and a Commit is one no author could write. The repository
	// comes from the commit being pointed at.
	Register(Spec{
		Name:       "ref.update",
		Summary:    "Point a ref at a commit — the mutable-ref primitive and the stale-approval TOCTOU mechanism.",
		Ports:      []Port{Accepts[Commit]("to", true)},
		Caps:       []Capability{CapContentsWrite},
		Mutating:   true,
		Reversible: true,
		OriginFrom: "to",
	}, refUpdate)
}

type refCreateParams struct {
	Name string `yaml:"name"`
	From string `yaml:"from"`
}

// refCreate is idempotent through the read below and not through the POST's
// status: GET /git/ref answers 404 for a ref that is not there, so a resumed or
// re-run chain adopts the ref its earlier attempt created instead of creating a
// second one. What POST /git/refs answers for a ref that already exists is not
// documented, so nothing here depends on it.
func refCreate(ctx context.Context, s *Session, p refCreateParams, in Inputs) (Branch, error) {
	on := In[WritableRef](in, "on").WriteRef()
	if p.Name == "" {
		return Branch{}, fmt.Errorf("ref.create needs a branch name")
	}
	ref := "refs/heads/" + strings.TrimPrefix(p.Name, "refs/heads/")
	branch := Branch{
		RefLoc:  RefLoc{Owner: on.Owner, Repo: on.Repo, Ref: ref},
		FromRef: cmp.Or(p.From, strings.TrimPrefix(on.Ref, "refs/heads/")),
	}

	client, err := s.Client()
	if err != nil && s.Execute {
		return Branch{}, err
	}
	if client != nil {
		if sha, err := getString(ctx, client, gitRefReadPath(on.Owner, on.Repo, ref), "object", "sha"); err == nil {
			s.Note(fmt.Sprintf("adopted %s at %s: it already exists, so nothing was created", ref, shortSHA(sha)))
			branch.SHA = sha
			return branch, nil
		}
	}

	start := on.SHA
	if p.From != "" || start == "" {
		sha, err := resolveCommitish(ctx, s, on.Owner, on.Repo, branch.FromRef)
		if err != nil {
			return Branch{}, err
		}
		start = sha
	}
	branch.SHA = start
	branch.Created = true

	_, _, err = s.Mutate(ctx, Mutation{
		Method: http.MethodPost,
		Path:   fmt.Sprintf("/repos/%s/%s/git/refs", on.Owner, on.Repo),
		Body:   map[string]any{"ref": ref, "sha": start},
		Target: on.Owner + "/" + on.Repo,
		Inverse: []UndoStep{{
			Method: http.MethodDelete,
			Path:   gitRefWritePath(on.Owner, on.Repo, ref),
			Note:   "exact for a ref this run created; the create event and audit entry persist",
		}},
	})
	if err != nil {
		return branch, err
	}
	return branch, nil
}

type refDeleteParams struct{}

func refDelete(ctx context.Context, s *Session, _ refDeleteParams, in Inputs) (None, error) {
	target := In[Branch](in, "ref").RefLoc
	path := gitRefWritePath(target.Owner, target.Repo, target.Ref)

	client, err := s.Client()
	if err != nil && s.Execute {
		return None{}, err
	}
	sha := target.SHA
	if client != nil {
		current, err := getString(ctx, client, gitRefReadPath(target.Owner, target.Repo, target.Ref), "object", "sha")
		if err != nil && statusOf(err) == http.StatusNotFound {
			s.MarkEmpty("ref is already absent")
			return None{}, nil
		}
		if err == nil {
			sha = current
		}
	}

	inverse := []UndoStep{}
	// Without the SHA there is no inverse at all: the API exposes no reflog.
	if sha != "" {
		inverse = append(inverse, UndoStep{
			Method: http.MethodPost,
			Path:   fmt.Sprintf("/repos/%s/%s/git/refs", target.Owner, target.Repo),
			Body:   map[string]any{"ref": target.Ref, "sha": sha},
			Note:   "recreates the ref at " + sha,
		})
	}

	_, _, err = s.Mutate(ctx, Mutation{
		Method: http.MethodDelete, Path: path, Target: target.Owner + "/" + target.Repo,
		Inverse: inverse,
	})
	return None{}, err
}

type refUpdateParams struct {
	Ref   string `yaml:"ref"`
	Force bool   `yaml:"force"`
}

// refUpdate is racy by construction: PATCH takes the new SHA absolutely with no
// expected-current-SHA parameter, so a tip that moved between the read below and
// the call is silently clobbered. The read is still worth making — it is where
// PreviousSHA, and therefore the only clean undo in the system, comes from.
func refUpdate(ctx context.Context, s *Session, p refUpdateParams, in Inputs) (Ref, error) {
	to := In[Commit](in, "to")
	if !strings.HasPrefix(p.Ref, "refs/") {
		return Ref{}, fmt.Errorf("ref %q must be a full ref, e.g. refs/heads/main or refs/tags/v1", p.Ref)
	}
	// A merge GitHub refused with a 405 or a 409 returns a commit with no sha, and
	// the PATCH below would then ask for a ref pointing at nothing: a refusal in the
	// customer's audit log that establishes nothing and still costs them an entry.
	if to.SHA == "" {
		return Ref{}, fmt.Errorf("refusing to point %s at an empty sha: the commit bound to to: carries none, so the step that produced it created no commit", p.Ref)
	}
	path := gitRefWritePath(to.Owner, to.Repo, p.Ref)
	out := Ref{
		RefLoc: RefLoc{Owner: to.Owner, Repo: to.Repo, Ref: p.Ref, SHA: to.SHA},
		Forced: p.Force,
	}

	client, err := s.Client()
	if err != nil && s.Execute {
		return Ref{}, err
	}
	if client != nil {
		previous, err := getString(ctx, client, gitRefReadPath(to.Owner, to.Repo, p.Ref), "object", "sha")
		if err := s.SoftRead(err, "read "+p.Ref); err != nil {
			return Ref{}, fmt.Errorf("read %s: %w", p.Ref, err)
		}
		out.PreviousSHA = previous
		if previous != "" && previous == to.SHA {
			s.Note(fmt.Sprintf("%s already points at %s, so nothing was sent", p.Ref, shortSHA(to.SHA)))
			return out, nil
		}
	}

	inverse := []UndoStep{}
	if out.PreviousSHA != "" {
		inverse = append(inverse, UndoStep{
			Method: http.MethodPatch, Path: path,
			Body: map[string]any{"sha": out.PreviousSHA, "force": true},
			Note: "restores the ref to " + out.PreviousSHA + "; the push event, the timeline entry and the audit record are not reversible",
		})
	}

	_, _, err = s.Mutate(ctx, Mutation{
		Method: http.MethodPatch, Path: path,
		Body:    map[string]any{"sha": to.SHA, "force": p.Force},
		Target:  to.Owner + "/" + to.Repo,
		Inverse: inverse,
	})
	return out, err
}

// gitRefWritePath is the plural form, which is the documented path for PATCH and
// DELETE only. POST takes /git/refs with the fully qualified refs/heads/x in the
// body; every read goes through gitRefReadPath.
func gitRefWritePath(owner, repo, ref string) string {
	return fmt.Sprintf("/repos/%s/%s/git/refs/%s", owner, repo, strings.TrimPrefix(ref, "refs/"))
}

// gitRefReadPath is the documented single-ref read, and the plural form is not a
// synonym for it: GET /git/refs/{ref} prefix-matches like matching-refs, so a ref
// that is absent while a longer one shares its name answers 200 with an array
// instead of the 404 an absence has to be. Every caller here turns on that 404 —
// an absent ref is nothing to delete, and a present one is a ref to adopt rather
// than create twice.
func gitRefReadPath(owner, repo, ref string) string {
	return fmt.Sprintf("/repos/%s/%s/git/ref/%s", owner, repo, strings.TrimPrefix(ref, "refs/"))
}

// resolveCommitish turns a branch name, tag name or sha into a commit sha
// through one endpoint, so an author writes from: main and from: v1.2.3 the same
// way.
func resolveCommitish(ctx context.Context, s *Session, owner, repo, ref string) (string, error) {
	client, err := s.Client()
	if err != nil {
		if err := s.SoftRead(err, "resolve "+ref); err != nil {
			return "", err
		}
		return "", nil
	}
	sha, err := getString(ctx, client, fmt.Sprintf("/repos/%s/%s/commits/%s", owner, repo, ref), "sha")
	if err := s.SoftRead(err, "resolve "+ref); err != nil {
		return "", fmt.Errorf("resolve %s in %s/%s: %w", ref, owner, repo, err)
	}
	return sha, nil
}
