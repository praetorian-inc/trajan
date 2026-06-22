package github

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// router implements GitHub by dispatching each call to the highest-preference
// transport capable of serving its surface, falling through to the REST floor on
// failure (D2.1/D2.4).
type router struct {
	transports map[transportKind]transport
	forceREST  bool
	// git, when set, owns a temp clone dir released by closeRouter.
	git *gitTransport
}

var _ GitHub = (*router)(nil)

func newRouter(rest *Client) *router {
	r := &router{
		transports: map[transportKind]transport{
			transportREST: restTransport{rest},
		},
		forceREST: os.Getenv("TRAJAN_FORCE_REST") != "",
	}
	if !r.forceREST {
		if gitAvailable() {
			if gt, err := newGitTransport(rest.token); err == nil {
				r.transports[transportGit] = gt
				r.git = gt
			} else {
				slog.Warn("git transport unavailable, falling back to rest", "err", err)
			}
		}
		r.transports[transportGraphQL] = newGraphQLTransport(rest)
	}
	return r
}

func closeRouter(gh GitHub) {
	if r, ok := gh.(*router); ok {
		r.git.close()
	}
}

// sourceAPIFor reports the provenance of the preferred transport for s (D2.6); it
// ignores per-call fall-through, which only affects this cosmetic field.
func (r *router) sourceAPIFor(s surface) string {
	cands := r.candidates(s)
	if len(cands) == 0 {
		return "github_rest"
	}
	switch cands[0].kind() {
	case transportGit:
		return "github_git"
	case transportGraphQL:
		return "github_graphql"
	default:
		return "github_rest"
	}
}

// localRetries is the per-transport retry budget before fall-through, kept small:
// the transports' own clients already back off on Retry-After/x-ratelimit-reset.
const localRetries = 2

func (r *router) candidates(s surface) []transport {
	if r.forceREST {
		if t, ok := r.transports[transportREST]; ok {
			return []transport{t}
		}
		return nil
	}
	capable := capabilityMatrix[s]
	var out []transport
	for _, k := range preferenceOrder {
		if !containsKind(capable, k) {
			continue
		}
		if t, ok := r.transports[k]; ok {
			out = append(out, t)
		}
	}
	return out
}

func containsKind(ks []transportKind, k transportKind) bool {
	for _, x := range ks {
		if x == k {
			return true
		}
	}
	return false
}

func isUnservable(err error) bool {
	return errors.Is(err, errUnservable)
}

// isTransient reports errors worth a local retry (429, 5xx, secondary-rate-limit,
// or a bare transport error). A definitive 404/permission-403 is not transient.
func isTransient(err error) bool {
	if err == nil || isUnservable(err) {
		return false
	}
	var ghErr *GhError
	if errors.As(err, &ghErr) {
		switch {
		case ghErr.Status == 429:
			return true
		case ghErr.Status >= 500:
			return true
		case ghErr.Status == 403 && strings.Contains(strings.ToLower(ghErr.Body), "secondary rate limit"):
			return true
		}
		return false
	}
	return true
}

func backoff(ctx context.Context, attempt int) {
	sec := 0.25 * float64(int(1)<<attempt)
	if sec > 2 {
		sec = 2
	}
	sleepFn(ctx, sec)
}

// dispatch tries each candidate transport for s: an unservable error falls
// through at once, a transient one retries with capped backoff then falls
// through, and a definitive error is returned as-is for the collector to handle.
func dispatch[T any](ctx context.Context, r *router, s surface, zero T, call func(transport) (T, error)) (T, error) {
	cands := r.candidates(s)
	if len(cands) == 0 {
		return zero, errors.New("github router: no transport available for surface " + string(s))
	}
	var lastErr error
	for _, t := range cands {
		for attempt := 0; ; attempt++ {
			v, err := call(t)
			if err == nil {
				return v, nil
			}
			lastErr = err
			if isUnservable(err) {
				slog.Debug("github router fall-through (unservable)", "from", t.kind(), "surface", s, "err", err)
				break
			}
			if !isTransient(err) {
				return zero, err
			}
			if attempt >= localRetries {
				slog.Debug("github router fall-through (throttle)", "from", t.kind(), "surface", s, "err", lastErr)
				break
			}
			backoff(ctx, attempt)
		}
	}
	return zero, lastErr
}

func (r *router) Get(ctx context.Context, p string, params url.Values, allow404 bool) (json.RawMessage, http.Header, error) {
	type res struct {
		body json.RawMessage
		hdr  http.Header
	}
	v, err := dispatch(ctx, r, classifyGet(p), res{}, func(t transport) (res, error) {
		b, h, e := t.Get(ctx, p, params, allow404)
		return res{b, h}, e
	})
	return v.body, v.hdr, err
}

func (r *router) GetRaw(ctx context.Context, p string, params url.Values, accept string) ([]byte, http.Header, error) {
	type res struct {
		body []byte
		hdr  http.Header
	}
	v, err := dispatch(ctx, r, classifyGet(p), res{}, func(t transport) (res, error) {
		b, h, e := t.GetRaw(ctx, p, params, accept)
		return res{b, h}, e
	})
	return v.body, v.hdr, err
}

func (r *router) GetContentWithSHA(ctx context.Context, p, ref string, allow404 bool) ([]byte, string, bool, error) {
	type res struct {
		body []byte
		sha  string
		ok   bool
	}
	v, err := dispatch(ctx, r, classifyContent(p, ref), res{}, func(t transport) (res, error) {
		b, sha, ok, e := t.GetContentWithSHA(ctx, p, ref, allow404)
		return res{b, sha, ok}, e
	})
	return v.body, v.sha, v.ok, err
}

func (r *router) ResolveRefCommitSHA(ctx context.Context, owner, repo, ref string) (string, error) {
	return dispatch(ctx, r, surfaceRefResolve, "", func(t transport) (string, error) {
		return t.ResolveRefCommitSHA(ctx, owner, repo, ref)
	})
}

func (r *router) Paginate(ctx context.Context, p string, params url.Values, perPage int) ([]json.RawMessage, error) {
	return dispatch(ctx, r, classifyGet(p), nil, func(t transport) ([]json.RawMessage, error) {
		return t.Paginate(ctx, p, params, perPage)
	})
}

// classifyGet maps a REST path to its surface; anything not explicitly
// offloadable defaults to the REST floor.
func classifyGet(p string) surface {
	switch {
	case strings.Contains(p, "/contents/.github/workflows"):
		return surfaceWorkflowFiles
	case strings.Contains(p, "/branches") && !strings.Contains(p, "/protection"):
		return surfaceBranchRefs
	case strings.Contains(p, "/commits/"):
		return surfaceRefResolve
	case strings.Contains(p, "/orgs/") && offloadableOrgMembers(p):
		return surfaceOrgMembers
	case strings.HasSuffix(stripQuery(p), "/topics"):
		return surfaceRepoTopics
	case isBareRepo(p):
		return surfaceRepoMeta
	default:
		return surfaceRESTFloor
	}
}

// classifyContent keeps workflow files and local actions on git, but routes a
// ref-pinned remote read to the REST floor: the shallow all-branches clone does
// not hold arbitrary tags/SHAs.
func classifyContent(p, ref string) surface {
	switch {
	case strings.Contains(p, "/contents/.github/workflows"):
		if ref != "" {
			return surfaceRESTFloor
		}
		return surfaceWorkflowFiles
	case strings.Contains(p, "/contents/"):
		if ref != "" {
			return surfaceRESTFloor
		}
		return surfaceLocalActions
	default:
		return surfaceRESTFloor
	}
}

func offloadableOrgMembers(p string) bool {
	tail := p
	if i := strings.Index(p, "/orgs/"); i >= 0 {
		tail = p[i+len("/orgs/"):]
		if j := strings.IndexByte(tail, '/'); j >= 0 {
			tail = tail[j:]
		} else {
			return false
		}
	}
	// /members but not /members/{user} membership checks.
	return tail == "/members" || strings.HasPrefix(tail, "/members?")
}

func isBareRepo(p string) bool {
	if !strings.HasPrefix(p, "/repos/") {
		return false
	}
	parts := strings.Split(stripQuery(strings.TrimPrefix(p, "/repos/")), "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] != ""
}
