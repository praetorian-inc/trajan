package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync"
)

// gitTransport serves the git-preferred surfaces (workflow files across all
// branches, local composite actions, branch list, marketplace ref->SHA) from a
// shallow all-branches clone. It synthesizes REST-shaped responses, and the git
// blob SHA equals the Contents-API `sha`, so on-disk data/.meta.json stay
// byte-compatible. A repo/path git cannot serve yields errUnservable (router
// falls through to REST); a path absent in a cloned tree yields ok=false.
type gitTransport struct {
	token string
	base  string
	// urlFn is overridable in tests to point at a local fixture repo.
	urlFn func(owner, repo string) string

	mu     sync.Mutex
	clones map[string]*gitClone
}

type gitClone struct {
	once sync.Once
	dir  string
	err  error
}

func (*gitTransport) kind() transportKind { return transportGit }

var _ transport = (*gitTransport)(nil)

func gitAvailable() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// sourceAPI is the provenance string for the transport serving s; it is
// github_rest unless gh is the router with a non-REST preference for s.
func sourceAPI(gh GitHub, s surface) string {
	if r, ok := gh.(*router); ok {
		return r.sourceAPIFor(s)
	}
	return "github_rest"
}

func newGitTransport(token string) (*gitTransport, error) {
	base, err := os.MkdirTemp("", "trajan-git-")
	if err != nil {
		return nil, err
	}
	g := &gitTransport{token: token, base: base, clones: map[string]*gitClone{}}
	g.urlFn = g.githubURL
	return g, nil
}

func (g *gitTransport) close() {
	if g != nil && g.base != "" {
		_ = os.RemoveAll(g.base)
	}
}

// notServable wraps errUnservable so the router falls through to REST; it is not
// a genuine 404.
func notServable(repoOrPath string) error {
	return fmt.Errorf("%w: %s", errUnservable, repoOrPath)
}

func (g *gitTransport) repoURL(owner, repo string) string {
	return g.urlFn(owner, repo)
}

func (g *gitTransport) githubURL(owner, repo string) string {
	if g.token != "" {
		return fmt.Sprintf("https://x-access-token:%s@github.com/%s/%s.git", g.token, owner, repo)
	}
	return fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
}

// ensureClone shallow-clones every branch once (D2.5), caching the dir or the
// clone error so a failed repo is not retried.
func (g *gitTransport) ensureClone(ctx context.Context, owner, repo string) (string, error) {
	key := owner + "/" + repo
	g.mu.Lock()
	c, ok := g.clones[key]
	if !ok {
		c = &gitClone{}
		g.clones[key] = c
	}
	g.mu.Unlock()

	c.once.Do(func() {
		dir := path.Join(g.base, owner+"__"+repo)
		url := g.repoURL(owner, repo)
		if _, err := g.run(ctx, "", "clone", "--depth", "1", "--no-single-branch", "--no-tags", url, dir); err != nil {
			c.err = notServable(key)
			return
		}
		if _, err := g.run(ctx, dir, "remote", "set-branches", "origin", "*"); err != nil {
			c.err = notServable(key)
			return
		}
		if _, err := g.run(ctx, dir, "fetch", "--depth", "1", "--no-tags", "origin"); err != nil {
			c.err = notServable(key)
			return
		}
		c.dir = dir
	})
	return c.dir, c.err
}

func (g *gitTransport) run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", args[0], err, g.redact(stderr.String()))
	}
	return []byte(stdout.String()), nil
}

func (g *gitTransport) redact(s string) string {
	if g.token == "" {
		return s
	}
	return strings.ReplaceAll(s, g.token, "***")
}

// gitRef maps a branch to its remote-tracking ref; "" means the default branch.
func gitRef(branch string) string {
	if branch == "" {
		return "origin/HEAD"
	}
	return "origin/" + branch
}

func (g *gitTransport) Get(ctx context.Context, p string, params url.Values, allow404 bool) (json.RawMessage, http.Header, error) {
	switch {
	case strings.Contains(p, "/contents/.github/workflows"):
		return g.listWorkflows(ctx, p, params, allow404)
	case strings.HasSuffix(p, "/branches") || strings.Contains(p, "/branches?"):
		return g.listBranchesREST(ctx, p)
	}
	return nil, nil, notServable(p)
}

func (g *gitTransport) Paginate(ctx context.Context, p string, params url.Values, perPage int) ([]json.RawMessage, error) {
	if !strings.Contains(p, "/branches") {
		return nil, notServable(p)
	}
	owner, repo, err := parseRepoPath(p)
	if err != nil {
		return nil, notServable(p)
	}
	names, err := g.branchNames(ctx, owner, repo)
	if err != nil {
		return nil, err
	}
	out := make([]json.RawMessage, 0, len(names))
	for _, n := range names {
		out = append(out, json.RawMessage(`{"name":`+jsonString(n)+`}`))
	}
	return out, nil
}

func (g *gitTransport) GetRaw(ctx context.Context, p string, params url.Values, accept string) ([]byte, http.Header, error) {
	owner, repo, pathInRepo, err := parseContentsPath(p)
	if err != nil {
		return nil, nil, notServable(p)
	}
	body, _, ok, err := g.readBlob(ctx, owner, repo, pathInRepo, params.Get("ref"))
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, notServable(p)
	}
	return body, http.Header{}, nil
}

func (g *gitTransport) GetContentWithSHA(ctx context.Context, p, ref string, allow404 bool) ([]byte, string, bool, error) {
	owner, repo, pathInRepo, err := parseContentsPath(p)
	if err != nil {
		return nil, "", false, notServable(p)
	}
	return g.readBlob(ctx, owner, repo, pathInRepo, ref)
}

func (g *gitTransport) ResolveRefCommitSHA(ctx context.Context, owner, repo, ref string) (string, error) {
	// A full SHA matches no ref via ls-remote, so echo it back like REST.
	if isFullSHA(ref) {
		return ref, nil
	}
	// Request the peeled form too so an annotated tag resolves to the commit it
	// points at, as REST does, rather than the tag object's own SHA.
	out, err := g.run(ctx, "", "ls-remote", g.repoURL(owner, repo), ref, ref+"^{}")
	if err != nil {
		return "", notServable(owner + "/" + repo)
	}
	return parseLsRemoteSHA(string(out)), nil
}

// parseLsRemoteSHA prefers the peeled "<ref>^{}" line (an annotated tag's commit)
// over the tag object's line; empty when the ref is unknown.
func parseLsRemoteSHA(out string) string {
	var direct string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		if strings.HasSuffix(fields[1], "^{}") {
			return fields[0]
		}
		if direct == "" {
			direct = fields[0]
		}
	}
	return direct
}

func isFullSHA(ref string) bool {
	if len(ref) != 40 {
		return false
	}
	for _, c := range ref {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func (g *gitTransport) branchNames(ctx context.Context, owner, repo string) ([]string, error) {
	dir, err := g.ensureClone(ctx, owner, repo)
	if err != nil {
		return nil, err
	}
	out, err := g.run(ctx, dir, "for-each-ref", "--format=%(refname:short)", "refs/remotes/origin")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "origin/HEAD" || line == "origin" {
			continue
		}
		name := strings.TrimPrefix(line, "origin/")
		if name == "HEAD" || name == "" {
			continue
		}
		names = append(names, name)
	}
	return names, nil
}

func (g *gitTransport) listBranchesREST(ctx context.Context, p string) (json.RawMessage, http.Header, error) {
	owner, repo, err := parseRepoPath(p)
	if err != nil {
		return nil, nil, notServable(p)
	}
	names, err := g.branchNames(ctx, owner, repo)
	if err != nil {
		return nil, nil, err
	}
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, `{"name":`+jsonString(n)+`}`)
	}
	return json.RawMessage("[" + strings.Join(parts, ",") + "]"), http.Header{}, nil
}

func (g *gitTransport) listWorkflows(ctx context.Context, p string, params url.Values, allow404 bool) (json.RawMessage, http.Header, error) {
	owner, repo, err := parseRepoPath(p)
	if err != nil {
		return nil, nil, notServable(p)
	}
	dir, err := g.ensureClone(ctx, owner, repo)
	if err != nil {
		return nil, nil, err
	}
	ref := gitRef(params.Get("ref"))
	entries, err := g.lsTree(ctx, dir, ref, ".github/workflows")
	if err != nil {
		// An absent dir is empty output, not an error; an error means git cannot
		// serve this ref, so fall through to REST.
		return nil, nil, notServable(p)
	}
	if len(entries) == 0 {
		if allow404 {
			return nil, http.Header{}, nil
		}
		return json.RawMessage("[]"), http.Header{}, nil
	}
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		parts = append(parts, fmt.Sprintf(
			`{"name":%s,"type":%s,"sha":%s,"size":%d}`,
			jsonString(e.name), jsonString(e.typ), jsonString(e.sha), e.size))
	}
	return json.RawMessage("[" + strings.Join(parts, ",") + "]"), http.Header{}, nil
}

type treeEntry struct {
	name string
	typ  string // "file"/"dir", matching the Contents-API type field
	sha  string
	size int64
}

func (g *gitTransport) lsTree(ctx context.Context, cloneDir, ref, dirInRepo string) ([]treeEntry, error) {
	out, err := g.run(ctx, cloneDir, "ls-tree", "--long", ref, dirInRepo+"/")
	if err != nil {
		return nil, err
	}
	var entries []treeEntry
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		// "<mode> <type> <sha> <size>\t<path>"
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			continue
		}
		meta := strings.Fields(line[:tab])
		fullPath := line[tab+1:]
		if len(meta) < 3 {
			continue
		}
		objType := meta[1]
		sha := meta[2]
		var size int64
		if len(meta) >= 4 && meta[3] != "-" {
			size, _ = strconv.ParseInt(meta[3], 10, 64)
		}
		typ := "file"
		if objType == "tree" {
			typ = "dir"
		}
		entries = append(entries, treeEntry{name: path.Base(fullPath), typ: typ, sha: sha, size: size})
	}
	return entries, nil
}

// readBlob returns a file's bytes + git blob SHA at ref. A missing path, dir,
// symlink, or submodule is ok=false with no error (no 404 probe), matching
// GetContentWithSHA's contract.
func (g *gitTransport) readBlob(ctx context.Context, owner, repo, pathInRepo, branch string) ([]byte, string, bool, error) {
	dir, err := g.ensureClone(ctx, owner, repo)
	if err != nil {
		return nil, "", false, err
	}
	ref := gitRef(branch)
	out, err := g.run(ctx, dir, "ls-tree", "--long", ref, pathInRepo)
	if err != nil {
		return nil, "", false, notServable(pathInRepo)
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return nil, "", false, nil
	}
	tab := strings.IndexByte(line, '\t')
	if tab < 0 {
		return nil, "", false, nil
	}
	meta := strings.Fields(line[:tab])
	if len(meta) < 3 {
		return nil, "", false, nil
	}
	mode, objType, sha := meta[0], meta[1], meta[2]
	if objType != "blob" || mode == "120000" {
		return nil, "", false, nil
	}
	body, err := g.run(ctx, dir, "cat-file", "blob", sha)
	if err != nil {
		return nil, "", false, notServable(pathInRepo)
	}
	return body, sha, true, nil
}

func parseRepoPath(p string) (owner, repo string, err error) {
	p = stripQuery(p)
	rest := strings.TrimPrefix(p, "/repos/")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", errors.New("not a repo path: " + p)
	}
	return parts[0], parts[1], nil
}

func parseContentsPath(p string) (owner, repo, pathInRepo string, err error) {
	p = stripQuery(p)
	rest := strings.TrimPrefix(p, "/repos/")
	idx := strings.Index(rest, "/contents/")
	if idx < 0 {
		return "", "", "", errors.New("not a contents path: " + p)
	}
	head := rest[:idx]
	pathInRepo = rest[idx+len("/contents/"):]
	parts := strings.Split(head, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", errors.New("not a contents path: " + p)
	}
	return parts[0], parts[1], pathInRepo, nil
}

func stripQuery(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
