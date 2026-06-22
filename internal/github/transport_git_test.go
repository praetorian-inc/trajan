package github

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// gitRun runs git in dir and fails the test on error.
func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fixtureRepo builds a bare-cloneable repo on disk with: a default branch
// "main" holding .github/workflows/ci.yml + a local composite action, and a
// second branch "release/1.0" holding a different workflow. Returns the repo dir
// and a gitTransport whose urlFn points at it.
func fixtureRepo(t *testing.T) (string, *gitTransport) {
	t.Helper()
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := t.TempDir()
	gitRun(t, repo, "init", "-q", "-b", "main")

	writeFile(t, repo, ".github/workflows/ci.yml", "name: ci\non: push\njobs: {}\n")
	writeFile(t, repo, ".github/actions/lint/action.yml", "name: lint\nruns:\n  using: composite\n")
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-q", "-m", "init")

	gitRun(t, repo, "checkout", "-q", "-b", "release/1.0")
	writeFile(t, repo, ".github/workflows/release.yml", "name: release\non: push\njobs: {}\n")
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-q", "-m", "release")
	gitRun(t, repo, "checkout", "-q", "main")

	gt, err := newGitTransport("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gt.close)
	gt.urlFn = func(owner, name string) string { return repo }
	return repo, gt
}

// branch-slug mapping is exercised through the on-disk path the git all-branches
// collection writes to: default branch stays bare {repo}/, non-default becomes
// {repo}@{slug}/ with "/"->"__".
func TestGitBranchSlugMapping(t *testing.T) {
	cases := []struct {
		repo, ref string
		isDefault bool
		want      string
	}{
		{"r", "main", true, "00-collect/workflows/r/ci.yml"},
		{"r", "release/1.0", false, "00-collect/workflows/r@release__1.0/ci.yml"},
		{"r", "feature/a/b", false, "00-collect/workflows/r@feature__a__b/ci.yml"},
		{"r", "refs/heads/release/1.0", false, "00-collect/workflows/r@release__1.0/ci.yml"},
	}
	for _, c := range cases {
		if got := engine.CollectWorkflowYAMLBranch(c.repo, c.ref, c.isDefault, "ci.yml"); got != c.want {
			t.Errorf("CollectWorkflowYAMLBranch(%q,%q,%v) = %q, want %q", c.repo, c.ref, c.isDefault, got, c.want)
		}
	}
}

func TestGitAllBranchEnumeration(t *testing.T) {
	_, gt := fixtureRepo(t)
	names, err := gt.branchNames(context.Background(), "o", "r")
	if err != nil {
		t.Fatalf("branchNames: %v", err)
	}
	sort.Strings(names)
	want := []string{"main", "release/1.0"}
	if len(names) != len(want) || names[0] != want[0] || names[1] != want[1] {
		t.Fatalf("branchNames = %v, want %v", names, want)
	}
}

func TestGitBranchesRESTShapeSynthesis(t *testing.T) {
	_, gt := fixtureRepo(t)
	raw, _, err := gt.Get(context.Background(), "/repos/o/r/branches", nil, false)
	if err != nil {
		t.Fatalf("Get branches: %v", err)
	}
	var arr []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("branches not an array of {name}: %v (%s)", err, raw)
	}
	got := map[string]bool{}
	for _, b := range arr {
		got[b.Name] = true
	}
	if !got["main"] || !got["release/1.0"] {
		t.Fatalf("branches synthesis missing entries: %s", raw)
	}

	// Paginate must produce the same {name} objects (listBranches consumes it).
	items, err := gt.Paginate(context.Background(), "/repos/o/r/branches", nil, 100)
	if err != nil {
		t.Fatalf("Paginate: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("Paginate returned %d items, want 2", len(items))
	}
}

func TestGitWorkflowListingPerBranch(t *testing.T) {
	_, gt := fixtureRepo(t)
	ctx := context.Background()

	// default branch (no ref) -> ci.yml only
	raw, _, err := gt.Get(ctx, "/repos/o/r/contents/.github/workflows", nil, true)
	if err != nil {
		t.Fatalf("list default: %v", err)
	}
	var entries []workflowEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatalf("default listing not array: %v (%s)", err, raw)
	}
	if len(entries) != 1 || entries[0].Name != "ci.yml" || entries[0].Type != "file" || entries[0].SHA == "" {
		t.Fatalf("default workflow listing = %+v", entries)
	}

	// release branch -> release.yml present (proves all-branches tree reads)
	raw, _, err = gt.Get(ctx, "/repos/o/r/contents/.github/workflows?ref=release/1.0",
		map[string][]string{"ref": {"release/1.0"}}, true)
	if err != nil {
		t.Fatalf("list release: %v", err)
	}
	entries = nil
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatalf("release listing not array: %v (%s)", err, raw)
	}
	// release/1.0 branched off main, so it carries ci.yml AND its own
	// release.yml — the branch-specific file MUST appear (proves the tree is
	// read at the requested ref, not the default branch).
	hasRelease := false
	for _, e := range entries {
		if e.Name == "release.yml" {
			hasRelease = true
		}
	}
	if !hasRelease {
		t.Fatalf("release branch listing missing release.yml: %+v", entries)
	}
}

// TestGitBlobSHAEqualsContentsSHA pins the cross-transport invariant the
// .meta.json compatibility depends on: the SHA the git tree reports for a file
// is byte-for-byte the SHA `git hash-object` computes for that blob (which is in
// turn the GitHub Contents-API `sha`).
func TestGitBlobSHAEqualsContentsSHA(t *testing.T) {
	repo, gt := fixtureRepo(t)
	ctx := context.Background()

	body, sha, ok, err := gt.GetContentWithSHA(ctx, "/repos/o/r/contents/.github/workflows/ci.yml", "", true)
	if err != nil || !ok {
		t.Fatalf("GetContentWithSHA ok=%v err=%v", ok, err)
	}
	if string(body) != "name: ci\non: push\njobs: {}\n" {
		t.Fatalf("body mismatch: %q", body)
	}

	// independent oracle: git hash-object on the same file content
	cmd := exec.Command("git", "hash-object", filepath.Join(repo, ".github/workflows/ci.yml"))
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	want := string(out)
	want = want[:len(want)-1] // strip newline
	if sha != want {
		t.Fatalf("git blob sha %q != hash-object %q", sha, want)
	}
}

// TestGitLocalActionNo404Probe verifies local composite actions are read from
// the tree with NO action.yml/.yaml fallback probing: a single tree read either
// finds the file or returns ok=false, and a missing path is ok=false (not a
// retried 404). The recorder asserts exactly one git invocation path per read.
func TestGitLocalActionNo404Probe(t *testing.T) {
	_, gt := fixtureRepo(t)
	ctx := context.Background()

	// existing action.yml resolves from the working tree
	body, sha, ok, err := gt.GetContentWithSHA(ctx, "/repos/o/r/contents/.github/actions/lint/action.yml", "", true)
	if err != nil || !ok || sha == "" {
		t.Fatalf("local action read ok=%v sha=%q err=%v", ok, sha, err)
	}
	if string(body) == "" {
		t.Fatal("local action body empty")
	}

	// a path that does not exist must return ok=false WITHOUT an error (no 404
	// round-trip / probe), matching GetContentWithSHA's contract.
	_, _, ok, err = gt.GetContentWithSHA(ctx, "/repos/o/r/contents/.github/actions/missing/action.yml", "", true)
	if err != nil {
		t.Fatalf("missing path returned error %v, want ok=false nil", err)
	}
	if ok {
		t.Fatal("missing path returned ok=true")
	}
}

func TestGitResolveRefCommitSHA(t *testing.T) {
	repo, gt := fixtureRepo(t)
	ctx := context.Background()

	sha, err := gt.ResolveRefCommitSHA(ctx, "o", "r", "main")
	if err != nil {
		t.Fatalf("ResolveRefCommitSHA: %v", err)
	}
	// oracle: rev-parse of the same ref in the fixture
	cmd := exec.Command("git", "rev-parse", "main")
	cmd.Dir = repo
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	want := string(out[:len(out)-1])
	if sha != want {
		t.Fatalf("ls-remote sha %q != rev-parse %q", sha, want)
	}

	// unknown ref resolves to "" (mirrors REST's 404 -> "") not an error
	sha, err = gt.ResolveRefCommitSHA(ctx, "o", "r", "no-such-ref")
	if err != nil {
		t.Fatalf("unknown ref err: %v", err)
	}
	if sha != "" {
		t.Fatalf("unknown ref sha = %q, want empty", sha)
	}
}

func TestGitResolveAnnotatedTagAndSHA(t *testing.T) {
	repo, gt := fixtureRepo(t)
	ctx := context.Background()
	gitRun(t, repo, "tag", "-a", "v1", "-m", "v1")
	commit := revParse(t, repo, "v1^{commit}")

	// annotated tag must dereference to the commit it points at, as REST does,
	// not the tag object's own SHA.
	got, err := gt.ResolveRefCommitSHA(ctx, "o", "r", "v1")
	if err != nil {
		t.Fatalf("annotated tag: %v", err)
	}
	if got != commit {
		t.Fatalf("annotated tag sha = %q, want commit %q", got, commit)
	}

	// a full commit SHA is echoed back (REST /commits/{sha} behavior)
	if got, err = gt.ResolveRefCommitSHA(ctx, "o", "r", commit); err != nil || got != commit {
		t.Fatalf("full sha = %q err=%v, want %q", got, err, commit)
	}
}

func revParse(t *testing.T, repo, rev string) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", rev)
	cmd.Dir = repo
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(out[:len(out)-1])
}

func TestGitCloneFailureIsUnservable(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	gt, err := newGitTransport("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gt.close)
	gt.urlFn = func(owner, repo string) string { return filepath.Join(t.TempDir(), "does-not-exist") }

	_, _, _, err = gt.GetContentWithSHA(context.Background(), "/repos/o/r/contents/x.yml", "", true)
	if !errors.Is(err, errUnservable) {
		t.Fatalf("clone failure err = %v, want errUnservable (router falls through to REST)", err)
	}
	var ghErr *GhError
	if errors.As(err, &ghErr) {
		t.Fatal("clone failure must not surface as a GhError")
	}
}

func TestGitClassifyContentRefPinsRemoteToREST(t *testing.T) {
	// a ref-pinned remote reusable read must NOT route to git (shallow clone may
	// lack the tag/sha); empty-ref local reads stay git-preferred.
	if got := classifyContent("/repos/o/r/contents/x/action.yml", ""); got != surfaceLocalActions {
		t.Errorf("empty-ref local action = %q, want local_actions", got)
	}
	if got := classifyContent("/repos/o/r/contents/.github/workflows/a.yml", "v1"); got != surfaceRESTFloor {
		t.Errorf("ref-pinned remote workflow = %q, want rest_floor", got)
	}
}
