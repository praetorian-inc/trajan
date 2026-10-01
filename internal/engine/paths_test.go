package engine

import (
	"path"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectPaths(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"CollectOrg", CollectOrg("acme"), "00-collect/org/acme.json"},
		{"CollectRepo", CollectRepo("repo1"), "00-collect/repos/repo1.json"},
		{"CollectActionsSettings", CollectActionsSettings("repo1"), "00-collect/actions-settings/repo1.json"},
		{"CollectWorkflowYAML", CollectWorkflowYAML("repo1", "ci.yml"), "00-collect/workflows/repo1/ci.yml"},
		{"CollectWorkflowMeta", CollectWorkflowMeta("repo1", "ci.yml"), "00-collect/workflows/repo1/ci.yml.meta.json"},
		{"CollectActionYAML", CollectActionYAML("actions", "checkout", "", "v4"),
			"00-collect/actions/actions__checkout___root@v4.yaml"},
		{"CollectActionYAML-path", CollectActionYAML("owner", "repo", "sub/dir", "main"),
			"00-collect/actions/owner__repo__sub__dir@main.yaml"},
		{"CollectActionMeta", CollectActionMeta("owner", "repo", "sub/dir", "main"),
			"00-collect/actions/owner__repo__sub__dir@main.meta.json"},
		{"CollectRefResolution", CollectRefResolution("actions", "checkout", "v4"),
			"00-collect/action-resolutions/actions__checkout@v4.json"},
		{"CollectRefResolution-slash-ref", CollectRefResolution("o", "r", "refs/tags/v1"),
			"00-collect/action-resolutions/o__r@refs__tags__v1.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestNormalizeAndScanPaths(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"NormalizeJob", NormalizeJob("repo1", "ci.yml", "build"),
			"10-normalize/jobs/repo1__ci__build.json"},
		{"NormalizeJob-yaml", NormalizeJob("repo1", "ci.yaml", "build"),
			"10-normalize/jobs/repo1__ci__build.json"},
		{"NormalizeJob-empty-wf", NormalizeJob("repo1", "", "build"),
			"10-normalize/jobs/repo1____build.json"},
		{"NormalizeJob-underscore-stem", NormalizeJob("inputs", "_build.yml", "pkg"),
			"10-normalize/jobs/inputs___build__pkg.json"},
		{"Finding", Finding("P01-prt-checkout-execute", "abc123def456"),
			"20-scan/findings/P01-prt-checkout-execute__abc123def456.json"},
		{"ScanSummary", ScanSummary(), "20-scan/_summary.json"},
		{"RunMeta", RunMeta(), "_meta.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestSafePath(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", "_root"},
		{"/", "_root"},
		{"a/b", "a__b"},
		{"/leading", "leading"},
		{"__abc", "abc"},
		{"sub/dir/x", "sub__dir__x"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := safePath(tt.in); got != tt.want {
				t.Errorf("safePath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSafeRef(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"v4", "v4"},
		{"refs/heads/main", "refs__heads__main"},
		{"release/1.0", "release__1.0"},
	}
	for _, tt := range tests {
		if got := safeRef(tt.in); got != tt.want {
			t.Errorf("safeRef(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestWFStem(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"ci.yml", "ci"},
		{"ci.yaml", "ci"},
		{"ci", "ci"},
		{"", ""},
		{"x.yml.yaml", "x.yml"},
		{"x.yaml.yml", "x"},
	}
	for _, tt := range tests {
		if got := wfStem(tt.in); got != tt.want {
			t.Errorf("wfStem(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestBranchSlug(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"main", "main"},
		{"refs/heads/main", "main"},
		{"release/1.0", "release__1.0"},
		{"refs/heads/feature/x", "feature__x"},
	}
	for _, tt := range tests {
		if got := BranchSlug(tt.in); got != tt.want {
			t.Errorf("BranchSlug(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestBranchBuildersDefaultMatchLegacy(t *testing.T) {
	repo, file, ref := "repo1", "ci.yml", "main"
	if got, want := CollectWorkflowYAMLBranch(repo, ref, true, file), CollectWorkflowYAML(repo, file); got != want {
		t.Errorf("CollectWorkflowYAMLBranch default = %q, want legacy %q", got, want)
	}
	if got, want := CollectWorkflowMetaBranch(repo, ref, true, file), CollectWorkflowMeta(repo, file); got != want {
		t.Errorf("CollectWorkflowMetaBranch default = %q, want legacy %q", got, want)
	}
	if got, want := NormalizeJobBranch(repo, ref, true, file, "build"), NormalizeJob(repo, file, "build"); got != want {
		t.Errorf("NormalizeJobBranch default = %q, want legacy %q", got, want)
	}
	if got, want := NormalizeJobBranch(repo, ref, true, "", "build"), NormalizeJob(repo, "", "build"); got != want {
		t.Errorf("NormalizeJobBranch empty-wf default = %q, want legacy %q", got, want)
	}
}

func TestBranchBuildersNonDefault(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"yaml", CollectWorkflowYAMLBranch("repo1", "release/1.0", false, "ci.yml"),
			"00-collect/workflows/repo1@release__1.0/ci.yml"},
		{"meta", CollectWorkflowMetaBranch("repo1", "release/1.0", false, "ci.yml"),
			"00-collect/workflows/repo1@release__1.0/ci.yml.meta.json"},
		{"job", NormalizeJobBranch("repo1", "release/1.0", false, "ci.yml", "build"),
			"10-normalize/jobs/repo1@release__1.0__ci__build.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

// The composite key must hash to a bounded, collision-free filename: distinct keys
// never share a file (adoKey's "__"->"--" folding used to alias them), and a long key
// never overflows the 255-byte path limit.
func TestNormalizeADOEdgesBoundedDistinct(t *testing.T) {
	a := NormalizeADOEdges("has-policy", "foo-bar__baz")
	b := NormalizeADOEdges("has-policy", "foo__bar-baz")
	if a == b {
		t.Errorf("distinct composite keys collided to %q", a)
	}
	long := NormalizeADOEdges("uses-connection", strings.Repeat("refs/heads/very-long-branch/", 40))
	if base := path.Base(long); len(base) > 64 {
		t.Errorf("edge filename not bounded: %d bytes (%q)", len(base), base)
	}
}

func TestFoldedKeysAreInjective(t *testing.T) {
	groups := map[string][]string{
		"GHKey":  {"evil workflow.yml", "evil-workflow.yml", "evil/workflow.yml", "evil:workflow.yml"},
		"glKey":  {"acme/api-server", "acme/api/server", "acme-api-server", "acme_api_server"},
		"adoKey": {"Team_A", "Team-A", "Team A", "Team/A"},
	}
	fns := map[string]func(string) string{"GHKey": GHKey, "glKey": glKey, "adoKey": adoKey}
	for name, inputs := range groups {
		t.Run(name, func(t *testing.T) {
			seen := map[string]string{}
			for _, in := range inputs {
				got := fns[name](in)
				if prev, dup := seen[got]; dup {
					t.Errorf("%q and %q both key to %q", prev, in, got)
				}
				seen[got] = in
				if strings.ContainsAny(got, `/\`) || got == "." || got == ".." {
					t.Errorf("%q keys to %q, which is not a single safe path segment", in, got)
				}
			}
		})
	}
}

func TestGHKeyLeavesACleanScopeKeyUnchanged(t *testing.T) {
	for _, s := range []string{"acme", "acme__prod", "ci.yml", "release__1.0"} {
		if got := GHKey(s); got != s {
			t.Errorf("GHKey(%q) = %q; existing GitHub paths and fingerprints move", s, got)
		}
	}
}

func TestGLRepoPathsConfineARemoteFilePath(t *testing.T) {
	const proj = "g/p"
	for _, in := range []string{"../../etc/passwd", "/etc/passwd", "a/../../b", "..\\..\\win"} {
		for dir, got := range map[string]string{
			"ci-config":  CollectGLCIConfig(proj, in),
			"repo-files": CollectGLRepoFile(proj, in),
		} {
			base := glCollect(dir, glKey(proj))
			rel, err := filepath.Rel(base, got)
			if err != nil || strings.HasPrefix(rel, "..") {
				t.Errorf("%q builds %q, outside %q", in, got, base)
			}
			if strings.ContainsRune(path.Base(got), '\\') {
				t.Errorf("%q builds %q, whose last segment is not a single path segment", in, got)
			}
		}
	}
}
