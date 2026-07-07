package github

import "testing"

func TestParseScopeKindDetection(t *testing.T) {
	tests := []struct {
		name     string
		arg      string
		wantKind ScopeKind
		wantEnt  string
		wantOrg  string
		wantRepo string
	}{
		{"ent bare", "enterprises/acme", ScopeEnterprise, "acme", "", ""},
		{"ent url", "https://github.com/enterprises/acme", ScopeEnterprise, "acme", "", ""},
		{"ent ghes url", "https://ghe.corp.example.com/enterprises/acme", ScopeEnterprise, "acme", "", ""},
		// a trailing segment after the enterprise slug is not a repo
		{"ent with tail", "enterprises/acme/extra", ScopeEnterprise, "acme", "", ""},

		{"repo bare", "octocat/hello-world", ScopeRepo, "", "octocat", "hello-world"},
		{"repo url", "https://github.com/octocat/hello-world", ScopeRepo, "", "octocat", "hello-world"},
		{"repo url trailing slash", "https://github.com/octocat/hello-world/", ScopeRepo, "", "octocat", "hello-world"},
		{"repo ghes url", "https://ghe.corp.example.com/octocat/hello-world", ScopeRepo, "", "octocat", "hello-world"},
		// anything past <org>/<repo> (tree/branch links, .git) is ignored
		{"repo url with tree path", "https://github.com/octocat/hello-world/tree/main", ScopeRepo, "", "octocat", "hello-world"},

		{"org bare", "octocat", ScopeOrg, "", "octocat", ""},
		{"org url", "https://github.com/octocat", ScopeOrg, "", "octocat", ""},
		{"org url trailing slash", "https://github.com/octocat/", ScopeOrg, "", "octocat", ""},
		{"org ghes url", "https://ghe.corp.example.com/octocat", ScopeOrg, "", "octocat", ""},
		{"org http scheme", "http://github.com/octocat", ScopeOrg, "", "octocat", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc, err := ParseScope(tt.arg)
			if err != nil {
				t.Fatalf("ParseScope(%q) unexpected error: %v", tt.arg, err)
			}
			if sc.Kind != tt.wantKind {
				t.Errorf("Kind = %v, want %v", sc.Kind, tt.wantKind)
			}
			if sc.Enterprise != tt.wantEnt {
				t.Errorf("Enterprise = %q, want %q", sc.Enterprise, tt.wantEnt)
			}
			if sc.Org != tt.wantOrg {
				t.Errorf("Org = %q, want %q", sc.Org, tt.wantOrg)
			}
			if sc.Repo != tt.wantRepo {
				t.Errorf("Repo = %q, want %q", sc.Repo, tt.wantRepo)
			}
		})
	}
}

// "enterprises" is the sentinel only as the leading segment; as a repo name it must not trip enterprise detection
func TestParseScopeEnterprisesAsRepoNameIsRepo(t *testing.T) {
	sc, err := ParseScope("octocat/enterprises")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sc.Kind != ScopeRepo || sc.Org != "octocat" || sc.Repo != "enterprises" {
		t.Fatalf("octocat/enterprises = %+v, want repo octocat/enterprises", sc)
	}
}

func TestParseScopeSlug(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{"org plain", "octocat", "octocat"},
		{"org lowercased", "OctoCat", "octocat"},
		{"repo joined with double underscore", "octocat/hello-world", "octocat__hello-world"},
		{"repo lowercased", "OctoCat/Hello-World", "octocat__hello-world"},
		{"org with dot becomes dash", "my.org", "my-org"},
		{"repo with dots", "my.org/my.repo", "my-org__my-repo"},
		{"enterprise prefixed", "enterprises/acme", "ent-acme"},
		{"enterprise lowercased", "enterprises/AcmeCorp", "ent-acmecorp"},
		{"enterprise with dot", "enterprises/acme.inc", "ent-acme-inc"},
		// URL forms must slug identically to their bare equivalents
		{"repo url same slug as bare", "https://github.com/octocat/hello-world", "octocat__hello-world"},
		{"ghes url same slug as bare", "https://ghe.corp.example.com/octocat/hello-world", "octocat__hello-world"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc, err := ParseScope(tt.arg)
			if err != nil {
				t.Fatalf("ParseScope(%q) unexpected error: %v", tt.arg, err)
			}
			if sc.Slug != tt.want {
				t.Errorf("Slug = %q, want %q", sc.Slug, tt.want)
			}
		})
	}
}

// the slug feeds the run-dir name, so every byte must be run-dir-safe: [a-z0-9-] plus "_" for the org__repo join
func TestParseScopeSlugCharset(t *testing.T) {
	args := []string{
		"Weird Org Name!",
		"org_with_underscore",
		"UPPER/Case.Repo",
		"enterprises/My Big Co.",
	}
	for _, arg := range args {
		sc, err := ParseScope(arg)
		if err != nil {
			t.Fatalf("ParseScope(%q): %v", arg, err)
		}
		for i := 0; i < len(sc.Slug); i++ {
			c := sc.Slug[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				t.Errorf("ParseScope(%q).Slug = %q has illegal byte %q at %d", arg, sc.Slug, c, i)
			}
		}
		if sc.Slug == "" {
			t.Errorf("ParseScope(%q).Slug is empty", arg)
		}
	}
}

// a GHES locator must resolve to the same scope as the equivalent github.com locator
func TestParseScopeGHESHostEquivalence(t *testing.T) {
	pairs := []struct{ ghes, dotcom string }{
		{"https://ghe.corp.example.com/octocat", "https://github.com/octocat"},
		{"https://ghe.corp.example.com/octocat/hello-world", "https://github.com/octocat/hello-world"},
		{"https://ghe.corp.example.com/enterprises/acme", "https://github.com/enterprises/acme"},
		{"ghe.corp.example.com/octocat/hello-world", "github.com/octocat/hello-world"},
	}
	for _, p := range pairs {
		g, err1 := ParseScope(p.ghes)
		d, err2 := ParseScope(p.dotcom)
		if err1 != nil || err2 != nil {
			t.Fatalf("ParseScope errors: ghes=%v dotcom=%v", err1, err2)
		}
		if g != d {
			t.Errorf("GHES %q parsed to %+v; github.com %q parsed to %+v; want equal",
				p.ghes, g, p.dotcom, d)
		}
	}
}

// host-stripping must not eat the only segment when it is a dotless org, not a host
func TestParseScopeBareOrgIsNotMistakenForHost(t *testing.T) {
	sc, err := ParseScope("octocat")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sc.Kind != ScopeOrg || sc.Org != "octocat" {
		t.Fatalf("bare org = %+v, want org octocat", sc)
	}
}

func TestParseScopeErrors(t *testing.T) {
	bad := []struct {
		name string
		arg  string
	}{
		{"empty", ""},
		{"only slashes", "///"},
		{"only scheme and host", "https://github.com/"},
		{"only scheme and host no slash", "https://github.com"},
		{"whitespace", "   "},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			sc, err := ParseScope(tt.arg)
			if err == nil {
				t.Fatalf("ParseScope(%q) = %+v, want error", tt.arg, sc)
			}
		})
	}
}

// an empty Enterprise would mint a bogus `ent-` run dir and query a nonexistent enterprise
func TestParseScopeEnterprisesNoSlugIsNotEmptyEnterprise(t *testing.T) {
	for _, arg := range []string{"enterprises/", "https://github.com/enterprises/"} {
		sc, err := ParseScope(arg)
		if err == nil && sc.Kind == ScopeEnterprise && sc.Enterprise == "" {
			t.Errorf("ParseScope(%q) = enterprise with empty Enterprise (%+v)", arg, sc)
		}
	}
}
