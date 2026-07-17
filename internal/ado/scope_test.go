package ado

import "testing"

func TestParseScope(t *testing.T) {
	tests := []struct {
		in      string
		wantErr bool
		kind    ScopeKind
		org     string
		project string
		repo    string
		slug    string
	}{
		{in: "Middle-Earth-Arda", kind: ScopeOrg, org: "Middle-Earth-Arda", slug: "middle-earth-arda"},
		{in: "org/Imladris", kind: ScopeProject, org: "org", project: "Imladris", slug: "org__imladris"},
		{in: "org/proj/repo", kind: ScopeRepo, org: "org", project: "proj", repo: "repo", slug: "org__proj__repo"},
		{in: "https://dev.azure.com/org/proj", kind: ScopeProject, org: "org", project: "proj"},
		{in: "dev.azure.com/org", kind: ScopeOrg, org: "org"},
		{in: "org/", kind: ScopeOrg, org: "org"},
		{in: "  org/proj  ", kind: ScopeProject, org: "org", project: "proj"},
		{in: "", wantErr: true},
		{in: "   ", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			sc, err := ParseScope(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if sc.Kind != tt.kind || sc.Org != tt.org || sc.Project != tt.project || sc.Repo != tt.repo {
				t.Errorf("got {kind:%d org:%q project:%q repo:%q}, want {kind:%d org:%q project:%q repo:%q}",
					sc.Kind, sc.Org, sc.Project, sc.Repo, tt.kind, tt.org, tt.project, tt.repo)
			}
			if tt.slug != "" && sc.Slug != tt.slug {
				t.Errorf("slug = %q, want %q", sc.Slug, tt.slug)
			}
		})
	}
}
