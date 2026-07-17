package ado

import (
	"fmt"
	"slices"
	"strings"
)

type ScopeKind int

const (
	ScopeOrg ScopeKind = iota
	ScopeProject
	ScopeRepo
)

// Scope narrows a run. Org is always required; Project/Repo optionally restrict
// the fan-out. Org and project surfaces are collected regardless of narrowing,
// mirroring the GitHub collector (a repo-scoped run still collects the org).
type Scope struct {
	Kind    ScopeKind
	Org     string
	Project string
	Repo    string
	Slug    string
}

// ParseScope accepts "<org>", "<org>/<project>", "<org>/<project>/<repo>", or a
// dev.azure.com URL. An empty locator yields the zero Scope so the caller can
// fall back to ORG_NAME.
func ParseScope(arg string) (Scope, error) {
	s := strings.TrimSpace(arg)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	s = strings.Trim(s, "/")
	parts := strings.Split(s, "/")
	// drop a leading dev.azure.com host, or a visualstudio.com vanity host
	if len(parts) > 0 && (strings.Contains(parts[0], "dev.azure.com") || strings.HasSuffix(parts[0], "visualstudio.com")) {
		parts = parts[1:]
	}
	parts = slices.DeleteFunc(parts, func(p string) bool { return p == "" })
	if len(parts) == 0 {
		return Scope{}, fmt.Errorf("cannot parse scope from %q", arg)
	}

	sc := Scope{Kind: ScopeOrg, Org: parts[0]}
	if len(parts) >= 2 {
		sc.Kind = ScopeProject
		sc.Project = parts[1]
	}
	if len(parts) >= 3 {
		sc.Kind = ScopeRepo
		// a repo path segment may itself contain "_git/<repo>"; keep the last part
		sc.Repo = parts[len(parts)-1]
	}
	sc.Slug = slugify(sc)
	return sc, nil
}

func slugify(sc Scope) string {
	switch sc.Kind {
	case ScopeRepo:
		return slugComponent(sc.Org) + "__" + slugComponent(sc.Project) + "__" + slugComponent(sc.Repo)
	case ScopeProject:
		return slugComponent(sc.Org) + "__" + slugComponent(sc.Project)
	default:
		return slugComponent(sc.Org)
	}
}

func slugComponent(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

func scopeString(s Scope) string {
	switch s.Kind {
	case ScopeRepo:
		return s.Org + "/" + s.Project + "/" + s.Repo
	case ScopeProject:
		return s.Org + "/" + s.Project
	default:
		return s.Org
	}
}
