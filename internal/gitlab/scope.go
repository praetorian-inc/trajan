package gitlab

import (
	"fmt"
	"slices"
	"strings"
)

type ScopeKind int

const (
	ScopeProject ScopeKind = iota
	ScopeGroup
)

// GitLab paths are variable-depth, so segment count alone cannot tell
// "group/subgroup/subgroup" from "group/subgroup/project". ParseScope records the raw
// split with a provisional group Kind and Collect probes /groups then /projects to
// settle it.
type Scope struct {
	Kind    ScopeKind
	Group   string // full group path (namespace)
	Project string // project full path when the locator resolves to a project
	Slug    string
	path    string // raw normalized path, group and project undecided
}

// Accepts a path or a gitlab.com / self-hosted URL. The whole path is provisionally
// the group; Collect flips the last segment to a project if the /groups probe 404s.
func ParseScope(arg string) (Scope, error) {
	s := strings.TrimSpace(arg)
	hasScheme := strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://")
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	s = strings.Trim(s, "/")
	parts := strings.Split(s, "/")
	if len(parts) > 0 && isHost(parts[0], hasScheme) {
		parts = parts[1:]
	}
	parts = slices.DeleteFunc(parts, func(p string) bool { return p == "" })
	if len(parts) == 0 {
		return Scope{}, fmt.Errorf("cannot parse scope from %q", arg)
	}

	full := strings.Join(parts, "/")
	sc := Scope{Kind: ScopeGroup, Group: full, path: full}
	sc.Slug = slugPath(parts)
	return sc, nil
}

// A first segment is only stripped as a host if it looks like one: dotted with a
// scheme, gitlab.com, or multi-label. The multi-label test is what lets a bare
// self-hosted IP through as a host rather than as a group name.
func isHost(seg string, hasScheme bool) bool {
	if !strings.Contains(seg, ".") {
		return false
	}
	return hasScheme || seg == "gitlab.com" || strings.Count(seg, ".") >= 2
}

func slugPath(parts []string) string {
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = slugComponent(p)
	}
	return strings.Join(out, "__")
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
	if s.Project != "" {
		return s.Project
	}
	return s.Group
}
