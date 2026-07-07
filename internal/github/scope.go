package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

type ScopeKind int

const (
	ScopeRepo ScopeKind = iota
	ScopeOrg
	ScopeEnterprise
)

type Scope struct {
	Kind       ScopeKind
	Enterprise string
	Org        string
	Repo       string
	Slug       string
}

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

	var sc Scope
	switch {
	case parts[0] == "enterprises":
		if len(parts) < 2 {
			return Scope{}, fmt.Errorf("cannot parse enterprise scope from %q", arg)
		}
		sc = Scope{Kind: ScopeEnterprise, Enterprise: parts[1]}
	case len(parts) >= 2:
		sc = Scope{Kind: ScopeRepo, Org: parts[0], Repo: parts[1]}
	default:
		sc = Scope{Kind: ScopeOrg, Org: parts[0]}
	}
	sc.Slug = slugify(sc)
	return sc, nil
}

// without a scheme, only github.com or a multi-label domain is a host, so a
// single-dot org name (my.org) survives as the scope
func isHost(seg string, hasScheme bool) bool {
	if !strings.Contains(seg, ".") {
		return false
	}
	return hasScheme || seg == "github.com" || strings.Count(seg, ".") >= 2
}

func slugify(sc Scope) string {
	switch sc.Kind {
	case ScopeEnterprise:
		return "ent-" + slugComponent(sc.Enterprise)
	case ScopeRepo:
		return slugComponent(sc.Org) + "__" + slugComponent(sc.Repo)
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

func WhoAmI(ctx context.Context) error {
	token, err := ResolveToken(ctx)
	if err != nil {
		return err
	}
	c := NewClient(token)

	if raw, hdr, err := c.Get(ctx, "/user", nil, false); err == nil {
		var user struct {
			Login string `json:"login"`
			ID    int64  `json:"id"`
		}
		if err := json.Unmarshal(raw, &user); err != nil {
			return fmt.Errorf("parsing /user response: %w", err)
		}
		fmt.Printf("identity: user %s (id %d)\n", user.Login, user.ID)
		fmt.Printf("scopes: %s\n", hdr.Get("X-OAuth-Scopes"))
		return nil
	}

	// App installation tokens cannot call /user ("not accessible by integration");
	// fall back to the installation's repository view, which they can read.
	raw, _, err := c.Get(ctx, "/installation/repositories", url.Values{"per_page": []string{"1"}}, false)
	if err != nil {
		return fmt.Errorf("token is not a user token and /installation/repositories failed: %w", err)
	}
	var inst struct {
		TotalCount int `json:"total_count"`
	}
	if err := json.Unmarshal(raw, &inst); err != nil {
		return fmt.Errorf("parsing /installation/repositories response: %w", err)
	}
	fmt.Printf("identity: github app installation token\n")
	fmt.Printf("accessible repositories: %d\n", inst.TotalCount)
	return nil
}
