package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// WhoAmI resolves the token/endpoint, then prints the authenticated identity,
// detected token type, scopes, admin flag, accessible groups, and a rate-limit
// snapshot. It writes nothing to a run dir.
func WhoAmI(ctx context.Context) error {
	token, err := ResolveToken("")
	if err != nil {
		return err
	}
	cl := NewClient(ResolveBaseURL(FlagURL), token, FlagInsecure, 1)

	userRaw, _, err := cl.Get(ctx, "/user", nil, false)
	if err != nil {
		return fmt.Errorf("GET /user: %w", err)
	}
	var user struct {
		Username         string `json:"username"`
		Name             string `json:"name"`
		IsAdmin          bool   `json:"is_admin"`
		Bot              bool   `json:"bot"`
		CanCreateGroup   bool   `json:"can_create_group"`
		CanCreateProject bool   `json:"can_create_project"`
	}
	if err := json.Unmarshal(userRaw, &user); err != nil {
		return fmt.Errorf("parsing /user: %w", err)
	}

	fmt.Printf("identity: %s (%s)\n", user.Username, user.Name)
	fmt.Printf("token type: %s\n", detectTokenType(user.Username, user.Bot))
	fmt.Printf("admin: %v\n", user.IsAdmin)
	fmt.Printf("can create group/project: %v/%v\n", user.CanCreateGroup, user.CanCreateProject)

	// Personal access tokens carry scopes+expiry here; project/group tokens 401/404.
	if patRaw, _, perr := cl.Get(ctx, "/personal_access_tokens/self", nil, true); perr == nil && patRaw != nil {
		var pat struct {
			Scopes    []string `json:"scopes"`
			ExpiresAt *string  `json:"expires_at"`
		}
		if json.Unmarshal(patRaw, &pat) == nil {
			fmt.Printf("scopes: %s\n", strings.Join(pat.Scopes, ", "))
			if pat.ExpiresAt != nil {
				fmt.Printf("expires: %s\n", *pat.ExpiresAt)
			}
		}
	}

	if groups, gerr := cl.Paginate(ctx, "/groups", url.Values{"min_access_level": {"10"}}); gerr == nil {
		fmt.Printf("accessible groups: %d\n", len(groups))
		for _, g := range groups {
			if fp := strField(g, "full_path"); fp != "" {
				fmt.Printf("  - %s\n", fp)
			}
		}
	}

	limit, remaining := cl.limiter.Snapshot()
	fmt.Printf("rate limit: %d/%d remaining\n", remaining, limit)
	return nil
}

// detectTokenType infers the token kind from the authenticated user: bot usernames
// prefixed project_/group_ with _bot_ are project/group access tokens.
func detectTokenType(username string, bot bool) string {
	if bot {
		if strings.HasPrefix(username, "project_") && strings.Contains(username, "_bot_") {
			return "project_access_token"
		}
		if strings.HasPrefix(username, "group_") && strings.Contains(username, "_bot_") {
			return "group_access_token"
		}
		return "bot_token"
	}
	return "personal_access_token"
}
