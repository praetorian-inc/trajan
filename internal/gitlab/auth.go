package gitlab

import (
	"errors"
	"os"
	"strings"
)

// FlagURL and FlagInsecure carry the CLI's --url / --insecure into Collect and
// WhoAmI, whose signatures are frozen to (ctx,cfg,locator) / (ctx). The CLI binds
// its persistent flags to these before dispatching.
var (
	FlagURL      = "https://gitlab.com"
	FlagInsecure = false
)

// ErrNoToken is returned when no GitLab token is found.
var ErrNoToken = errors.New("no GitLab token: pass --token or set GITLAB_TOKEN or GL_TOKEN")

// ResolveToken returns the token: an explicit value (--token / cfg.Token) wins,
// otherwise the environment.
func ResolveToken(explicit string) (string, error) {
	if v := strings.TrimSpace(explicit); v != "" {
		return v, nil
	}
	for _, k := range []string{"GITLAB_TOKEN", "GL_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v, nil
		}
	}
	return "", ErrNoToken
}

// ResolveBaseURL returns the instance root; the client appends /api/v4.
func ResolveBaseURL(flagURL string) string {
	if v := strings.TrimSpace(flagURL); v != "" {
		return v
	}
	return "https://gitlab.com"
}
