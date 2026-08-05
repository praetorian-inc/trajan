package gitlab

import (
	"errors"
	"os"
	"strings"
)

// Collect and WhoAmI have signatures frozen to (ctx,cfg,locator) and (ctx), so --url
// and --insecure reach them as package vars the CLI sets before dispatching.
var (
	FlagURL      = "https://gitlab.com"
	FlagInsecure = false
)

var ErrNoToken = errors.New("no GitLab token: pass --token or set GITLAB_TOKEN or GL_TOKEN")

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

// Returns the instance root only; the client appends /api/v4.
func ResolveBaseURL(flagURL string) string {
	if v := strings.TrimSpace(flagURL); v != "" {
		return v
	}
	return "https://gitlab.com"
}
