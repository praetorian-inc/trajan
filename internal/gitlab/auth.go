package gitlab

import (
	"errors"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// Collect and WhoAmI have signatures frozen to (ctx,cfg,locator) and (ctx,token), so --url
// and --insecure reach them as package vars the CLI sets before dispatching.
var (
	FlagURL      = "https://gitlab.com"
	FlagInsecure = false
)

var ErrNoToken = errors.New("no GitLab token: pass --token or set TRAJAN_GL_TOKEN/GITLAB_TOKEN/GL_TOKEN/CI_JOB_TOKEN")

func ResolveToken(explicit string) (string, error) {
	c, ok := engine.ResolveGitLab(explicit)
	if !ok {
		return "", ErrNoToken
	}
	return c.Value, nil
}

// Returns the instance root only; the client appends /api/v4.
func ResolveBaseURL(flagURL string) string {
	if v := strings.TrimSpace(flagURL); v != "" {
		return v
	}
	return "https://gitlab.com"
}
