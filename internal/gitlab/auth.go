package gitlab

import (
	"errors"

	"github.com/praetorian-inc/trajan/internal/engine"
)

var ErrNoToken = errors.New("no GitLab token: pass --token or set TRAJAN_GL_TOKEN/GITLAB_TOKEN/GL_TOKEN/CI_JOB_TOKEN")

func ResolveToken(explicit string) (string, error) {
	c, ok := engine.ResolveGitLab(explicit)
	if !ok {
		return "", ErrNoToken
	}
	return c.Value, nil
}
