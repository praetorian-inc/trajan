package engine

import "errors"

var (
	ErrNotImplemented = errors.New("not implemented for this platform")
	ErrPhaseBackStep  = errors.New("phase ordering violation")
	ErrNoRunDir       = errors.New("no run directory found")
	ErrNoToken        = errors.New("no GitHub token: set GITHUB_TOKEN or run `gh auth login`")
)
