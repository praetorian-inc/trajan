package gitlab

import (
	"context"

	"github.com/praetorian-inc/trajan/internal/engine"
)

type ScanOptions struct {
	GroupOnly bool
}

type ScopeKind int

const (
	ScopeProject ScopeKind = iota
	ScopeGroup
)

type Scope struct {
	Kind    ScopeKind
	Group   string
	Project string
	Slug    string
}

func ParseScope(locator string) (Scope, error) {
	return Scope{}, engine.ErrNotImplemented
}

func Collect(ctx context.Context, cfg *engine.Config, locator string) (string, error) {
	return "", engine.ErrNotImplemented
}

func Normalize(ctx context.Context, runDir string) error {
	return engine.ErrNotImplemented
}

func Scan(ctx context.Context, runDir string, opts ScanOptions) error {
	return engine.ErrNotImplemented
}

func WhoAmI(ctx context.Context) error {
	return engine.ErrNotImplemented
}
