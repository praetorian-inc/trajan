package graph

import (
	"context"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func Push(ctx context.Context, cfg *engine.Config, runDir, neo4jURL, neo4jUser, neo4jPass string) error {
	return engine.ErrNotImplemented
}

func Analyze(ctx context.Context, cfg *engine.Config, runDir string, writeBack, noGraph, detailed bool) error {
	return engine.ErrNotImplemented
}
