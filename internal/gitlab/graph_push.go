package gitlab

import (
	"context"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/graph"
)

func PushGraph(ctx context.Context, cfg *engine.Config, runDir, neo4jURL, neo4jUser, neo4jPass string, reset bool) error {
	return graph.Push(ctx, cfg, glSchema{}, runDir, neo4jURL, neo4jUser, neo4jPass, reset)
}
