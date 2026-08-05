package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/praetorian-inc/trajan/internal/engine"
)

const pushBatch = 1000

func Push(ctx context.Context, cfg *engine.Config, runDir, neo4jURL, neo4jUser, neo4jPass string, reset bool) error {
	state, err := engine.LoadState(runDir)
	if err != nil {
		return err
	}
	if err := state.CheckPhase(engine.PhasePush); err != nil {
		return err
	}
	timer := engine.StartPhaseTimer(engine.PhasePush, "push")
	pushErr := runPush(ctx, runDir, state, neo4jURL, neo4jUser, neo4jPass, reset)
	state.RecordPhase(timer.Stop(pushErr))
	return errors.Join(pushErr, state.Save(runDir))
}

func runPush(ctx context.Context, runDir string, state *engine.State, url, user, pass string, reset bool) error {
	var nf nodesFile
	var ef edgesFile
	for _, in := range []struct {
		rel string
		v   any
	}{{engine.GraphNodes(), &nf}, {engine.GraphEdges(), &ef}} {
		b, err := os.ReadFile(filepath.Join(runDir, in.rel))
		if err != nil {
			return fmt.Errorf("read %s: %w (run graph first)", in.rel, err)
		}
		if err := json.Unmarshal(b, in.v); err != nil {
			return fmt.Errorf("parse %s: %w", in.rel, err)
		}
	}

	drv, err := neo4j.NewDriverWithContext(url, neo4j.BasicAuth(user, pass, ""))
	if err != nil {
		return err
	}
	defer drv.Close(ctx)
	if err := drv.VerifyConnectivity(ctx); err != nil {
		return fmt.Errorf("connect %s: %w", url, err)
	}

	sess := drv.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer sess.Close(ctx)

	if err := ensureConstraints(ctx, sess, nf.Nodes); err != nil {
		return err
	}
	if reset {
		if _, err := run(ctx, sess, "MATCH (n) DETACH DELETE n", nil); err != nil {
			return err
		}
	}

	nodesWritten, err := pushNodes(ctx, sess, nf.Nodes, state)
	if err != nil {
		return err
	}
	edgesWritten, err := pushEdges(ctx, sess, ef.Edges, state)
	if err != nil {
		return err
	}

	slog.Info("push complete", "url", url, "nodes", nodesWritten, "edges", edgesWritten,
		"edges_skipped", len(ef.Edges)-edgesWritten)
	if edgesWritten < len(ef.Edges) {
		return fmt.Errorf("%d edge(s) named an endpoint no node supplied", len(ef.Edges)-edgesWritten)
	}
	return nil
}

func run(ctx context.Context, sess neo4j.SessionWithContext, cypher string, params map[string]any) (int, error) {
	res, err := sess.Run(ctx, cypher, params)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", firstLine(cypher), err)
	}
	sum, err := res.Consume(ctx)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", firstLine(cypher), err)
	}
	c := sum.Counters()
	return c.NodesCreated() + c.PropertiesSet() + c.RelationshipsCreated(), nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// _id is the node identity the edge writer already resolved, so the import never
// has to rebuild a composite key. One uniqueness constraint per label both
// enforces that and gives the edge MATCHes an index to seek on.
func ensureConstraints(ctx context.Context, sess neo4j.SessionWithContext, nodes []node) error {
	for _, l := range slices.Sorted(maps.Keys(labelsPresent(nodes))) {
		q := fmt.Sprintf("CREATE CONSTRAINT trajan_%s_id IF NOT EXISTS FOR (n:%s) REQUIRE n._id IS UNIQUE",
			strings.ToLower(string(l)), l)
		if _, err := run(ctx, sess, q, nil); err != nil {
			return err
		}
	}
	return nil
}

func labelsPresent(nodes []node) map[NodeLabel]bool {
	out := map[NodeLabel]bool{}
	for _, n := range nodes {
		if len(n.Labels) > 0 {
			out[n.Labels[0]] = true
		}
	}
	return out
}

func pushNodes(ctx context.Context, sess neo4j.SessionWithContext, nodes []node, state *engine.State) (int, error) {
	byLabel := map[NodeLabel][]any{}
	for _, n := range nodes {
		if len(n.Labels) == 0 {
			continue
		}
		props := scalarProps(n.Properties, n.Findings, n.ID, state)
		for k, v := range n.Key {
			props[k] = v
		}
		byLabel[n.Labels[0]] = append(byLabel[n.Labels[0]], map[string]any{"id": n.ID, "props": props})
	}

	total := 0
	for _, l := range slices.Sorted(maps.Keys(labelsPresent(nodes))) {
		q := fmt.Sprintf("UNWIND $rows AS r MERGE (n:%s {_id: r.id}) SET n += r.props", l)
		for chunk := range slices.Chunk(byLabel[l], pushBatch) {
			if _, err := run(ctx, sess, q, map[string]any{"rows": chunk}); err != nil {
				return total, err
			}
			total += len(chunk)
		}
	}
	return total, nil
}

// Grouped by the whole triple, not by type: the endpoint labels are what let
// each MATCH seek the per-label _id index instead of scanning every node.
func pushEdges(ctx context.Context, sess neo4j.SessionWithContext, edges []edge, state *engine.State) (int, error) {
	type triple struct {
		t        EdgeType
		from, to NodeLabel
	}
	byTriple := map[triple][]any{}
	for _, e := range edges {
		k := triple{e.Type, e.FromLabel, e.ToLabel}
		byTriple[k] = append(byTriple[k], map[string]any{
			"from": e.From, "to": e.To,
			"props": scalarProps(e.Properties, e.Findings, e.ID, state),
		})
	}

	keys := make([]triple, 0, len(byTriple))
	for k := range byTriple {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b triple) int {
		return strings.Compare(string(a.t)+string(a.from)+string(a.to), string(b.t)+string(b.from)+string(b.to))
	})

	total := 0
	for _, k := range keys {
		q := fmt.Sprintf(`UNWIND $rows AS r
MATCH (a:%s {_id: r.from})
MATCH (b:%s {_id: r.to})
MERGE (a)-[e:%s]->(b)
SET e += r.props
RETURN count(*) AS n`, k.from, k.to, k.t)
		for chunk := range slices.Chunk(byTriple[k], pushBatch) {
			res, err := sess.Run(ctx, q, map[string]any{"rows": chunk})
			if err != nil {
				return total, fmt.Errorf("%s{%s,%s}: %w", k.t, k.from, k.to, err)
			}
			rec, err := res.Single(ctx)
			if err != nil {
				return total, fmt.Errorf("%s{%s,%s}: %w", k.t, k.from, k.to, err)
			}
			n, _ := rec.Get("n")
			written, _ := n.(int64)
			total += int(written)
		}
	}
	return total, nil
}

// Neo4j stores scalars and homogeneous scalar arrays. A null property is dropped
// because SET n += {k: null} removes the key anyway, and findings are flattened
// to their fingerprints and rule ids so the graph joins back to 20-scan.
func scalarProps(props map[string]any, findings []findingRef, id string, state *engine.State) map[string]any {
	out := make(map[string]any, len(props)+5)
	for k, v := range props {
		if v == nil {
			continue
		}
		if a, ok := v.([]any); ok {
			out[k] = scalarArray(a)
			continue
		}
		out[k] = scalar(v)
	}
	if len(findings) > 0 {
		fps := make([]string, 0, len(findings))
		rules := make([]string, 0, len(findings))
		for _, f := range findings {
			fps = append(fps, f.Fingerprint)
			rules = append(rules, f.RuleID)
		}
		slices.Sort(rules)
		out["finding_fingerprints"] = fps
		out["finding_rule_ids"] = slices.Compact(rules)
	}
	out["_id"] = id
	out["_org"] = state.Org
	out["_run_id"] = state.RunID
	return out
}

// JSON decodes every number as a float64, so a whole one is restored to an
// integer: member_runner_ids must stay [2], not [2.0], to match on.
func scalar(v any) any {
	if f, ok := v.(float64); ok && f == float64(int64(f)) {
		return int64(f)
	}
	return v
}

func scalarArray(a []any) any {
	if len(a) == 0 {
		return []string{}
	}
	switch scalar(a[0]).(type) {
	case string:
		out := make([]string, 0, len(a))
		for _, v := range a {
			s, ok := v.(string)
			if !ok {
				return jsonArray(a)
			}
			out = append(out, s)
		}
		return out
	case int64:
		out := make([]int64, 0, len(a))
		for _, v := range a {
			n, ok := scalar(v).(int64)
			if !ok {
				return jsonArray(a)
			}
			out = append(out, n)
		}
		return out
	case bool:
		out := make([]bool, 0, len(a))
		for _, v := range a {
			b, ok := v.(bool)
			if !ok {
				return jsonArray(a)
			}
			out = append(out, b)
		}
		return out
	}
	return jsonArray(a)
}

// A heterogeneous or nested array is not storable, and dropping it would make a
// missing capability list look like an empty one.
func jsonArray(a []any) []string {
	out := make([]string, 0, len(a))
	for _, v := range a {
		b, err := json.Marshal(v)
		if err != nil {
			b = []byte(fmt.Sprint(v))
		}
		out = append(out, string(b))
	}
	return out
}
