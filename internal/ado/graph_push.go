package ado

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/ui"
)

const pushBatch = 1000

func PushGraph(ctx context.Context, cfg *engine.Config, runDir, neo4jURL, neo4jUser, neo4jPass string, reset bool) error {
	state, err := engine.LoadState(runDir)
	if err != nil {
		return err
	}
	if err := state.CheckPhase(engine.PhasePush); err != nil {
		return err
	}
	ui.PhaseHeader("Push")
	timer := engine.StartPhaseTimer(engine.PhasePush, "push")
	stats, pushErr := runPush(ctx, runDir, state, neo4jURL, neo4jUser, neo4jPass, reset)
	rec := timer.Stop(pushErr)
	state.RecordPhase(rec)
	saveErr := state.Save(runDir)
	if pushErr == nil {
		ui.Outcome("Push complete", []ui.Count{
			{Label: "nodes", N: stats.nodes},
			{Label: "edges", N: stats.edges},
		}, engine.Elapsed(rec.DurationS))
	}
	return errors.Join(pushErr, saveErr)
}

type pushStats struct{ nodes, edges int }

func runPush(ctx context.Context, runDir string, state *engine.State, url, user, pass string, reset bool) (pushStats, error) {
	var nf nodesFile
	var ef edgesFile
	for _, in := range []struct {
		rel string
		v   any
	}{{engine.GraphNodes(), &nf}, {engine.GraphEdges(), &ef}} {
		b, err := os.ReadFile(filepath.Join(runDir, in.rel))
		if err != nil {
			return pushStats{}, fmt.Errorf("read %s: %w (run graph first)", in.rel, err)
		}
		if err := json.Unmarshal(b, in.v); err != nil {
			return pushStats{}, fmt.Errorf("parse %s: %w", in.rel, err)
		}
	}

	drv, err := neo4j.NewDriverWithContext(url, neo4j.BasicAuth(user, pass, ""))
	if err != nil {
		return pushStats{}, err
	}
	defer drv.Close(ctx)
	if err := drv.VerifyConnectivity(ctx); err != nil {
		return pushStats{}, fmt.Errorf("connect %s: %w", url, err)
	}

	sess := drv.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer sess.Close(ctx)

	if err := ensureConstraints(ctx, sess, nf.Nodes); err != nil {
		return pushStats{}, err
	}
	if reset {
		if _, err := runCypher(ctx, sess, "MATCH (n) DETACH DELETE n", nil); err != nil {
			return pushStats{}, err
		}
	}

	nodesWritten, err := pushNodes(ctx, sess, nf.Nodes, state)
	if err != nil {
		return pushStats{}, err
	}
	edgesWritten, err := pushEdges(ctx, sess, ef.Edges, state)
	if err != nil {
		return pushStats{}, err
	}

	if edgesWritten < len(ef.Edges) {
		return pushStats{}, fmt.Errorf("%d edge(s) named an endpoint no node supplied", len(ef.Edges)-edgesWritten)
	}
	return pushStats{nodes: nodesWritten, edges: edgesWritten}, nil
}

func runCypher(ctx context.Context, sess neo4j.SessionWithContext, cypher string, params map[string]any) (int, error) {
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

func ensureConstraints(ctx context.Context, sess neo4j.SessionWithContext, nodes []node) error {
	for _, l := range slices.Sorted(maps.Keys(labelsPresent(nodes))) {
		if !ValidNodeLabel(l) {
			return fmt.Errorf("node label %q is not in the schema", l)
		}
		q := fmt.Sprintf("CREATE CONSTRAINT trajan_%s_id IF NOT EXISTS FOR (n:%s) REQUIRE n._id IS UNIQUE",
			strings.ToLower(string(l)), l)
		if _, err := runCypher(ctx, sess, q, nil); err != nil {
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
		if !ValidNodeLabel(l) {
			return total, fmt.Errorf("node label %q is not in the schema", l)
		}
		q := fmt.Sprintf("UNWIND $rows AS r MERGE (n:%s {_id: r.id}) SET n += r.props", l)
		for chunk := range slices.Chunk(byLabel[l], pushBatch) {
			if _, err := runCypher(ctx, sess, q, map[string]any{"rows": chunk}); err != nil {
				return total, err
			}
			total += len(chunk)
		}
	}
	return total, nil
}

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
		if !ValidEdge(k.t, k.from, k.to) {
			return total, fmt.Errorf("%s does not connect %s -> %s in the schema", k.t, k.from, k.to)
		}
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

// A null property is dropped because SET n += {k: null} removes the key anyway.
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
		out[k] = pushScalar(v)
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

// The corpus decodes with UseNumber, so an identity value that reached a property as
// json.Number must land as an integer rather than a string.
func pushScalar(v any) any {
	switch t := v.(type) {
	case json.Number:
		if n, err := t.Int64(); err == nil {
			return n
		}
		if f, err := t.Float64(); err == nil {
			return f
		}
		return t.String()
	case float64:
		if t == float64(int64(t)) {
			return int64(t)
		}
	}
	return v
}

func scalarArray(a []any) any {
	if len(a) == 0 {
		return []string{}
	}
	switch pushScalar(a[0]).(type) {
	case string:
		out := make([]string, 0, len(a))
		for _, v := range a {
			s, ok := pushScalar(v).(string)
			if !ok {
				return jsonArray(a)
			}
			out = append(out, s)
		}
		return out
	case int64, float64:
		return numericArray(a)
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

// Neo4j takes a mixed int/float collection, but Go does not, so one float in the
// array widens the whole of it rather than falling back to JSON strings.
func numericArray(a []any) any {
	ints := make([]int64, 0, len(a))
	floats := make([]float64, 0, len(a))
	widened := false
	for _, v := range a {
		switch n := pushScalar(v).(type) {
		case int64:
			ints = append(ints, n)
			floats = append(floats, float64(n))
		case float64:
			widened = true
			floats = append(floats, n)
		default:
			return jsonArray(a)
		}
	}
	if widened {
		return floats
	}
	return ints
}

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
