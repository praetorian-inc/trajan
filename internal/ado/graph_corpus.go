package ado

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

const normalizeDir = "10-normalize"

type record struct {
	rel    string
	dir    string
	kind   string
	id     string
	fields map[string]any
}

type corpus struct {
	org    string
	byKind map[string][]record
	byDir  map[string]map[string]bool

	seen  int
	files int
}

func loadCorpus(ctx context.Context, cfg *engine.Config, runDir string, onError func(error)) (*corpus, error) {
	files, err := engine.PriorPhase{RunDir: runDir}.IterJSON(normalizeDir)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s: no normalized records", normalizeDir)
	}

	recs := engine.RunPartial(ctx, cfg.Concurrency, files,
		func(_ context.Context, f engine.PhaseFile) (record, error) {
			var m map[string]any
			dec := json.NewDecoder(bytes.NewReader(f.Data))
			dec.UseNumber()
			if err := dec.Decode(&m); err != nil {
				return record{}, fmt.Errorf("%s/%s: %w", normalizeDir, f.Rel, err)
			}
			rel := filepath.ToSlash(f.Rel)
			dir := path.Dir(rel)
			id, _ := m["_id"].(string)
			kind, _ := m["kind"].(string)
			return record{rel: rel, dir: dir, kind: kind, id: id, fields: m}, nil
		},
		func(_ engine.PhaseFile, err error) { onError(err) })
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(recs, func(a, b record) int { return strings.Compare(a.rel, b.rel) })

	c := &corpus{byKind: map[string][]record{}, byDir: map[string]map[string]bool{},
		seen: len(files), files: len(recs)}
	for _, r := range recs {
		if r.id != "" {
			if c.byDir[r.dir] == nil {
				c.byDir[r.dir] = map[string]bool{}
			}
			c.byDir[r.dir][r.id] = true
		}
		if r.kind == "" {
			continue
		}
		c.byKind[r.kind] = append(c.byKind[r.kind], r)
	}

	orgs := c.byKind[string(Organization)]
	if len(orgs) == 0 {
		return nil, fmt.Errorf("%s: no organization record; every node identity is qualified by it", normalizeDir)
	}
	c.org = str(orgs[0].fields["org"])
	if c.org == "" {
		return nil, fmt.Errorf("%s: organization record has no %q", orgs[0].rel, "org")
	}
	return c, nil
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	}
	return ""
}
