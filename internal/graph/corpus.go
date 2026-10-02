package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

var ErrNoOrgRecord = errors.New("no organization record")

type Record struct {
	Rel    string
	Dir    string
	Path   string
	Kind   string
	ID     string
	Fields map[string]any
}

type Corpus struct {
	Org     string
	Records []Record

	// Seen is what 10-normalize offered, Files is what parsed; the difference is
	// dropped records the graph is silently missing.
	Seen  int
	Files int
}

func LoadCorpus(ctx context.Context, cfg *engine.Config, runDir string, skipPrefixes []string,
	onError func(error)) (*Corpus, error) {

	all, err := engine.PriorPhase{RunDir: runDir}.IterJSON(engine.DirNormalize)
	if err != nil {
		return nil, err
	}
	wanted := make([]engine.PhaseFile, 0, len(all))
	for _, f := range all {
		rel := filepath.ToSlash(f.Rel)
		if slices.ContainsFunc(skipPrefixes, func(p string) bool { return strings.HasPrefix(rel, p) }) {
			continue
		}
		wanted = append(wanted, f)
	}
	if len(wanted) == 0 {
		return nil, fmt.Errorf("%s: no normalized records", engine.DirNormalize)
	}

	recs, err := engine.RunPartial(ctx, cfg.Concurrency, wanted,
		func(_ context.Context, f engine.PhaseFile) (Record, error) {
			var m map[string]any
			dec := json.NewDecoder(bytes.NewReader(f.Data))
			dec.UseNumber()
			if err := dec.Decode(&m); err != nil {
				return Record{}, fmt.Errorf("%s/%s: %w", engine.DirNormalize, f.Rel, err)
			}
			rel := filepath.ToSlash(f.Rel)
			dir, _, _ := strings.Cut(rel, "/")
			id, _ := m["_id"].(string)
			kind, _ := m["kind"].(string)
			return Record{Rel: rel, Dir: dir, Path: path.Dir(rel), Kind: kind, ID: id, Fields: m}, nil
		},
		func(_ engine.PhaseFile, err error) { onError(err) })
	if err != nil {
		return nil, err
	}
	slices.SortFunc(recs, func(a, b Record) int { return strings.Compare(a.Rel, b.Rel) })

	return &Corpus{Records: recs, Seen: len(wanted), Files: len(recs)}, nil
}

func Str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	}
	return ""
}

func Truthy(v any) bool {
	b, _ := v.(bool)
	return b
}

func Objects(v any) []map[string]any {
	items, _ := v.([]any)
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
