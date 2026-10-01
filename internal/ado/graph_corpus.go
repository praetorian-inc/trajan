package ado

import (
	"fmt"

	"github.com/praetorian-inc/trajan/internal/graph"
)

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
}

func indexCorpus(src *graph.Corpus) (*corpus, error) {
	c := &corpus{byKind: map[string][]record{}, byDir: map[string]map[string]bool{}}
	for _, r := range src.Records {
		rec := record{rel: r.Rel, dir: r.Path, kind: r.Kind, id: r.ID, fields: r.Fields}
		if rec.id != "" {
			if c.byDir[rec.dir] == nil {
				c.byDir[rec.dir] = map[string]bool{}
			}
			c.byDir[rec.dir][rec.id] = true
		}
		if rec.kind == "" {
			continue
		}
		c.byKind[rec.kind] = append(c.byKind[rec.kind], rec)
	}

	orgs := c.byKind[string(Organization)]
	if len(orgs) == 0 {
		return nil, fmt.Errorf("10-normalize: %w; every node identity is qualified by it", graph.ErrNoOrgRecord)
	}
	c.org = str(orgs[0].fields["org"])
	if c.org == "" {
		return nil, fmt.Errorf("%s: organization record has no %q", orgs[0].rel, "org")
	}
	return c, nil
}

func str(v any) string { return graph.Str(v) }
