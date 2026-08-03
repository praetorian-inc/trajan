package graph

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

const normalizeDir = "10-normalize"

type record struct {
	rel    string
	dir    string
	id     string
	fields map[string]any
}

type corpus struct {
	org    string
	dirs   map[string][]record
	chains map[string]map[string]any

	// trueBranch maps "<full repo>\x00<slug>" to the unslugged branch name, and
	// to "" where two branches share a slug ("feat/a" and "feat__a"). BranchSlug
	// is not injective, so a job record's slugged branch can only be recovered
	// against branches the chain layer actually observed, and where the recovery
	// is ambiguous the caller must degrade rather than name one of the two.
	trueBranch map[string]string

	// seen is what 10-normalize offered, files is what parsed; the difference is
	// dropped records the graph is silently missing.
	seen  int
	files int
}

// loadCorpus reads every 10-normalize record once. chains/indices is skipped:
// it re-keys data the primary records already carry, and its filenames embed
// raw ${{ }} expressions.
func loadCorpus(ctx context.Context, cfg *engine.Config, runDir string, onError func(error)) (*corpus, error) {
	all, err := engine.PriorPhase{RunDir: runDir}.IterJSON(normalizeDir)
	if err != nil {
		return nil, err
	}
	wanted := make([]engine.PhaseFile, 0, len(all))
	for _, f := range all {
		if strings.HasPrefix(filepath.ToSlash(f.Rel), "chains/indices/") {
			continue
		}
		wanted = append(wanted, f)
	}
	if len(wanted) == 0 {
		return nil, fmt.Errorf("%s: no normalized records", normalizeDir)
	}

	recs := engine.RunPartial(ctx, cfg.Concurrency, wanted,
		func(_ context.Context, f engine.PhaseFile) (record, error) {
			var m map[string]any
			dec := json.NewDecoder(bytes.NewReader(f.Data))
			dec.UseNumber()
			if err := dec.Decode(&m); err != nil {
				return record{}, fmt.Errorf("%s/%s: %w", normalizeDir, f.Rel, err)
			}
			rel := filepath.ToSlash(f.Rel)
			dir, _, _ := strings.Cut(rel, "/")
			id, _ := m["_id"].(string)
			return record{rel: rel, dir: dir, id: id, fields: m}, nil
		},
		func(_ engine.PhaseFile, err error) { onError(err) })
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(recs, func(a, b record) int { return strings.Compare(a.rel, b.rel) })

	c := &corpus{
		dirs:       map[string][]record{},
		chains:     map[string]map[string]any{},
		trueBranch: map[string]string{},
		seen:       len(wanted),
		files:      len(recs),
	}
	for _, r := range recs {
		if r.dir == "chains" {
			c.chains[strings.TrimSuffix(filepath.Base(r.rel), ".json")] = r.fields
			continue
		}
		c.dirs[r.dir] = append(c.dirs[r.dir], r)
	}

	if len(c.dirs["org"]) == 0 {
		return nil, fmt.Errorf("%s/org: no organization record; every node identity is qualified by it", normalizeDir)
	}
	c.org = str(c.dirs["org"][0].fields["org"])
	if c.org == "" {
		return nil, fmt.Errorf("%s: organization record has no %q", c.dirs["org"][0].rel, "org")
	}

	for _, e := range c.chainArray("effective-ruleset", "effective_per_branch") {
		branch := str(e["branch"])
		repo := c.full(str(e["repo"]))
		if repo == "" || branch == "" {
			continue
		}
		k := repo + "\x00" + engine.BranchSlug(branch)
		if prev, dup := c.trueBranch[k]; dup && prev != branch {
			branch = ""
		}
		c.trueBranch[k] = branch
	}
	return c, nil
}

// full qualifies a bare repo name. Every identity property that names a
// repository holds "owner/repo" so joins survive a second org being scanned.
func (c *corpus) full(repo string) string {
	if repo == "" {
		return ""
	}
	return c.org + "/" + repo
}

// repoNames returns the bare repo names of the org's repository records, in
// record order, optionally filtered on the record's own fields.
func (c *corpus) repoNames(keep func(map[string]any) bool) []string {
	out := make([]string, 0, len(c.dirs["repos"]))
	for _, r := range c.dirs["repos"] {
		if keep != nil && !keep(r.fields) {
			continue
		}
		if name := str(r.fields["repo"]); name != "" {
			out = append(out, name)
		}
	}
	return out
}

func (c *corpus) chainArray(file, key string) []map[string]any {
	return objects(c.chains[file][key])
}

func (c *corpus) chainSource(file, key string) string {
	return "chains/" + file + ".json#" + key
}

// secretScopeKey canonicalizes the scope a secret lives in. It is built from the
// record's own repo/environment fields, never by splitting the "__"-slugged
// scope_key, which is ambiguous.
func (c *corpus) secretScopeKey(f map[string]any) string {
	switch str(f["scope"]) {
	case "org":
		return c.org
	case "repo":
		return c.full(str(f["repo"]))
	case "environment":
		repo, env := c.full(str(f["repo"])), str(f["environment"])
		if repo == "" || env == "" {
			return ""
		}
		return repo + ":" + env
	}
	return ""
}

// runnerScopeKey qualifies a runner's scope the way secretScopeKey does: repo
// runner ids are a per-repository sequence, so an unqualified scope_key would
// collapse every repo's first runner onto one node.
func (c *corpus) runnerScopeKey(f map[string]any) string {
	switch str(f["scope"]) {
	case "org":
		return c.org
	case "repo":
		return c.full(cmp.Or(str(f["repo"]), str(f["scope_key"])))
	}
	return ""
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

func truthy(v any) bool {
	b, _ := v.(bool)
	return b
}

func objects(v any) []map[string]any {
	a, _ := v.([]any)
	out := make([]map[string]any, 0, len(a))
	for _, e := range a {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
