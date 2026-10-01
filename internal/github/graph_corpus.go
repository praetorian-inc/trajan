package github

import (
	"cmp"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/graph"
)

type ghRecord struct {
	rel    string
	dir    string
	id     string
	fields map[string]any
}

type ghCorpus struct {
	org    string
	dirs   map[string][]ghRecord
	chains map[string]map[string]any

	// Maps "<full repo>\x00<slug>" to the unslugged branch name, and to "" where two
	// branches share a slug ("feat/a" and "feat__a"). BranchSlug is not injective, so
	// an ambiguous slug must make the caller degrade rather than name one of the two.
	trueBranch map[string]string
}

func indexCorpus(src *graph.Corpus) (*ghCorpus, error) {
	c := &ghCorpus{
		dirs:       map[string][]ghRecord{},
		chains:     map[string]map[string]any{},
		trueBranch: map[string]string{},
	}
	for _, r := range src.Records {
		rec := ghRecord{rel: r.Rel, dir: r.Dir, id: r.ID, fields: r.Fields}
		if rec.dir == "chains" {
			c.chains[strings.TrimSuffix(filepath.Base(rec.rel), ".json")] = rec.fields
			continue
		}
		c.dirs[rec.dir] = append(c.dirs[rec.dir], rec)
	}

	if len(c.dirs["org"]) == 0 {
		return nil, fmt.Errorf("10-normalize/org: %w; every node identity is qualified by it", graph.ErrNoOrgRecord)
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

// Every identity property naming a repository holds "owner/repo", so joins survive
// a second org being scanned.
func (c *ghCorpus) full(repo string) string {
	if repo == "" {
		return ""
	}
	return c.org + "/" + repo
}

func (c *ghCorpus) repoNames(keep func(map[string]any) bool) []string {
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

func (c *ghCorpus) chainArray(file, key string) []map[string]any {
	return objects(c.chains[file][key])
}

func (c *ghCorpus) chainSource(file, key string) string {
	return "chains/" + file + ".json#" + key
}

// The canonical scope is built from the record's own repo/environment fields, never
// by splitting the "__"-slugged scope_key, which is ambiguous.
func (c *ghCorpus) secretScopeKey(f map[string]any) string {
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

// Repo runner ids are a per-repository sequence, so an unqualified scope_key would
// collapse every repo's first runner onto one node.
func (c *ghCorpus) runnerScopeKey(f map[string]any) string {
	switch str(f["scope"]) {
	case "org":
		return c.org
	case "repo":
		return c.full(cmp.Or(str(f["repo"]), str(f["scope_key"])))
	}
	return ""
}

func (c *ghCorpus) rulesetScopeKey(scope, repo string) string {
	switch scope {
	case "org":
		return c.org
	case "repo":
		return c.full(repo)
	}
	return ""
}

func str(v any) string               { return graph.Str(v) }
func truthy(v any) bool              { return graph.Truthy(v) }
func objects(v any) []map[string]any { return graph.Objects(v) }
