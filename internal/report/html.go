package report

import (
	"bytes"
	"cmp"
	_ "embed"
	"fmt"
	"html/template"
	"maps"
	"slices"
	"strings"
	"unicode"

	"github.com/praetorian-inc/trajan/internal/finding"
)

//go:embed assets/report.html
var htmlSource string

//go:embed assets/report.css
var htmlCSS string

//go:embed assets/report.js
var htmlJS string

type htmlView struct {
	CSS         template.CSS
	JS          template.JS
	Platform    string
	Scope       string
	RunID       string
	GeneratedAt string
	Total       int
	RuleCount   int
	Severities  []bucket
	Confidences []bucket
	RuleGroups  []ruleGroup
	Findings    []finding.Finding
}

type bucket struct {
	Key   string
	Label string
	N     int
}

type ruleGroup struct {
	Cat   string
	N     int
	Rules []ruleEntry
}

type ruleEntry struct {
	ID   string
	Leaf string
	N    int
}

type kv struct{ K, V string }

var platformNames = map[string]string{
	"ado":     "Azure DevOps",
	"github":  "GitHub",
	"gitlab":  "GitLab",
	"jenkins": "Jenkins",
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"titleCase":   titleCase,
	"location":    locationOf,
	"ruleID":      ruleID,
	"plural":      plural,
	"trim":        strings.TrimSpace,
	"codeCaption": codeCaption,
	"provRows":    provRows,
	"hasDetails":  hasDetails,
}).Parse(htmlSource))

func renderHTML(meta reportMeta, findings []finding.Finding) ([]byte, error) {
	groups := ruleGroups(findings)
	view := htmlView{
		CSS:         template.CSS(htmlCSS),
		JS:          template.JS(htmlJS),
		Platform:    platformLabel(meta, findings),
		Scope:       cmp.Or(meta.Scope, meta.Org, meta.RunID),
		RunID:       meta.RunID,
		GeneratedAt: meta.Generated.UTC().Format("2 Jan 2006 15:04 UTC"),
		Total:       meta.Total,
		Severities:  buckets(meta.BySeverity, severityOrder),
		Confidences: buckets(meta.ByConfidence, confidenceOrder),
		RuleGroups:  groups,
		Findings:    findings,
	}
	for _, g := range groups {
		view.RuleCount += len(g.Rules)
	}
	var buf bytes.Buffer
	if err := htmlTemplate.Execute(&buf, view); err != nil {
		return nil, fmt.Errorf("render html: %w", err)
	}
	return buf.Bytes(), nil
}

// A run written before _meta.json carried the platform still renders correctly:
// every finding names its own provider.
func platformLabel(meta reportMeta, findings []finding.Finding) string {
	p := meta.Platform
	if p == "" && len(findings) > 0 {
		p = findings[0].Provider
	}
	if name, ok := platformNames[p]; ok {
		return name
	}
	return p
}

// Rule ids are "cat-NN/rule-name" on every platform, so the leading segment
// groups the sidebar. An id without one still lists, just ungrouped.
func ruleGroups(findings []finding.Finding) []ruleGroup {
	counts := countBy(findings, ruleID)
	delete(counts, "")

	byCat := map[string][]ruleEntry{}
	for _, id := range slices.Sorted(maps.Keys(counts)) {
		cat, leaf, found := strings.Cut(id, "/")
		if !found {
			cat, leaf = "", id
		}
		byCat[cat] = append(byCat[cat], ruleEntry{ID: id, Leaf: leaf, N: counts[id]})
	}

	out := make([]ruleGroup, 0, len(byCat))
	for _, cat := range slices.Sorted(maps.Keys(byCat)) {
		g := ruleGroup{Cat: cat, Rules: byCat[cat]}
		for _, r := range g.Rules {
			g.N += r.N
		}
		out = append(out, g)
	}
	return out
}

func buckets(counts map[string]int, order []string) []bucket {
	var out []bucket
	for _, k := range present(counts, order) {
		out = append(out, bucket{Key: k, Label: titleCase(k), N: counts[k]})
	}
	return out
}

func provRows(f finding.Finding) []kv {
	out := make([]kv, 0, len(f.Provenance))
	for _, k := range sortedKeys(f.Provenance) {
		out = append(out, kv{k, provString(f.Provenance[k])})
	}
	return out
}

type location struct {
	Path  string
	Label string
}

// The headline is where a finding lives: org / repo / file. A GitHub repo slug
// already contains its org, so it is not prepended twice; with no file there is
// no path, so the label carries the subject kind instead.
func locationOf(f finding.Finding) location {
	var seg []string
	if f.Org != "" && !strings.HasPrefix(f.Repo, f.Org+"/") {
		seg = append(seg, f.Org)
	}
	if f.Repo != "" {
		seg = append(seg, f.Repo)
	}
	if file := strings.TrimPrefix(f.File, "/"); file != "" {
		return location{Path: strings.Join(append(seg, file), "/")}
	}
	if len(seg) == 0 {
		return location{Path: f.Subject.Display}
	}
	return location{
		Path:  strings.Join(seg, "/"),
		Label: strings.ToUpper(strings.ReplaceAll(f.Subject.Kind, "_", " ")),
	}
}

func hasDetails(f finding.Finding) bool {
	return f.Rule != nil || f.Subject.Display != "" ||
		strings.TrimSpace(f.Description) != "" || len(f.Provenance) > 0
}

func titleCase(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	return string(unicode.ToUpper(r[0])) + string(r[1:])
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
