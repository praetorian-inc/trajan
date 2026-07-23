package detect

import (
	"regexp"
	"slices"
	"strings"
)

// The inner capture stops at '|' to reject (unsupported) filter syntax.
var templRe = regexp.MustCompile(`\{\{\s*([^}|]+?)\s*\}\}`)

func renderEvidence(template string, subject any) string {
	return templRe.ReplaceAllStringFunc(template, func(match string) string {
		m := templRe.FindStringSubmatch(match)
		path := strings.TrimSpace(m[1])
		value := getPath(subject, path)
		if value == nil {
			return "<none>"
		}
		if items, ok := value.([]any); ok {
			parts := make([]string, len(items))
			for i, item := range items {
				parts[i] = humanValue(item)
			}
			return strings.Join(parts, ", ")
		}
		return humanValue(value)
	})
}

// salientKeys are the identifier fields evidence should lead with when rendering
// a record (secret name, app slug, collaborator login, …), in preference order.
var salientKeys = []string{"name", "login", "slug", "app_slug", "id", "uses", "_id"}

// humanValue renders an evidence value for display, recursively, so no Go
// map[...]/[...] syntax ever reaches the output. Scalars keep toStringValue's
// Python-str semantics (True/False/None); a record renders as its salient
// identifier when it has one, else as sorted key=value pairs; a list renders as
// bracketed, comma-joined elements. Trajan-internal keys (the "_"-prefixed
// provenance/metadata like _chain/_provenance) are dropped — they belong in
// provenance, not a sentence. The full structured value is preserved there.
func humanValue(v any) string {
	switch t := v.(type) {
	case map[string]any:
		for _, k := range salientKeys {
			if s, ok := t[k].(string); ok && s != "" {
				return s
			}
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			if strings.HasPrefix(k, "_") {
				continue
			}
			keys = append(keys, k)
		}
		slices.Sort(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"="+humanValue(t[k]))
		}
		return strings.Join(parts, " ")
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = humanValue(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return toStringValue(v)
	}
}

// evidenceRefs returns the unique {{ path }} expressions in a template, in
// first-seen order, so provenance can resolve and carry the values they render.
func evidenceRefs(template string) []string {
	var refs []string
	seen := map[string]bool{}
	for _, m := range templRe.FindAllStringSubmatch(template, -1) {
		ref := strings.TrimSpace(m[1])
		if ref == "" || seen[ref] {
			continue
		}
		seen[ref] = true
		refs = append(refs, ref)
	}
	return refs
}
