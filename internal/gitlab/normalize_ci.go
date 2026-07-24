package gitlab

import (
	"regexp"
	"strings"
)

// GitLab .gitlab-ci.yml parsing for the job normalizer. P2 collects only the raw
// entrypoint at the default branch (collectCIConfig) — included file bodies
// (local/project/remote/component/template) are not on disk — so job discovery is
// entrypoint-only and include: declarations are parsed for classification (cat-02)
// rather than expanded into new jobs. rules:/workflow: are read structurally to
// derive the job's trigger set and ref-protection gate.

// reserved is the set of top-level keys that are pipeline configuration, not jobs.
var reserved = map[string]bool{
	"include": true, "variables": true, "stages": true, "workflow": true,
	"default": true, "image": true, "services": true, "cache": true,
	"before_script": true, "after_script": true, "pages": false, // pages is a real job (cat-14)
	"spec": true, ".pre": true, ".post": true,
}

// parseCIPipeline decodes the raw entrypoint into a pipeline map. A `spec:` header
// document (used for `inputs:` in reusable configs) precedes a `---` separator;
// the pipeline is the last mapping document. Anchors/hidden `.templates` are left
// in place — hidden keys (leading `.`) are filtered at job discovery. A
// well-formed but empty/comment-only config returns (nil, nil): no jobs, not an
// error. Only a YAML syntax error returns a non-nil error.
func parseCIPipeline(raw []byte) (map[string]any, error) {
	if raw == nil {
		return nil, nil
	}
	docs := splitYAMLDocs(raw)
	for i := len(docs) - 1; i >= 0; i-- {
		var m map[string]any
		if err := yamlUnmarshal(docs[i], &m); err != nil {
			return nil, err
		} else if m != nil {
			return m, nil
		}
	}
	return nil, nil
}

var reDocSep = regexp.MustCompile(`(?m)^---\s*$`)

func splitYAMLDocs(raw []byte) [][]byte {
	parts := reDocSep.Split(string(raw), -1)
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, []byte(p))
		}
	}
	if len(out) == 0 {
		return [][]byte{raw}
	}
	return out
}

// jobNames returns the top-level job keys in stable (sorted) order: entries that
// are maps, not reserved config keys, and not hidden templates (leading `.`).
func jobNames(pipeline map[string]any) []string {
	out := []string{}
	for k, v := range pipeline {
		if strings.HasPrefix(k, ".") || reserved[k] {
			continue
		}
		if _, ok := v.(map[string]any); ok {
			out = append(out, k)
		}
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// asStrList coerces a YAML scalar-or-sequence (script:, tags:, artifacts:paths:)
// into a []string. Nested sequences are flattened one level (script blocks may
// nest).
func asStrList(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		out := []string{}
		for _, e := range x {
			switch ee := e.(type) {
			case string:
				out = append(out, ee)
			case []any:
				for _, n := range ee {
					if s, ok := n.(string); ok {
						out = append(out, s)
					}
				}
			}
		}
		return out
	}
	return nil
}

// jobScriptText concatenates every script phase (before_script/script/after_script,
// and a run: step block) into one blob for attacker-input and sink analysis.
func jobScriptText(job map[string]any) string {
	var b strings.Builder
	for _, k := range []string{"before_script", "script", "after_script"} {
		for _, line := range asStrList(job[k]) {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	if run, ok := job["run"].([]any); ok {
		for _, s := range run {
			if step, ok := s.(map[string]any); ok {
				for _, line := range asStrList(step["script"]) {
					b.WriteString(line)
					b.WriteByte('\n')
				}
			}
		}
	}
	return b.String()
}

// mergeDefault overlays the pipeline `default:` block onto a job for keys the job
// does not set itself (image, cache, tags, before/after_script). GitLab applies
// default: to every job unless overridden.
func mergeDefault(job, def map[string]any) map[string]any {
	if len(def) == 0 {
		return job
	}
	merged := map[string]any{}
	for k, v := range def {
		merged[k] = v
	}
	for k, v := range job {
		merged[k] = v
	}
	return merged
}
