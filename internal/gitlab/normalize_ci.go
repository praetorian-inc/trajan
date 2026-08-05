package gitlab

import (
	"regexp"
	"strings"
)

// Only the raw entrypoint is on disk — no included file bodies — so job discovery is
// entrypoint-only and include: declarations are classified rather than expanded into
// new jobs. rules: and workflow: are read structurally for the trigger set and the
// ref-protection gate.

var reserved = map[string]bool{
	"include": true, "variables": true, "stages": true, "workflow": true,
	"default": true, "image": true, "services": true, "cache": true,
	"before_script": true, "after_script": true, "pages": false, // pages is a real job (cat-14)
	"spec": true, ".pre": true, ".post": true,
}

// A `spec:` header document precedes a `---` separator, so the pipeline is the last
// mapping document. Hidden `.template` keys stay in place and are filtered at job
// discovery. An empty or comment-only config is (nil, nil): no jobs, not an error.
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

// Sorted, because a job record's identity must not depend on map iteration order.
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

// Nested sequences are flattened one level because a script: block may itself hold
// lists.
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

// Every phase is concatenated into one blob because attacker input reaching any of
// them reaches the same execution context.
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

// GitLab applies the pipeline `default:` block to every job unless the job overrides
// the key, so the job's own values win here.
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
