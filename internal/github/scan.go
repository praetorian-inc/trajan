package github

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine/detect"
	"github.com/praetorian-inc/trajan/internal/finding"
)

// Wires GitHub into the shared detection engine: the subject-kind → normalize-dir
// map, the rule subtree, and the hooks that read GitHub-specific fields.
var provider = detect.Provider{
	Name:        "github",
	RuleSubtree: "github",
	SubjectDirs: map[string]string{
		"job":         "jobs",
		"repo":        "repos",
		"org":         "org",
		"app":         "apps",
		"env":         "environments",
		"environment": "environments",
		"ruleset":     "rulesets",
		"deploy_key":  "deploy-keys",
	},
	Display: subjectDisplay,
	Code:    buildCode,
	Repo:    func(s map[string]any) string { return detect.StringField(s, "repo") },
	File:    workflowFilePath,
}

// The repo-relative locator that finding.code's line range indexes into.
// workflow_name is the author-declared `name:` and is not a path.
func workflowFilePath(subject map[string]any) string {
	if f := detect.StringField(subject, "workflow_filename"); f != "" {
		return ".github/workflows/" + f
	}
	return ""
}

// The scan itself is generic over platforms and lives in detect; callers reach it
// through the platform package they collected with.
type ScanOptions = detect.ScanOptions

func Scan(ctx context.Context, runDir string, opts ScanOptions) error {
	return detect.Scan(ctx, runDir, provider, opts)
}

// A pre-rendered label, so the renderer never parses subject.id.
func subjectDisplay(kind string, subject map[string]any) string {
	if kind == "job" {
		var parts []string
		for _, k := range []string{"repo", "workflow_filename", "job_id"} {
			if v := detect.StringField(subject, k); v != "" {
				parts = append(parts, v)
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, " › ")
		}
	}
	return detect.StringField(subject, "_id")
}

// Embeds the exact YAML window the subject points at, read from the collected
// workflow, so the finding is self-contained. Best-effort: a subject without a code
// location, or an unreadable file, yields nil rather than a scan failure.
func buildCode(runDir string, subject map[string]any) *finding.Code {
	prov, ok := subject["_provenance"].(map[string]any)
	if !ok {
		return nil
	}
	wf := detect.StringField(prov, "workflow_file")
	lr := intPair(prov["yaml_line_range"])
	if wf == "" || lr == nil || runDir == "" {
		return nil
	}
	snippet, err := readSnippet(filepath.Join(runDir, wf), lr[0], lr[1])
	if err != nil {
		return nil
	}
	return &finding.Code{LineRange: lr, Snippet: snippet}
}

func readSnippet(path string, start, end int) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(b), "\n")
	if start < 1 {
		start = 1
	}
	if end > len(lines) {
		end = len(lines)
	}
	if start > end {
		return "", fmt.Errorf("invalid line range [%d,%d] for %s (%d lines)", start, end, path, len(lines))
	}
	return strings.Join(lines[start-1:end], "\n"), nil
}

// Coerces a [start,end] range from JSON (float64 elements) or native ints.
func intPair(v any) []int {
	list, ok := v.([]any)
	if !ok || len(list) != 2 {
		return nil
	}
	out := make([]int, 2)
	for i, e := range list {
		switch n := e.(type) {
		case float64:
			out[i] = int(n)
		case int:
			out[i] = n
		default:
			return nil
		}
	}
	return out
}
