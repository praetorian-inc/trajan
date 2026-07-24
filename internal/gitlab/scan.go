package gitlab

import (
	"context"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine/detect"
)

// gitlabScanProvider wires GitLab into the shared detection engine
// (internal/engine/detect): the subject-kind → 10-normalize-dir map covering all
// 11 GitLab subject kinds, the "gitlab" rule subtree, and the finding-label
// hooks that read GitLab-normalized fields.
var gitlabScanProvider = detect.Provider{
	Name:        "gitlab",
	RuleSubtree: "gitlab",
	SubjectDirs: map[string]string{
		"job":           "jobs",
		"project":       "projects",
		"group":         "groups",
		"instance":      "instance",
		"merge_request": "merge-requests",
		"environment":   "environments",
		"runner":        "runners",
		"agent":         "agents",
		"credential":    "credentials",
		"integration":   "integrations",
	},
	Display:    gitlabDisplay,
	Repo:       gitlabRepo,
	File:       gitlabFile,
	SubjectKey: func(s map[string]any) string { return detect.StringField(s, "_id") },
}

// ScanOptions keeps GitLab's own shape: GroupOnly restricts evaluation to
// group/instance-settings rules. The shared engine's ScanOptions.OrgOnly filters
// on the literal "org" subject kind, which GitLab has none of, so the flag is
// carried here and passed through unchanged.
type ScanOptions struct {
	GroupOnly bool
}

func Scan(ctx context.Context, runDir string, opts ScanOptions) error {
	return detect.Scan(ctx, runDir, gitlabScanProvider, detect.ScanOptions{OrgOnly: opts.GroupOnly})
}

// gitlabRepo is the project path a finding belongs to. Project-scoped subjects
// (job, environment, agent, integration, project, merge_request) key by a project
// full path in _id; group/instance/credential subjects are not project-scoped and
// return "".
func gitlabRepo(s map[string]any) string {
	id := detect.StringField(s, "_id")
	switch {
	case strings.Contains(id, ":"): // job "<project>:<name>"
		return id[:strings.LastIndex(id, ":")]
	case strings.Contains(id, "/"): // env/agent "<project>/<name>"; project/MR full path
		return id
	default:
		return ""
	}
}

// gitlabFile is the CI config a finding points at. GitLab jobs come from a single
// .gitlab-ci.yml; non-job subjects carry no source file.
func gitlabFile(s map[string]any) string {
	if strings.Contains(detect.StringField(s, "_id"), ":") {
		return ".gitlab-ci.yml"
	}
	return ""
}

// gitlabDisplay renders a finding's subject label. Jobs render "<project> › <job>";
// every other kind's _id (full path, "<project>/<name>", or "<kind>:<key>") is
// already human-readable.
func gitlabDisplay(kind string, s map[string]any) string {
	id := detect.StringField(s, "_id")
	if kind == "job" {
		if i := strings.LastIndex(id, ":"); i >= 0 {
			return id[:i] + " › " + id[i+1:]
		}
	}
	return id
}
