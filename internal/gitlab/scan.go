package gitlab

import (
	"context"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/engine/detect"
)

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
	HierarchyKinds: []string{"group", "instance"},
	Display:        gitlabDisplay,
	Repo:           gitlabRepo,
	File:           gitlabFile,
	SubjectKey:     func(s map[string]any) string { return detect.StringField(s, "_id") },
}

type ScanOptions = detect.ScanOptions

func Scan(ctx context.Context, cfg *engine.Config, runDir string, opts ScanOptions) error {
	return detect.Scan(ctx, cfg, runDir, gitlabScanProvider, opts)
}

// A project-scoped subject carries a project full path in its _id; group, instance and
// credential subjects are not project-scoped and have no repo.
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

// Every GitLab job comes from the one .gitlab-ci.yml; a non-job subject has no
// source file.
func gitlabFile(s map[string]any) string {
	if strings.Contains(detect.StringField(s, "_id"), ":") {
		return ".gitlab-ci.yml"
	}
	return ""
}

// Only a job needs reformatting; every other kind's _id already reads as a label.
func gitlabDisplay(kind string, s map[string]any) string {
	id := detect.StringField(s, "_id")
	if kind == "job" {
		if i := strings.LastIndex(id, ":"); i >= 0 {
			return id[:i] + " › " + id[i+1:]
		}
	}
	return id
}
