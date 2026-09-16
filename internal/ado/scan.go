package ado

import (
	"context"

	"github.com/praetorian-inc/trajan/internal/engine/detect"
)

var adoScanProvider = detect.Provider{
	Name:        "ado",
	RuleSubtree: "ado",
	SubjectDirs: map[string]string{
		"org":                       "org",
		"project":                   "projects",
		"repo":                      "repos",
		"repository":                "repos",
		"pipeline":                  "pipelines",
		"stage":                     "stages",
		"job":                       "jobs",
		"service_connection":        "service-connections",
		"variable_group":            "variable-groups",
		"secret_variable":           "secret-variables",
		"environment":               "environments",
		"branch":                    "branches",
		"branch_policy":             "policies",
		"feed":                      "feeds",
		"key_vault":                 "key-vaults",
		"extension":                 "extensions",
		"secure_file":               "secure-files",
		"service_hook":              "service-hooks",
		"agent_pool":                "agent-pools",
		"queue_time_injection":      "edges/queue-time-injection",
		"logging_command_injection": "edges/logging-command-injection",
		"agent_injection":           "edges/agent-injection",
		"pipeline_poisoning":        "edges/pipeline-poisoning",
		"reads":                     "edges/reads",
		"can_push_to":               "edges/can-push-to",
		"can_merge_via_pr":          "edges/can-merge-via-pr",
		"can_bypass":                "edges/can-bypass",
	},
	Display: adoDisplay,
	Repo:    func(s map[string]any) string { return detect.StringField(s, "project") },
	File:    func(s map[string]any) string { return detect.StringField(s, "yaml_path") },
}

type ScanOptions = detect.ScanOptions

func Scan(ctx context.Context, runDir string, opts ScanOptions) error {
	return detect.Scan(ctx, runDir, adoScanProvider, opts)
}

// An edge subject's _id discriminates rather than names, so it renders from its target.
func adoDisplay(kind string, s map[string]any) string {
	proj := detect.StringField(s, "project")
	switch kind {
	case "pipeline":
		if n := detect.StringField(s, "name"); n != "" {
			return proj + " › " + n
		}
	case "job", "stage":
		if id := detect.StringField(s, "_id"); id != "" {
			return proj + " › " + id
		}
	}
	if t := detect.StringField(s, "target"); t != "" {
		return proj + " › " + t
	}
	if j := detect.StringField(s, "job"); j != "" {
		return proj + " › " + j
	}
	if id := detect.StringField(s, "_id"); id != "" {
		return id
	}
	return proj
}
