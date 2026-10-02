package ado

import (
	"context"

	"github.com/praetorian-inc/trajan/internal/engine"
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
	HierarchyKinds: []string{"org", "project"},
	Display:        adoDisplay,
	Repo:           adoRepo,
	File:           func(s map[string]any) string { return detect.StringField(s, "yaml_path") },
}

type ScanOptions = detect.ScanOptions

func Scan(ctx context.Context, cfg *engine.Config, runDir string, opts ScanOptions) error {
	return detect.Scan(ctx, cfg, runDir, adoScanProvider, opts)
}

func adoRepo(s map[string]any) string {
	project := detect.StringField(s, "project")
	repo := detect.StringField(s, "repo")
	switch detect.StringField(s, "kind") {
	case "Repository":
		repo = detect.StringField(s, "name")
	case "Pipeline":
		repo = azureReposName(entObj(s, "repository"))
	}
	if project == "" || repo == "" {
		return ""
	}
	return project + "/" + repo
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
