package ado

import (
	"context"
	"encoding/json"

	"github.com/praetorian-inc/trajan/internal/engine/detect"
)

// adoScanProvider wires Azure DevOps into the shared detection engine
// (internal/engine/detect): the subject-kind → 10-normalize-dir map — covering
// both structural nodes and the derived attack edges, which are consumed as rule
// subjects — plus the "ado" rule subtree and finding-label hooks.
var adoScanProvider = detect.Provider{
	Name:        "ado",
	RuleSubtree: "ado",
	SubjectDirs: map[string]string{
		// structural nodes
		"org":                "org",
		"project":            "projects",
		"repo":               "repos",
		"repository":         "repos",
		"pipeline":           "pipelines",
		"stage":              "stages",
		"job":                "jobs",
		"service_connection": "service-connections",
		"variable_group":     "variable-groups",
		"secret_variable":    "secret-variables",
		"environment":        "environments",
		"branch":             "branches",
		"branch_policy":      "policies",
		"feed":               "feeds",
		"key_vault":          "key-vaults",
		"extension":          "extensions",
		"secure_file":        "secure-files",
		"service_hook":       "service-hooks",
		"agent_pool":         "agent-pools",
		// derived attack edges (the taint/permission half of normalize)
		"queue_time_injection":      "edges/queue-time-injection",
		"logging_command_injection": "edges/logging-command-injection",
		"agent_injection":           "edges/agent-injection",
		"pipeline_poisoning":        "edges/pipeline-poisoning",
		"reads":                     "edges/reads",
		"can_push_to":               "edges/can-push-to",
		"can_merge_via_pr":          "edges/can-merge-via-pr",
		"can_bypass":                "edges/can-bypass",
	},
	Display:    adoDisplay,
	Repo:       func(s map[string]any) string { return detect.StringField(s, "project") },
	File:       func(s map[string]any) string { return detect.StringField(s, "yaml_path") },
	SubjectKey: adoSubjectKey,
}

// adoSubjectKey gives every subject a stable, unique finding identity. Nodes use
// their _id; derived-edge records (which carry no _id) use their full serialized
// form, so distinct edges never collide to a single finding.
func adoSubjectKey(s map[string]any) string {
	if id := detect.StringField(s, "_id"); id != "" {
		return id
	}
	b, _ := json.Marshal(s) // sorted keys → deterministic across runs
	return string(b)
}

// ScanOptions and Scan wrap the shared engine so callers use ado.Scan directly.
type ScanOptions = detect.ScanOptions

func Scan(ctx context.Context, runDir string, opts ScanOptions) error {
	return detect.Scan(ctx, runDir, adoScanProvider, opts)
}

// adoDisplay renders a finding's subject label. Node subjects carry a project +
// name/_id; derived-edge subjects (which have no _id) are labeled by their
// project and target job.
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
	if id := detect.StringField(s, "_id"); id != "" {
		return id
	}
	if t := detect.StringField(s, "target"); t != "" {
		return proj + " › " + t
	}
	if j := detect.StringField(s, "job"); j != "" {
		return proj + " › " + j
	}
	return proj
}
