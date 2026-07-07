package github

import (
	"regexp"
	"strings"
)

var lowTrustTriggers = map[string]bool{
	"pull_request":                true,
	"pull_request_target":         true,
	"pull_request_review":         true,
	"pull_request_review_comment": true,
	"issue_comment":               true,
	"issues":                      true,
	"discussion":                  true,
	"discussion_comment":          true,
	"fork":                        true,
	"watch":                       true,
	"star":                        true,
	"public":                      true,
}

var mediumTrustTriggers = map[string]bool{
	"workflow_dispatch":   true,
	"repository_dispatch": true,
	"workflow_run":        true,
	"workflow_call":       true,
	"check_run":           true,
	"check_suite":         true,
	"label":               true,
}

var highTrustTriggers = map[string]bool{
	"push":                   true,
	"release":                true,
	"deployment":             true,
	"deployment_status":      true,
	"schedule":               true,
	"milestone":              true,
	"page_build":             true,
	"create":                 true,
	"delete":                 true,
	"registry_package":       true,
	"branch_protection_rule": true,
}

func classifyTrigger(trigger string) string {
	t := strings.ToLower(trigger)
	switch {
	case lowTrustTriggers[t]:
		return "low"
	case mediumTrustTriggers[t]:
		return "medium"
	case highTrustTriggers[t]:
		return "high"
	default:
		return "medium"
	}
}

func triggerClassSummary(triggers []string) TriggerClassSummary {
	out := TriggerClassSummary{
		LowTrust:  []string{},
		Medium:    []string{},
		HighTrust: []string{},
	}
	for _, tr := range triggers {
		switch classifyTrigger(tr) {
		case "low":
			out.LowTrust = append(out.LowTrust, tr)
		case "high":
			out.HighTrust = append(out.HighTrust, tr)
		default:
			out.Medium = append(out.Medium, tr)
		}
	}
	return out
}

var triggerToAttackerFields = map[string][]string{
	"pull_request": {
		"github.event.pull_request.title", "github.event.pull_request.body",
		"github.event.pull_request.head.ref", "github.event.pull_request.head.sha",
		"github.event.pull_request.head.repo",
		"github.event.pull_request.user.login",
		"github.head_ref", "github.event.number",
	},
	"pull_request_target": {
		"github.event.pull_request.title", "github.event.pull_request.body",
		"github.event.pull_request.head.ref", "github.event.pull_request.head.sha",
		"github.event.pull_request.head.repo",
		"github.event.pull_request.user.login",
		"github.head_ref", "github.event.number",
	},
	"pull_request_review": {
		"github.event.review.body", "github.event.review.user.login",
		"github.event.pull_request.title", "github.event.pull_request.body",
		"github.event.pull_request.head.ref", "github.event.pull_request.head.sha",
	},
	"pull_request_review_comment": {
		"github.event.comment.body", "github.event.comment.user.login",
		"github.event.pull_request.title", "github.event.pull_request.body",
		"github.event.pull_request.head.ref", "github.event.pull_request.head.sha",
	},
	"issue_comment": {
		"github.event.comment.body", "github.event.comment.user.login",
		"github.event.issue.title", "github.event.issue.body",
		"github.event.issue.user.login",
	},
	"issues": {
		"github.event.issue.title", "github.event.issue.body",
		"github.event.issue.user.login",
	},
	"discussion": {
		"github.event.discussion.title", "github.event.discussion.body",
	},
	"discussion_comment": {
		"github.event.comment.body",
	},
	"workflow_dispatch": {
		"github.event.inputs", "inputs",
	},
	"repository_dispatch": {
		"github.event.client_payload",
	},
	"workflow_run": {
		"github.event.workflow_run.head_branch",
		"github.event.workflow_run.head_sha",
		"github.event.workflow_run.head_repository",
		"github.event.workflow_run.pull_requests",
	},
}

// Deterministic order (triggers input order, fields declaration order) because
// the Python original iterated a set, which made downstream break-on-first
// matching order-dependent.
func attackerFieldsForTriggers(triggers []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, tr := range triggers {
		for _, f := range triggerToAttackerFields[tr] {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	return out
}

var interpRe = regexp.MustCompile(`\$\{\{\s*([^}]+?)\s*\}\}`)

func extractInterpolations(text string) []string {
	if text == "" {
		return []string{}
	}
	matches := interpRe.FindAllStringSubmatch(text, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, strings.TrimSpace(m[1]))
	}
	return out
}

func exprMatchesPrefix(expr, prefix string) bool {
	return strings.HasPrefix(expr, prefix) ||
		strings.HasPrefix(expr, "toJSON("+prefix) ||
		strings.HasPrefix(expr, "toJson("+prefix)
}

func findAttackerReferences(text string, triggers []string) []string {
	attackerFields := attackerFieldsForTriggers(triggers)
	var refs []string
	seen := map[string]bool{}
	for _, expr := range extractInterpolations(text) {
		for _, prefix := range attackerFields {
			if exprMatchesPrefix(expr, prefix) {
				if !seen[prefix] {
					seen[prefix] = true
					refs = append(refs, prefix)
				}
				break
			}
		}
	}
	return refs
}

var needsOutputRE = regexp.MustCompile(`needs\.([A-Za-z_][A-Za-z0-9_-]*)\.outputs\.([A-Za-z_][A-Za-z0-9_-]*)`)

// Matches on the raw blob, not extractInterpolations, so a ref nested inside
// fromJSON(needs.X.outputs.Y) or a larger ${{ }} expression is still caught.
func extractNeedsOutputRefs(text string) []NeedsOutputRef {
	out := []NeedsOutputRef{}
	seen := map[[2]string]bool{}
	for _, m := range needsOutputRE.FindAllStringSubmatch(text, -1) {
		key := [2]string{m[1], m[2]}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, NeedsOutputRef{JobID: m[1], OutputName: m[2]})
	}
	return out
}
