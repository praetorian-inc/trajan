// Package github collects, normalizes and scans a GitHub Actions estate.
package github

import (
	"fmt"
	"maps"
)

// The workflow-syntax permissions table, plus models — absent from the table but
// real, and a job cannot reach GitHub Models without it. repository-projects went
// with classic projects. Exported because a permissions: key outside this set is one
// GitHub refuses to parse, so anything composing a workflow must reject it first.
var PermissionScopes = []string{
	"actions", "artifact-metadata", "attestations", "checks", "code-quality",
	"contents", "deployments", "discussions", "id-token", "issues", "models",
	"packages", "pages", "pull-requests", "security-events", "statuses",
	"vulnerability-alerts",
}

// Scopes appearing in no GITHUB_TOKEN default-permission table, so a workflow that
// does not name id-token cannot mint an OIDC token however permissive the repository
// or organization default is. Workflow-level write-all does grant them, so this
// applies to the default layer only.
var OptInOnlyScopes = map[string]bool{"id-token": true, "attestations": true}

type permInputs struct {
	JobPerms           any
	WorkflowPerms      any
	RepoDefault        string
	OrgDefault         string
	JobProvenance      *SourceProvenance
	WorkflowProvenance *SourceProvenance
}

func normalizeBlock(block any) (str string, dict map[string]string, isDict bool) {
	switch v := block.(type) {
	case string:
		return v, nil, false
	case map[string]any:
		out := make(map[string]string, len(v))
		for k, val := range v {
			out[k] = pyStr(val)
		}
		return "", out, true
	default:
		return "", nil, false
	}
}

// The True/False/None spellings are contractual: normalized records and the
// findings rendered from them are compared byte for byte against a reference
// corpus, so a Go-idiomatic rendering is a diff in a customer's report.
func pyStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case nil:
		return "None"
	default:
		return fmt.Sprint(x)
	}
}

func expandShorthand(value string) map[string]string {
	switch value {
	case "read-all":
		return shorthandScopes("read")
	case "write-all":
		return shorthandScopes("write")
	case "restricted", "{}":
		return shorthandScopes("none")
	default:
		return map[string]string{}
	}
}

// read-all/write-all mean every scope at one level, except the two that lack that
// level: vulnerability-alerts has no write (write-all includes it as read), and
// id-token is write or nothing (read-all therefore grants it nothing).
func shorthandScopes(grant string) map[string]string {
	out := make(map[string]string, len(PermissionScopes))
	for _, s := range PermissionScopes {
		switch {
		case s == "vulnerability-alerts" && grant == "write":
			out[s] = "read"
		case s == "id-token" && grant == "read":
			out[s] = "none"
		default:
			out[s] = grant
		}
	}
	return out
}

// The repository- or organization-wide default grant is a smaller thing than a
// workflow's write-all: the opt-in scopes are never part of it.
func defaultScopeMap(grant string) map[string]string {
	out := shorthandScopes(grant)
	for s := range OptInOnlyScopes {
		out[s] = "none"
	}
	return out
}

func resolvePermissions(in permInputs) map[string]any {
	jStr, jDict, jIsDict := normalizeBlock(in.JobPerms)
	wStr, wDict, wIsDict := normalizeBlock(in.WorkflowPerms)
	jIsStr := isStringBlock(in.JobPerms)
	wIsStr := isStringBlock(in.WorkflowPerms)

	layered := map[string]string{}
	chain := []any{}

	switch in.OrgDefault {
	case "write", "read":
		maps.Copy(layered, defaultScopeMap(in.OrgDefault))
		chain = append(chain, map[string]any{"source": "org_default", "value": in.OrgDefault})
	}

	switch in.RepoDefault {
	case "write", "read":
		layered = defaultScopeMap(in.RepoDefault)
		chain = append(chain, map[string]any{"source": "repo_default", "value": in.RepoDefault})
	}

	finalSource := "implicit"
	switch {
	case in.RepoDefault != "":
		finalSource = "repo_default"
	case in.OrgDefault != "":
		finalSource = "org_default"
	}

	applyLayer := func(source string, isStr, isDict bool, str string, dict map[string]string, prov *SourceProvenance) {
		switch {
		case isStr:
			layered = expandShorthand(str)
			chain = append(chain, map[string]any{"source": source, "value": str, "_provenance": prov})
		case isDict:
			layered = allNone()
			maps.Copy(layered, dict)
			chain = append(chain, map[string]any{"source": source, "value": maps.Clone(dict), "_provenance": prov})
		default:
			return
		}
		finalSource = source
	}

	applyLayer("workflow", wIsStr, wIsDict, wStr, wDict, in.WorkflowProvenance)
	applyLayer("job", jIsStr, jIsDict, jStr, jDict, in.JobProvenance)

	out := map[string]any{"_source": finalSource, "_chain": chain}
	for k, v := range layered {
		out[k] = v
	}
	return out
}

func isStringBlock(block any) bool {
	_, ok := block.(string)
	return ok
}

func allNone() map[string]string {
	out := make(map[string]string, len(PermissionScopes))
	for _, s := range PermissionScopes {
		out[s] = "none"
	}
	return out
}
