package github

import (
	"fmt"
	"maps"
)

var allScopes = []string{
	"actions", "attestations", "checks", "contents", "deployments",
	"discussions", "id-token", "issues", "models", "packages", "pages",
	"pull-requests", "repository-projects", "security-events", "statuses",
}

var optInOnlyScopes = map[string]bool{"id-token": true, "attestations": true}

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

// stringifies like Python's str() so scope values stay byte-compatible with the Python output.
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
		return defaultScopeMap("read")
	case "write-all":
		return defaultScopeMap("write")
	case "restricted", "{}":
		return defaultScopeMap("none")
	default:
		return map[string]string{}
	}
}

// opt-in scopes are forced to "none": they are never inherited from defaults/shorthand.
func defaultScopeMap(grant string) map[string]string {
	out := make(map[string]string, len(allScopes))
	for _, s := range allScopes {
		if optInOnlyScopes[s] {
			out[s] = "none"
		} else {
			out[s] = grant
		}
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
	out := make(map[string]string, len(allScopes))
	for _, s := range allScopes {
		out[s] = "none"
	}
	return out
}
