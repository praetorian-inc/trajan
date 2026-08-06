package gitlab

import (
	"regexp"
	"strings"
)

// Deliberately literal and conservative: a rule keys on the emitted set or enum, so
// missing a trigger is safer than inventing one.

// GitLab runs a job on every pipeline source unless rules: or workflow: gates it, so
// this is the unconstrained default. The values are $CI_PIPELINE_SOURCE literals.
var allTriggers = []string{
	"push", "web", "api", "schedule", "trigger", "pipeline",
	"merge_request_event", "external_pull_request_event",
}

// An `if:` expression may reference $CI_PIPELINE_SOURCE by equality or by regex, and
// may name more than one source.
var reSourceEq = regexp.MustCompile(`\$CI_PIPELINE_SOURCE\s*==\s*["']([a-z_]+)["']`)
var reSourceIn = regexp.MustCompile(`\$CI_PIPELINE_SOURCE\s*=~\s*/([^/]+)/`)

// workflow: rules apply before the job's own. Only sources the rules name survive;
// with no constraint the job is reachable from all of them.
func resolveTriggers(job, workflow map[string]any) []string {
	jobRules := ruleExprs(job["rules"])
	wfRules := ruleExprs(workflow["rules"])

	constrained, sources := sourcesFromRules(append(append([]string{}, wfRules...), jobRules...))
	if !constrained {
		return append([]string{}, allTriggers...)
	}
	out := []string{}
	for _, s := range allTriggers {
		if sources[s] {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		// rules referenced a source we don't model; fall back to broad reachability.
		return append([]string{}, allTriggers...)
	}
	return out
}

// only: and except: are a separate legacy syntax, handled by their own callers.
func ruleExprs(rules any) []string {
	out := []string{}
	list, ok := rules.([]any)
	if !ok {
		return out
	}
	for _, r := range list {
		switch x := r.(type) {
		case string:
			out = append(out, x)
		case map[string]any:
			if s, ok := x["if"].(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func sourcesFromRules(exprs []string) (bool, map[string]bool) {
	sources := map[string]bool{}
	constrained := false
	for _, e := range exprs {
		for _, m := range reSourceEq.FindAllStringSubmatch(e, -1) {
			sources[m[1]] = true
			constrained = true
		}
		for _, m := range reSourceIn.FindAllStringSubmatch(e, -1) {
			for _, alt := range strings.Split(m[1], "|") {
				sources[strings.Trim(alt, "^$() ")] = true
			}
			constrained = true
		}
	}
	return constrained, sources
}

func hasMergeRequestTrigger(triggers []string) bool {
	for _, t := range triggers {
		if t == "merge_request_event" {
			return true
		}
	}
	return false
}

var (
	reRefProtected  = regexp.MustCompile(`\$CI_COMMIT_REF_PROTECTED\s*==\s*["']?true`)
	reDefaultBranch = regexp.MustCompile(`\$CI_COMMIT_BRANCH\s*==\s*\$CI_DEFAULT_BRANCH|\$CI_COMMIT_REF_NAME\s*==\s*["']?(main|master)`)
	reCommitTag     = regexp.MustCompile(`\$CI_COMMIT_TAG`)
)

// strong is an explicit $CI_COMMIT_REF_PROTECTED test; weak only pins a protected
// branch or tag by name, which a rename or a new protection rule can undo.
func protectedRefGate(job, workflow map[string]any) string {
	exprs := append(ruleExprs(workflow["rules"]), ruleExprs(job["rules"])...)
	if only := asStrList(job["only"]); len(only) > 0 {
		exprs = append(exprs, strings.Join(only, " "))
	}
	joined := strings.Join(exprs, "\n")
	if joined == "" {
		return "none"
	}
	if reRefProtected.MatchString(joined) {
		return "strong"
	}
	if reDefaultBranch.MatchString(joined) || reCommitTag.MatchString(joined) {
		return "weak"
	}
	return "none"
}

// Reachable on a ref an attacker can name: MR-event reachable, or no protected-ref
// gate at all.
func runsOnUntrustedRef(triggers []string, gate string) bool {
	if gate == "strong" {
		return false
	}
	if hasMergeRequestTrigger(triggers) {
		return true
	}
	return gate != "weak"
}

var (
	reMRMeta        = regexp.MustCompile(`\$CI_MERGE_REQUEST_(TITLE|DESCRIPTION|SOURCE_BRANCH_NAME|LABELS|MILESTONE|ASSIGNEES)`)
	reRefName       = regexp.MustCompile(`\$CI_COMMIT_REF_(NAME|SLUG)|\$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`)
	reCommitMessage = regexp.MustCompile(`\$CI_COMMIT_(MESSAGE|DESCRIPTION|TITLE)`)
	reComponentIn   = regexp.MustCompile(`\$\[\[\s*inputs\.`)
)

// Order is fixed rather than discovered, so the emitted list is stable across runs.
func attackerInputFields(scriptText string) []string {
	out := []string{}
	if reMRMeta.MatchString(scriptText) {
		out = append(out, "mr_metadata")
	}
	if reRefName.MatchString(scriptText) {
		out = append(out, "ref_name")
	}
	if reCommitMessage.MatchString(scriptText) {
		out = append(out, "commit_message")
	}
	if reComponentIn.MatchString(scriptText) {
		out = append(out, "component_input")
	}
	return out
}

var reVarInterp = regexp.MustCompile(`\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\$\[\[`)

// selfHost is the instance's own host, taken from project.web_url, and is what decides
// whether a remote include is first- or third-party.
func classifyIncludes(includeNode any, selfHost, ownerNamespace string) ([]any, includeFlags) {
	out := []any{}
	var f includeFlags
	for _, entry := range includeEntries(includeNode) {
		typ, tup, flags := classifyOneInclude(entry, selfHost, ownerNamespace)
		if typ == "" {
			continue
		}
		out = append(out, tup)
		f.merge(flags)
	}
	return out, f
}

type includeFlags struct {
	remoteUntrustedHost bool
	remoteCleartext     bool
	mutableCrossTrust   bool
	mutableComponent    bool
	refInterpolated     bool
	bareRefShadowable   bool
}

func (f *includeFlags) merge(o includeFlags) {
	f.remoteUntrustedHost = f.remoteUntrustedHost || o.remoteUntrustedHost
	f.remoteCleartext = f.remoteCleartext || o.remoteCleartext
	f.mutableCrossTrust = f.mutableCrossTrust || o.mutableCrossTrust
	f.mutableComponent = f.mutableComponent || o.mutableComponent
	f.refInterpolated = f.refInterpolated || o.refInterpolated
	f.bareRefShadowable = f.bareRefShadowable || o.bareRefShadowable
}

// include: is accepted by GitLab as a string, a list of strings, one map, or a list of
// maps.
func includeEntries(node any) []any {
	switch x := node.(type) {
	case nil:
		return nil
	case string:
		return []any{map[string]any{"local": x}}
	case map[string]any:
		return []any{x}
	case []any:
		out := []any{}
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, map[string]any{"local": s})
			} else {
				out = append(out, e)
			}
		}
		return out
	}
	return nil
}

func classifyOneInclude(entry any, selfHost, ownerNamespace string) (string, map[string]any, includeFlags) {
	m, ok := entry.(map[string]any)
	if !ok {
		return "", nil, includeFlags{}
	}
	var f includeFlags
	tup := map[string]any{"pinned": false, "cross_trust": false, "source_host": nil}
	var ref string
	if r, ok := m["ref"].(string); ok {
		ref = r
	}
	tup["ref"] = strOrNil(ref)
	hasIntegrity := m["integrity"] != nil

	switch {
	case m["remote"] != nil:
		u, _ := m["remote"].(string)
		host := hostOf(u)
		tup["type"] = "remote"
		tup["source_host"] = strOrNil(host)
		tup["pinned"] = hasIntegrity
		firstParty := host == selfHost || host == ""
		tup["cross_trust"] = !firstParty
		if !firstParty && !hasIntegrity {
			f.remoteUntrustedHost = true
		}
		if strings.HasPrefix(strings.ToLower(u), "http://") && !hasIntegrity {
			f.remoteCleartext = true
		}
		if reVarInterp.MatchString(u) {
			f.refInterpolated = true
		}
		return "remote", tup, f
	case m["project"] != nil:
		proj, _ := m["project"].(string)
		tup["type"] = "project"
		crossTrust := ownerNamespace != "" && !strings.HasPrefix(proj, ownerNamespace)
		tup["cross_trust"] = crossTrust
		pinned := isPinnedRef(ref)
		tup["pinned"] = pinned
		if !pinned && crossTrust {
			f.mutableCrossTrust = true
		}
		if ref == "" || (!isPinnedRef(ref) && !isWildcard(ref)) {
			f.bareRefShadowable = true
		}
		if fileInterpolated(m["file"]) || reVarInterp.MatchString(ref) {
			f.refInterpolated = true
		}
		return "project", tup, f
	case m["component"] != nil:
		comp, _ := m["component"].(string)
		version := componentVersion(comp)
		tup["type"] = "component"
		tup["source_host"] = strOrNil(hostOf(comp))
		pinned := isPinnedRef(version)
		tup["pinned"] = pinned
		thirdParty := hostOf(comp) != selfHost && hostOf(comp) != ""
		tup["cross_trust"] = thirdParty
		if !pinned && thirdParty {
			f.mutableComponent = true
		}
		return "component", tup, f
	case m["template"] != nil:
		tup["type"] = "template"
		tup["pinned"] = true // GitLab-maintained templates are first-party
		return "template", tup, f
	case m["local"] != nil:
		loc, _ := m["local"].(string)
		tup["type"] = "local"
		tup["pinned"] = true
		if reVarInterp.MatchString(loc) {
			f.refInterpolated = true
		}
		return "local", tup, f
	}
	return "", nil, includeFlags{}
}

func fileInterpolated(v any) bool {
	for _, f := range asStrList(v) {
		if reVarInterp.MatchString(f) {
			return true
		}
	}
	if s, ok := v.(string); ok {
		return reVarInterp.MatchString(s)
	}
	return false
}

// Only a 40-hex SHA or a semver-looking tag counts as immutable; a branch name and a
// moving tag such as latest are not.
func isPinnedRef(ref string) bool {
	if ref == "" {
		return false
	}
	if len(ref) == 40 && isHex(ref) {
		return true
	}
	return reSemverTag.MatchString(ref)
}

var reSemverTag = regexp.MustCompile(`^v?\d+\.\d+\.\d+`)

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// A component reference pins its version as an @suffix; absent means unpinned, which
// callers treat as mutable.
func componentVersion(comp string) string {
	if i := strings.LastIndex(comp, "@"); i >= 0 {
		return comp[i+1:]
	}
	return ""
}

func hostOf(u string) string {
	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/:"); i >= 0 {
		s = s[:i]
	}
	return s
}

func strOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}
