package gitlab

import (
	"regexp"
	"strings"
)

// Trigger, ref-protection, include and sink classification over a parsed job.
// Kept literal and conservative: a rule keys on the emitted set/enum, so a
// false-negative (missing trigger) is safer than inventing one.

// allTriggers is the default pipeline-source set a job runs on when neither
// rules: nor workflow: constrains it (GitLab runs a job on every source unless
// gated). Mirrors $CI_PIPELINE_SOURCE values the corpus reasons about.
var allTriggers = []string{
	"push", "web", "api", "schedule", "trigger", "pipeline",
	"merge_request_event", "external_pull_request_event",
}

// pipelineSourceFor maps a rules:/workflow: `if:` expression's referenced
// $CI_PIPELINE_SOURCE literal to a trigger. Multiple may appear.
var reSourceEq = regexp.MustCompile(`\$CI_PIPELINE_SOURCE\s*==\s*["']([a-z_]+)["']`)
var reSourceIn = regexp.MustCompile(`\$CI_PIPELINE_SOURCE\s*=~\s*/([^/]+)/`)

// resolveTriggers derives the trigger set from workflow:rules then job rules.
// When rules constrain $CI_PIPELINE_SOURCE, only the named sources survive;
// otherwise the job is reachable from every source.
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

// ruleExprs extracts the `if:` strings from a rules: list (or the string form of
// each entry). only:/except: are handled separately.
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

// hasMergeRequestTrigger reports the merge_request_event membership used across
// cat-01/03/09.
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

// protectedRefGate classifies how strongly a job's rules: gate its execution to a
// protected-ref context: strong (explicit $CI_COMMIT_REF_PROTECTED), weak (pins a
// specific protected branch/tag by name), or none.
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

// runsOnUntrustedRef reports whether the job is reachable on an attacker-nameable
// / unprotected ref: MR-event reachable, or no protected-ref gating on its rules.
func runsOnUntrustedRef(triggers []string, gate string) bool {
	if gate == "strong" {
		return false
	}
	if hasMergeRequestTrigger(triggers) {
		return true
	}
	return gate != "weak"
}

// ---- attacker input surface (cat-01) ----

var (
	reMRMeta        = regexp.MustCompile(`\$CI_MERGE_REQUEST_(TITLE|DESCRIPTION|SOURCE_BRANCH_NAME|LABELS|MILESTONE|ASSIGNEES)`)
	reRefName       = regexp.MustCompile(`\$CI_COMMIT_REF_(NAME|SLUG)|\$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`)
	reCommitMessage = regexp.MustCompile(`\$CI_COMMIT_(MESSAGE|DESCRIPTION|TITLE)`)
	reComponentIn   = regexp.MustCompile(`\$\[\[\s*inputs\.`)
)

// attackerInputFields returns the categories of untrusted input reaching an exec
// context (the job's script blocks). Order-stable.
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

// ---- include classification (cat-02) ----

var reVarInterp = regexp.MustCompile(`\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\$\[\[`)

// classifyIncludes parses the pipeline `include:` into normalized include tuples
// {type, ref, pinned, source_host, cross_trust}. selfHost is the instance host
// (project.web_url host) used to decide first-party vs third-party for remote.
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

// includeEntries normalizes the several YAML shapes of include: (string, list of
// strings, single map, list of maps) into a list of entries.
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

// isPinnedRef reports whether a ref is immutable: a 40-hex commit SHA or a
// semver-looking tag. Branch names and moving tags (latest, ~x) are mutable.
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

// componentVersion extracts the @version suffix of a component reference
// (gitlab.com/pub/comp@1.0). Absent → "" (treated mutable).
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
