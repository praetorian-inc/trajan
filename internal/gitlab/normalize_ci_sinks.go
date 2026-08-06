package gitlab

import (
	"regexp"
	"strings"
)

// A bare needs: entry is same-project and excluded; only an explicit project: (or a
// pipeline: carrying one) crosses a trust boundary.
func crossProjectNeeds(job map[string]any) []any {
	out := []any{}
	for _, raw := range needsEntries(job["needs"]) {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if proj, ok := m["project"].(string); ok && proj != "" {
			out = append(out, map[string]any{
				"project":   proj,
				"artifacts": entBool(m["artifacts"]),
				"ref":       strOrNil(entStr(m["ref"])),
			})
		}
	}
	return out
}

func needsEntries(needs any) []any {
	switch x := needs.(type) {
	case []any:
		return x
	case string:
		return []any{map[string]any{"job": x}}
	}
	return nil
}

// Same project, different pipeline: the artifact still comes from a run this job's
// own review gate never covered.
func consumesCrossPipelineArtifact(job map[string]any) bool {
	for _, raw := range needsEntries(job["needs"]) {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if m["pipeline"] != nil && m["project"] == nil {
			return true
		}
	}
	return false
}

func artifactSourceRefMutable(job map[string]any) bool {
	for _, n := range crossProjectNeeds(job) {
		ref := entStr(entMap(n)["ref"])
		if !isPinnedRef(ref) {
			return true
		}
	}
	return false
}

func producesDotenv(job map[string]any) bool {
	return entGetIn(job, "artifacts", "reports", "dotenv") != nil
}

// Non-constant dotenv content — command substitution, a variable, a fetched value —
// is what makes the inherited variables steerable rather than fixed.
var reCmdSubst = regexp.MustCompile(`\$\(|` + "`" + `|\$\{?[A-Za-z_]`)

func dotenvContentAttackerInfluenced(job map[string]any) bool {
	for _, line := range asStrList(job["script"]) {
		if (strings.Contains(line, ".env") || strings.Contains(line, ">>")) && reCmdSubst.MatchString(line) {
			return true
		}
	}
	return false
}

// A plain job dependency inherits the producer's dotenv variables unless narrowed.
func consumesDotenv(job map[string]any, producers map[string]bool) bool {
	for _, raw := range needsEntries(job["needs"]) {
		var name string
		switch m := raw.(type) {
		case string:
			name = m
		case map[string]any:
			name = entStr(m["job"])
		}
		if producers[name] {
			return true
		}
	}
	return false
}

// Either dependencies:[] or inherit:{variables:...} narrows the inheritance; neither
// present means the consumer takes everything the producer wrote.
func dotenvInheritanceUnnarrowed(job map[string]any) bool {
	if deps, ok := job["dependencies"]; ok {
		if l, ok := deps.([]any); ok && len(l) == 0 {
			return false
		}
	}
	if inh, ok := job["inherit"].(map[string]any); ok {
		if v, ok := inh["variables"]; ok {
			if b, ok := v.(bool); ok && !b {
				return false
			}
			if _, ok := v.([]any); ok {
				return false
			}
		}
	}
	return true
}

// cache: is accepted by GitLab as one map or a list of maps.
func cacheEntries(job map[string]any) []any {
	out := []any{}
	for _, c := range cacheList(job["cache"]) {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		key, files := cacheKey(m["key"])
		out = append(out, map[string]any{
			"key":       strOrNil(key),
			"key_files": files,
			"policy":    entStr(m["policy"]),
		})
	}
	return out
}

func cacheList(c any) []any {
	switch x := c.(type) {
	case []any:
		return x
	case map[string]any:
		return []any{x}
	}
	return nil
}

// cache:key is either a literal string or a {files, prefix} object.
func cacheKey(k any) (string, []any) {
	switch x := k.(type) {
	case string:
		return x, []any{}
	case map[string]any:
		files := []any{}
		for _, f := range asStrList(x["files"]) {
			files = append(files, f)
		}
		return entStr(x["prefix"]), files
	}
	return "", []any{}
}

func cachePolicyWrites(job map[string]any) bool {
	for _, c := range cacheList(job["cache"]) {
		p := entStr(entMap(c)["policy"])
		if p == "" || p == "pull-push" || p == "push" {
			return true
		}
	}
	return false
}

// A key with no ref or protection component is global, so a cache written on an
// unprotected branch is the same entry a protected job later reads.
func cacheKeyStaticCrossBoundary(job map[string]any) bool {
	entries := cacheEntries(job)
	if len(entries) == 0 {
		return false
	}
	for _, e := range entries {
		m := entMap(e)
		key := entStr(m["key"])
		files := entList(m["key_files"])
		if len(files) > 0 {
			continue // content-addressed; cacheKeyFilesAttackerWritable covers these
		}
		if !strings.Contains(key, "CI_COMMIT_REF") && !strings.Contains(key, "PROTECTED") {
			return true
		}
	}
	return false
}

func artifactPaths(job map[string]any) []any {
	out := []any{}
	for _, p := range asStrList(entGetIn(job, "artifacts", "paths")) {
		out = append(out, p)
	}
	return out
}

func artifactsAccessUnrestricted(job map[string]any) bool {
	art := entMap(job["artifacts"])
	if art == nil {
		return false
	}
	if pub, ok := art["public"].(bool); ok && !pub {
		return false
	}
	switch entStr(art["access"]) {
	case "developer", "maintainer", "none":
		return false
	}
	return true
}

func artifactPathsBroad(job map[string]any) bool {
	for _, p := range asStrList(entGetIn(job, "artifacts", "paths")) {
		t := strings.TrimSpace(p)
		if t == "." || t == "./" || t == "/" || t == "*" {
			return true
		}
	}
	return false
}

func imageRef(job map[string]any) string {
	switch x := job["image"].(type) {
	case string:
		return x
	case map[string]any:
		return entStr(x["name"])
	}
	return ""
}

var reImageDigest = regexp.MustCompile(`@sha256:[0-9a-f]{64}`)
var reMutableTag = regexp.MustCompile(`:(latest|staging|stable|main|master|dev|edge|prod|production)$`)

func imageFromVariable(ref string) bool { return strings.Contains(ref, "$") }
func imagePinnedDigest(ref string) bool { return reImageDigest.MatchString(ref) }
func imageMutableTag(ref string) bool {
	if ref == "" || imagePinnedDigest(ref) || imageFromVariable(ref) {
		return false
	}
	if reMutableTag.MatchString(ref) {
		return true
	}
	return !strings.Contains(ref[strings.LastIndex(ref, "/")+1:], ":")
}

func isPagesJob(name string, job map[string]any) bool {
	if name == "pages" {
		return true
	}
	if v, ok := job["pages"]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
		return true
	}
	return false
}

func mintsIDToken(job map[string]any) bool { return entMap(job["id_tokens"]) != nil }

func idTokenAuds(job map[string]any) []any {
	out := []any{}
	for _, tok := range entMap(job["id_tokens"]) {
		m := entMap(tok)
		switch a := m["aud"].(type) {
		case string:
			out = append(out, a)
		case []any:
			out = append(out, a...)
		}
	}
	return out
}

var (
	reJobTokenGitPush  = regexp.MustCompile(`gitlab-ci-token|CI_JOB_TOKEN.*(git push|/repository/)|git push.*CI_JOB_TOKEN`)
	reJobTokenTFState  = regexp.MustCompile(`CI_JOB_TOKEN.*terraform/state|terraform/state.*CI_JOB_TOKEN`)
	reJobTokenRead     = regexp.MustCompile(`CI_JOB_TOKEN|JOB-TOKEN:`)
	reJobArtifactFetch = regexp.MustCompile(`JOB-TOKEN:\s*\$?CI_JOB_TOKEN.*/jobs/artifacts|/jobs/artifacts.*JOB-TOKEN`)
)

func jobTokenCrossProjectUse(scriptText string) string {
	switch {
	case reJobTokenGitPush.MatchString(scriptText):
		return "git_push"
	case reJobTokenTFState.MatchString(scriptText):
		return "terraform_state"
	case reJobTokenRead.MatchString(scriptText):
		return "read"
	}
	return "none"
}

func fetchesCrossProjectArtifact(job map[string]any, scriptText string) bool {
	if reJobArtifactFetch.MatchString(scriptText) {
		return true
	}
	for _, n := range crossProjectNeeds(job) {
		if entBool(entMap(n)["artifacts"]) {
			return true
		}
	}
	return false
}

var (
	reExtractExec = regexp.MustCompile(`\btar\s+x|\bunzip\b|source\s+|\./|\binstall\b|cp\s+.*(/usr|/opt|/bin)`)
	reIntegrity   = regexp.MustCompile(`sha256sum\s+-c|cosign\s+verify|gpg\s+--verify|@sha256:`)
)

func executesFetchedArtifact(scriptText string) bool  { return reExtractExec.MatchString(scriptText) }
func artifactIntegrityChecked(scriptText string) bool { return reIntegrity.MatchString(scriptText) }

func reusesOnDiskCheckout(job, vars map[string]any) bool {
	strategy := entStr(mergeVarLookup(job, vars, "GIT_STRATEGY"))
	if strategy == "fetch" || strategy == "none" {
		return true
	}
	sub := entStr(mergeVarLookup(job, vars, "GIT_SUBMODULE_STRATEGY"))
	return sub == "recursive" || sub == "normal"
}

// Job scope wins over the global variables: block, matching GitLab's own precedence.
func mergeVarLookup(job, globalVars map[string]any, key string) any {
	if jv := entMap(job["variables"]); jv != nil {
		if v, ok := jv[key]; ok {
			return v
		}
	}
	if globalVars != nil {
		return globalVars[key]
	}
	return nil
}

func runnerTags(job map[string]any) []any {
	out := []any{}
	for _, t := range asStrList(job["tags"]) {
		out = append(out, t)
	}
	return out
}

func deploysEnvironment(job map[string]any) (bool, string) {
	switch x := job["environment"].(type) {
	case string:
		return true, x
	case map[string]any:
		return true, entStr(x["name"])
	}
	return false, ""
}

var reEnvInterp = regexp.MustCompile(`\$\{?[A-Za-z_]`)

func environmentNameInterpolated(name string) bool { return reEnvInterp.MatchString(name) }

func downloadsSecureFile(scriptText string) bool {
	return strings.Contains(scriptText, "download-secure-files") || strings.Contains(scriptText, ".secure_files/")
}

func installsRegistryPackage(scriptText string) bool {
	return strings.Contains(scriptText, "${CI_API_V4_URL}/packages") ||
		strings.Contains(scriptText, "/packages/") && strings.Contains(scriptText, "install")
}

// A child pipeline whose config comes from an artifact a cross-project need supplied:
// the generated YAML is as trusted as the foreign project.
func childPipelineFromCrossProjectArtifact(job map[string]any, crossNeedJobs map[string]bool) bool {
	trig := entMap(job["trigger"])
	if trig == nil {
		return false
	}
	for _, inc := range includeEntries(trig["include"]) {
		m := entMap(inc)
		if m["artifact"] != nil {
			if src := entStr(m["job"]); src == "" || crossNeedJobs[src] {
				return true
			}
		}
	}
	return false
}

// A run: step sourced from a remote git ref that is either mutable or third-party.
func remoteStepUntrustedRef(job map[string]any) bool {
	run, ok := job["run"].([]any)
	if !ok {
		return false
	}
	for _, s := range run {
		step := entMap(s)
		var ref, gitRef string
		if step["step"] != nil {
			ref = entStr(step["step"])
		}
		if g := entMap(step["git"]); g != nil {
			gitRef = entStr(g["rev"])
			ref = entStr(g["url"])
		}
		if ref == "" {
			continue
		}
		if hostOf(ref) != "" && !isPinnedRef(gitRef) {
			return true
		}
	}
	return false
}

// cache:key:files over a source-tree path lets a lower-trust actor on an unprotected
// branch choose which cache entry a later job hits; a lockfile is the exception.
func cacheKeyFilesAttackerWritable(job map[string]any) bool {
	for _, c := range cacheList(job["cache"]) {
		_, files := cacheKey(entMap(c)["key"])
		if len(files) > 0 {
			return true
		}
	}
	return false
}

var reExecutablePath = regexp.MustCompile(`node_modules/|vendor/|\.venv/|\.m2/|\.gradle/|\.cargo/|\.bundle/`)

// A cached dependency or bin directory is executed on restore; inert data is not.
func cachePathsExecutable(job map[string]any) bool {
	for _, c := range cacheList(job["cache"]) {
		for _, p := range asStrList(entMap(c)["paths"]) {
			if reExecutablePath.MatchString(p) {
				return true
			}
		}
	}
	return false
}

// The producer builds its dotenv from something fetched at runtime, so no review gate
// ever saw the values that end up as the consumer's variables.
var reFetch = regexp.MustCompile(`\bcurl\b|\bwget\b|\bgit clone\b|artifacts/`)

func dotenvContentFromUntrustedSource(job map[string]any) bool {
	if !producesDotenv(job) {
		return false
	}
	txt := jobScriptText(job)
	return reFetch.MatchString(txt) && reCmdSubst.MatchString(txt)
}

var (
	reMutableVersion = regexp.MustCompile(`@(latest|\*|\^|~)|:latest|==\s*\*`)
	reChecksum       = regexp.MustCompile(`--require-hashes|integrity|sha256|--frozen-lockfile|npm ci\b`)
)

func packageVersionMutableRange(scriptText string) bool {
	if !installsRegistryPackage(scriptText) {
		return false
	}
	return reMutableVersion.MatchString(scriptText) || !strings.Contains(scriptText, "==")
}

func packageVersionChecksumVerified(scriptText string) bool {
	return reChecksum.MatchString(scriptText)
}
