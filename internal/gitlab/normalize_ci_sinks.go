package gitlab

import (
	"regexp"
	"strings"
)

// Sink and dependency-edge extraction over a parsed job: needs:/dotenv/cache/
// artifacts/image/id_tokens/job-token usage. Feeds both the job record fields and
// the dotenv-flow / cache-keyspace / cross-project-artifact correlate joins.

// ---- needs / cross-project ----

// crossProjectNeeds returns {project, artifacts} tuples for needs:project: (and
// needs:pipeline: with a project) entries. Bare same-project needs are excluded.
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

// consumesCrossPipelineArtifact reports needs:pipeline:job: (or needs:pipeline
// artifacts:true) fetching from a different pipeline in the same project.
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

// ---- dotenv ----

func producesDotenv(job map[string]any) bool {
	return entGetIn(job, "artifacts", "reports", "dotenv") != nil
}

// dotenvContentAttackerInfluenced reports whether the dotenv producer's script
// writes non-constant content (command substitution, a variable, fetched value)
// rather than a fixed literal set.
var reCmdSubst = regexp.MustCompile(`\$\(|` + "`" + `|\$\{?[A-Za-z_]`)

func dotenvContentAttackerInfluenced(job map[string]any) bool {
	for _, line := range asStrList(job["script"]) {
		if (strings.Contains(line, ".env") || strings.Contains(line, ">>")) && reCmdSubst.MatchString(line) {
			return true
		}
	}
	return false
}

// consumesDotenv reports whether the job inherits dotenv variables from a needs:
// producer (a plain job dependency that isn't dependencies:[] narrowed).
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

// dotenvInheritanceUnnarrowed reports the consumer does NOT narrow dotenv
// inheritance: no dependencies:[] and no inherit:{variables:false}/list.
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

// ---- cache ----

// cacheEntries returns {key, key_files, policy} tuples. cache: may be a single
// map or a list of maps.
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

// cacheKey returns (literal key, files list). key may be a string or {files, prefix}.
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

// cacheKeyStaticCrossBoundary reports the cache:key is static/global (no
// $CI_COMMIT_REF_SLUG / protection component), so it collides across the boundary.
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
			continue // content-addressed, handled by key_files_attacker_writable
		}
		if !strings.Contains(key, "CI_COMMIT_REF") && !strings.Contains(key, "PROTECTED") {
			return true
		}
	}
	return false
}

// ---- artifacts / image / pages ----

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

// ---- id_tokens (cat-10) ----

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

// ---- job-token cross-project use (cat-04) ----

var (
	reJobTokenGitPush  = regexp.MustCompile(`gitlab-ci-token|CI_JOB_TOKEN.*(git push|/repository/)|git push.*CI_JOB_TOKEN`)
	reJobTokenTFState  = regexp.MustCompile(`CI_JOB_TOKEN.*terraform/state|terraform/state.*CI_JOB_TOKEN`)
	reJobTokenRead     = regexp.MustCompile(`CI_JOB_TOKEN|JOB-TOKEN:`)
	reJobArtifactFetch = regexp.MustCompile(`JOB-TOKEN:\s*\$?CI_JOB_TOKEN.*/jobs/artifacts|/jobs/artifacts.*JOB-TOKEN`)
)

// jobTokenCrossProjectUse classifies how the job wields CI_JOB_TOKEN off-project.
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

// executesFetchedArtifact / artifactIntegrityChecked (cat-09 consumer signals).
var (
	reExtractExec = regexp.MustCompile(`\btar\s+x|\bunzip\b|source\s+|\./|\binstall\b|cp\s+.*(/usr|/opt|/bin)`)
	reIntegrity   = regexp.MustCompile(`sha256sum\s+-c|cosign\s+verify|gpg\s+--verify|@sha256:`)
)

func executesFetchedArtifact(scriptText string) bool  { return reExtractExec.MatchString(scriptText) }
func artifactIntegrityChecked(scriptText string) bool { return reIntegrity.MatchString(scriptText) }

// reusesOnDiskCheckout (cat-08).
func reusesOnDiskCheckout(job, vars map[string]any) bool {
	strategy := entStr(mergeVarLookup(job, vars, "GIT_STRATEGY"))
	if strategy == "fetch" || strategy == "none" {
		return true
	}
	sub := entStr(mergeVarLookup(job, vars, "GIT_SUBMODULE_STRATEGY"))
	return sub == "recursive" || sub == "normal"
}

// mergeVarLookup reads a variable from the job's variables: then the global
// variables: block (job scope wins).
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

// childPipelineFromCrossProjectArtifact: trigger:include:artifact sourced from a
// generator job that pulls a cross-project artifact (cat-02).
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

// remoteStepUntrustedRef: a run: step/func from a remote git ref that is mutable
// or third-party (cat-02, the new run: steps syntax).
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

// cacheKeyFilesAttackerWritable: cache:key:files over source-tree files (any
// non-lockfile path is writable by a lower-trust actor on an unprotected branch).
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

// cachePathsExecutable: cached paths are dependency/executable dirs, not inert data.
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

// dotenvContentFromUntrustedSource: producer builds dotenv from runtime-fetched
// untrusted input (curl/wget/fetch of a lower-trust artifact) with no review gate.
var reFetch = regexp.MustCompile(`\bcurl\b|\bwget\b|\bgit clone\b|artifacts/`)

func dotenvContentFromUntrustedSource(job map[string]any) bool {
	if !producesDotenv(job) {
		return false
	}
	txt := jobScriptText(job)
	return reFetch.MatchString(txt) && reCmdSubst.MatchString(txt)
}

// package version pinning (cat-09).
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
