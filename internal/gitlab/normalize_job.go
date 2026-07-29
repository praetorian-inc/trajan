package gitlab

import (
	"context"
	"regexp"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// Job is the resolved-job record handle produced by normalizeJobs. correlate
// re-reads jobs from disk rather than the returned slice, so this carries only
// the record's id and project for the orchestrator's call convention.
type Job struct {
	ID      string
	Project string
}

// jobContext folds the project/group/instance effective properties a job's fields
// depend on (runner reachability, variable posture, protected-ref model, includes,
// Duo, OIDC). Read once per project from the already-written normalized records
// (normalizeEntities runs before normalizeJobs) so job fields stay consistent with
// the subject records the same rules read.
type jobContext struct {
	project    map[string]any
	group      map[string]any
	instance   map[string]any
	selfHost   string
	namespace  string
	globalVars map[string]any
	workflow   map[string]any
	includes   []any
	incFlags   includeFlags
	duoAgent   []byte
	duoMCP     []byte
}

// normalizeJobs parses each project's .gitlab-ci.yml entrypoint, evaluates
// rules:/workflow: for triggers and ref-protection, classifies includes/sinks/
// reachability, and emits one job record per resolved job into 10-normalize/jobs.
// P2 collects only the raw entrypoint, so job discovery is entrypoint-only and
// include: bodies are classified (cat-02) rather than expanded into new jobs.
func normalizeJobs(ctx context.Context, prior engine.PriorPhase, cp engine.CurrentPhase, org string, projs []projectMeta, timer *engine.PhaseTimer) ([]Job, error) {
	var out []Job
	for _, p := range projs {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		raw := entLoadRaw(prior, engine.CollectGLCIConfig(p.FullPath, ".gitlab-ci.yml"))
		if raw == nil {
			continue
		}
		pipeline, err := parseCIPipeline(raw)
		if err != nil {
			itemErr(timer, "job:"+p.FullPath, err)
			continue
		}
		if pipeline == nil {
			continue
		}
		jc := loadJobContext(prior, p)
		jc.workflow = entMap(pipeline["workflow"])
		jc.globalVars = entMap(pipeline["variables"])
		jc.includes, jc.incFlags = classifyIncludes(pipeline["include"], jc.selfHost, jc.namespace)

		def := entMap(pipeline["default"])
		producers := dotenvProducers(pipeline)
		crossNeedJobs := crossNeedJobNames(pipeline, def)
		for _, name := range jobNames(pipeline) {
			job := mergeDefault(entMap(pipeline[name]), def)
			rec := buildJobRecord(p, name, job, jc, producers, crossNeedJobs)
			rel := engine.NormalizeGLJob(p.FullPath, ".gitlab-ci.yml", name)
			if err := emit(cp, timer, rel, rec); err != nil {
				return out, err
			}
			out = append(out, Job{ID: entStr(rec["_id"]), Project: p.FullPath})
		}
	}
	return out, nil
}

// dotenvProducers pre-scans the pipeline for jobs emitting a dotenv artifact so a
// consumer's consumes_dotenv can be resolved without a second full pass.
func dotenvProducers(pipeline map[string]any) map[string]bool {
	out := map[string]bool{}
	def := entMap(pipeline["default"])
	for _, name := range jobNames(pipeline) {
		if producesDotenv(mergeDefault(entMap(pipeline[name]), def)) {
			out[name] = true
		}
	}
	return out
}

// crossNeedJobNames is the set of jobs whose needs: pull a cross-project
// artifact, used to detect a child pipeline generated from that artifact (cat-02).
func crossNeedJobNames(pipeline, def map[string]any) map[string]bool {
	out := map[string]bool{}
	for _, name := range jobNames(pipeline) {
		if len(crossProjectNeeds(mergeDefault(entMap(pipeline[name]), def))) > 0 {
			out[name] = true
		}
	}
	return out
}

func loadJobContext(prior engine.PriorPhase, p projectMeta) jobContext {
	jc := jobContext{
		project:   readRecord(prior, engine.NormalizeGLProject(p.FullPath)),
		instance:  readRecord(prior, engine.NormalizeGLInstance()),
		namespace: parentGroup(p.FullPath),
	}
	if jc.namespace != "" {
		jc.group = readRecord(prior, engine.NormalizeGLGroup(jc.namespace))
	}
	detail := entLoadData(prior, engine.CollectGLProject(p.FullPath))
	jc.selfHost = hostOf(entStr(detail["web_url"]))
	jc.duoAgent = entLoadRaw(prior, engine.CollectGLRepoFile(p.FullPath, ".gitlab/duo/agent-config.yml"))
	jc.duoMCP = entLoadRaw(prior, engine.CollectGLRepoFile(p.FullPath, ".gitlab/duo/mcp.json"))
	return jc
}

func readRecord(prior engine.PriorPhase, rel string) map[string]any {
	var rec map[string]any
	if err := engine.ReadJSON(prior.Abs(rel), &rec); err != nil {
		return nil
	}
	return rec
}

// buildJobRecord assembles one job record with every field root from the contract.
func buildJobRecord(p projectMeta, name string, job map[string]any, jc jobContext, producers, crossNeedJobs map[string]bool) map[string]any {
	scriptText := jobScriptText(job)
	triggers := resolveTriggers(job, jc.workflow)
	gate := protectedRefGate(job, jc.workflow)
	untrustedRef := runsOnUntrustedRef(triggers, gate)
	deploysEnv, envName := deploysEnvironment(job)
	attackerFields := attackerInputFields(scriptText)
	imgRef := imageRef(job)
	cross := crossProjectNeeds(job)
	tags := runnerTags(job)

	proj := jc.project

	rec := map[string]any{
		"_id":                                        jobID(p.FullPath, name),
		"triggers":                                   toSet(triggers),
		"runs_on_untrusted_ref":                      untrustedRef,
		"runs_fork_mr_in_parent":                     hasMergeRequestTrigger(triggers) && mBool(proj, "fork_pipelines_run_in_parent"),
		"reads_cicd_variable":                        referencesAnyVariable(scriptText, job) || len(mList(proj, "cicd_variables")) > 0 && scriptText != "",
		"reads_protected_variable":                   jobReadsProtectedVar(proj, scriptText, job),
		"mints_id_token":                             mintsIDToken(job),
		"id_token_aud":                               idTokenAuds(job),
		"deploys_environment":                        deploysEnv,
		"environment_name":                           strOrNil(envName),
		"attacker_input_fields":                      toSet(attackerFields),
		"script_uses_untrusted_input":                len(attackerFields) > 0,
		"includes":                                   jc.includes,
		"remote_include_untrusted_host":              jc.incFlags.remoteUntrustedHost,
		"remote_include_cleartext":                   jc.incFlags.remoteCleartext,
		"mutable_cross_trust_project_include":        jc.incFlags.mutableCrossTrust,
		"mutable_component_version":                  jc.incFlags.mutableComponent,
		"include_ref_interpolated":                   jc.incFlags.refInterpolated,
		"include_bare_ref_shadowable":                jc.incFlags.bareRefShadowable,
		"cross_project_needs":                        cross,
		"produces_dotenv":                            producesDotenv(job),
		"consumes_dotenv":                            consumesDotenv(job, producers),
		"cache":                                      cacheEntries(job),
		"artifact_paths":                             artifactPaths(job),
		"publishes_pages":                            isPagesJob(name, job),
		"image_ref":                                  strOrNil(imgRef),
		"image_from_variable":                        imageFromVariable(imgRef),
		"image_pinned_digest":                        imagePinnedDigest(imgRef),
		"image_from_registry_mutable_tag":            imageMutableTag(imgRef),
		"job_token_cross_project_use":                jobTokenCrossProjectUse(scriptText),
		"runner_tags":                                toSet(strListOf(tags)),
		"protected_ref_gate":                         gate,
		"runs_on_protected_ref":                      gate != "none",
		"mr_pipelines_unprotected":                   !mBool(proj, "mr_pipelines_protected"),
		"runs_on_merged_result":                      mBool(proj, "merged_results_pipelines"),
		"consumes_cross_pipeline_artifact":           consumesCrossPipelineArtifact(job),
		"fetches_cross_project_artifact":             fetchesCrossProjectArtifact(job, scriptText),
		"dotenv_inheritance_unnarrowed":              dotenvInheritanceUnnarrowed(job),
		"artifact_source_ref_mutable":                artifactSourceRefMutable(job),
		"executes_fetched_artifact":                  executesFetchedArtifact(scriptText),
		"artifact_integrity_checked":                 artifactIntegrityChecked(scriptText),
		"dotenv_content_attacker_influenced":         dotenvContentAttackerInfluenced(job),
		"cache_policy_writes":                        cachePolicyWrites(job),
		"cache_key_static_cross_boundary":            cacheKeyStaticCrossBoundary(job),
		"cache_separation_enabled":                   mBool(proj, "cache_separation_enabled"),
		"artifacts_access_unrestricted":              artifactsAccessUnrestricted(job),
		"reuses_ondisk_checkout":                     reusesOnDiskCheckout(job, jc.globalVars),
		"downloads_secure_file":                      downloadsSecureFile(scriptText),
		"artifact_paths_broad":                       artifactPathsBroad(job),
		"installs_gitlab_registry_package":           installsRegistryPackage(scriptText),
		"environment_name_interpolated":              deploysEnv && environmentNameInterpolated(envName),
		"outbound_job_token_broad":                   jobTokenBroad(proj),
		"child_pipeline_from_cross_project_artifact": childPipelineFromCrossProjectArtifact(job, crossNeedJobs),
		"remote_step_untrusted_ref":                  remoteStepUntrustedRef(job),
		"cache_key_files_attacker_writable":          cacheKeyFilesAttackerWritable(job),
		"cache_paths_executable":                     cachePathsExecutable(job),
		"dotenv_content_from_untrusted_source":       dotenvContentFromUntrustedSource(job),
		"package_version_mutable_range":              packageVersionMutableRange(scriptText),
		"package_version_checksum_verified":          packageVersionChecksumVerified(scriptText),
		"_provenance":                                jobProvenance(p.FullPath),
	}

	// Runner reachability folds (cat-01/08): the project's runner posture drives
	// which runner class this job can land on.
	rec["targets_self_managed_runner"] = mBool(proj, "has_self_managed_runner")
	rec["targets_protected_runner"] = mBool(proj, "has_protected_self_managed_runner")

	// Secret / OIDC / Pages / Duo effective folds.
	rec["env_scoped_secret_reachable"] = deploysEnv && envScopedSecretReachable(proj, envName)
	rec["sub_claim_omits_ref"] = subClaimOmitsRef(proj)
	rec["non_member_readable_pipelines"] = nonMemberReadablePipelines(proj)
	rec["pages_public"] = isPagesJob(name, job) && mStr(proj, "pages_access_level") == "public"
	rec["pages_references_secret_variable"] = isPagesJob(name, job) && pagesReferencesSecret(job, proj)
	rec["source_ci_writable_by_lower_trust"] = sourceCIWritable(proj, gate)
	rec["developer_controls_mr_branches"] = mBool(proj, "developer_writable_protected_branch")
	rec["runs_on_cross_trust_shared_runner"] = mBool(proj, "has_self_managed_runner") && untrustedRef

	// Cross-project artifact consumer folds (cat-09): the producer-project trust
	// posture that gates the fetch is resolved by the cross-project-artifact join;
	// the literal fields the job carries are its own consumer-side signals plus a
	// conservative default for the source-side (join refines them).
	rec["on_consumer_job_token_allowlist"] = false
	rec["source_ref_developer_pushable"] = artifactSourceRefMutable(job)
	rec["artifact_source_visibility"] = nil
	rec["upstream_pipeline_untrusted_ref_reachable"] = consumesCrossPipelineArtifact(job)

	// Registry / package protection folds (cat-09): the covering-rule and
	// default-permission checks the join resolves against the source project;
	// carried on the job so the rule reads a literal. Absent covering rule / broad
	// default is the vulnerable state, so these default to the conservative value.
	rec["registry_tag_protection_covers_consumed_tag"] = registryTagCovers(proj)
	rec["registry_push_reachable_by_developer"] = mBool(proj, "developer_writable_protected_branch") || mBool(proj, "has_developer_pushable_unprotected_ref")
	rec["package_protection_covers_consumed_name"] = len(mList(proj, "registry_protection_rules")) > 0
	rec["package_publish_reachable_by_developer"] = mBool(proj, "has_developer_pushable_unprotected_ref")
	rec["write_registry_token_reachable_low_trust"] = writeRegistryTokenLowTrust(proj)

	// Consumer inheritance / collision folds (cat-09 dotenv variable shadowing).
	rec["inherited_var_in_exec_sink"] = inheritedVarInExecSink(job, scriptText, imgRef)
	declared := declaredVarKeys(job, jc.globalVars)
	collides, inSink := dotenvCollision(producers, name, job, declared, scriptText, imgRef)
	rec["dotenv_key_collides_declared_var"] = collides
	rec["colliding_var_in_exec_sink"] = inSink

	// Duo folds (cat-13): flow context/scope/autonomy + group/instance governance.
	duoFlow := isDuoFlow(job, jc)
	rec["is_duo_flow"] = duoFlow
	rec["duo_flow_context_sources"] = duoFlowContextSources(duoFlow, jc)
	rec["duo_flow_secrets_in_scope"] = duoFlow && duoFlowSecretsInScope(proj)
	rec["duo_flow_autonomous_write"] = duoFlow && duoFlowAutonomousWrite(jc.duoAgent)
	rec["duo_mcp_endpoint_untrusted_host"] = duoMCPUntrustedHost(jc)
	rec["duo_external_agent_untrusted_host"] = duoExternalAgentUntrustedHost(jc)
	rec["duo_group_features_enabled"] = mGet(jc.group, "duo_features_enabled")
	rec["duo_guardrail_level"] = mGet(jc.group, "prompt_injection_protection_level")
	rec["duo_instance_features_enabled"] = mGet(jc.instance, "duo_features_enabled")
	rec["duo_instance_guardrail_level"] = mGet(jc.instance, "prompt_injection_protection_level")
	rec["duo_workflow_mcp_enabled"] = mGet(jc.group, "duo_workflow_mcp_enabled")

	return rec
}

func jobID(project, name string) string { return project + ":" + name }
func jobProvenance(project string) []provenance {
	return []provenance{{"config_file": ".gitlab-ci.yml", "project_path": project}}
}

// toSet returns a stable, deduplicated slice for a set-typed field, always [] not
// nil (contract C1).
func toSet(items []string) []any {
	seen := map[string]bool{}
	out := []any{}
	for _, s := range items {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func strListOf(list []any) []string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// referencesAnyVariable reports whether the job references a $VAR or declares
// variables:, i.e. exposes ≥1 CI/CD variable to its script/env.
func referencesAnyVariable(scriptText string, job map[string]any) bool {
	if strings.Contains(scriptText, "$") {
		return true
	}
	return entMap(job["variables"]) != nil
}

// jobReadsProtectedVar reports a protected variable is reachable by the job: the
// project has a protected cicd_variable and the job references a variable.
func jobReadsProtectedVar(proj map[string]any, scriptText string, job map[string]any) bool {
	if !referencesAnyVariable(scriptText, job) {
		return false
	}
	for _, v := range mList(proj, "cicd_variables") {
		if mBool(entMap(v), "protected") {
			return true
		}
	}
	return false
}

func envScopedSecretReachable(proj map[string]any, envName string) bool {
	for _, raw := range mList(proj, "cicd_variables") {
		v := entMap(raw)
		if mBool(v, "protected") {
			continue
		}
		scope := mStr(v, "environment_scope")
		if scope == "*" || scope == "" || globMatch(scope, envName) || scope == envName {
			return true
		}
	}
	return false
}

func subClaimOmitsRef(proj map[string]any) bool {
	comps := strListOf(mList(entMap(mGet(proj, "oidc")), "sub_claim_components"))
	if len(comps) == 0 {
		return false // default includes ref
	}
	for _, c := range comps {
		if c == "ref" || c == "ref_type" {
			return false
		}
	}
	return true
}

func nonMemberReadablePipelines(proj map[string]any) bool {
	vis := mStr(proj, "visibility")
	return (vis == "public" || vis == "internal") && mBool(proj, "public_pipelines")
}

func pagesReferencesSecret(job, proj map[string]any) bool {
	refs := map[string]bool{}
	for k := range entMap(job["variables"]) {
		refs[k] = true
	}
	for _, s := range asStrList(entGetIn(job, "secrets")) {
		refs[s] = true
	}
	for _, raw := range mList(proj, "cicd_variables") {
		v := entMap(raw)
		if !mBool(v, "protected") && !mBool(v, "masked") {
			continue
		}
		if refs[mStr(v, "key")] {
			return true
		}
	}
	return false
}

// sourceCIWritable reports the executed CI config / ref is writable by a
// lower-trust member: the job is not gated to a protected ref and the project has
// a developer-pushable unprotected ref (or a developer-writable protected branch).
func sourceCIWritable(proj map[string]any, gate string) bool {
	if gate == "strong" {
		return false
	}
	return mBool(proj, "has_developer_pushable_unprotected_ref") || mBool(proj, "developer_writable_protected_branch")
}

func jobTokenBroad(proj map[string]any) bool {
	if !mBool(proj, "inbound_job_token_scope_enabled") {
		return true
	}
	allow := mMap(proj, "job_token_allowlist")
	return mStr(allow, "mode") == "open" || mStr(allow, "mode") == "disabled"
}

// isDuoFlow reports the job runs a Duo flow/agent in CI: the project has Duo
// config present (folded onto the project record) and the job wires it.
func isDuoFlow(job map[string]any, jc jobContext) bool {
	duo := mMap(jc.project, "duo")
	if !mBool(duo, "config_present") {
		return false
	}
	scriptText := jobScriptText(job)
	return strings.Contains(scriptText, "duo") || strings.Contains(scriptText, "glab duo") ||
		len(mList(duo, "flows")) > 0
}

func registryTagCovers(proj map[string]any) bool {
	for _, raw := range mList(proj, "registry_protection_rules") {
		if entStr(entMap(raw)["tag_name_pattern"]) != "" {
			return true
		}
	}
	return false
}

func writeRegistryTokenLowTrust(proj map[string]any) bool {
	return mBool(proj, "has_developer_reachable_secret")
}

// inheritedVarInExecSink: the consumer references any $VAR in an execution
// sink (image:, script command). Without dotenv/global-var provenance on disk the
// conservative literal is: a variable reaches a sink. The join narrows to the
// inherited-only case.
func inheritedVarInExecSink(job map[string]any, scriptText, imgRef string) bool {
	return imageFromVariable(imgRef) || reCmdSubst.MatchString(scriptText)
}

// declaredVarKeys returns the union of the job-level and global variables: keys.
func declaredVarKeys(job, globalVars map[string]any) map[string]bool {
	out := map[string]bool{}
	for k := range entMap(job["variables"]) {
		out[k] = true
	}
	for k := range globalVars {
		out[k] = true
	}
	return out
}

// dotenvCollision reports whether a reachable dotenv producer emits a key that
// collides with a variable the consumer declares, and whether that colliding key
// is used in an exec sink.
func dotenvCollision(producers map[string]bool, name string, job map[string]any, declared map[string]bool, scriptText, imgRef string) (bool, bool) {
	if len(declared) == 0 || !consumesDotenv(job, producers) {
		return false, false
	}
	// Producer dotenv keys are not resolvable from the entrypoint alone (producer
	// may be another project); a same-pipeline producer's keys collide when the
	// consumer declares a key the producer could emit. Conservatively: a collision
	// exists when the consumer declares a variable AND consumes dotenv.
	collides := true
	inSink := false
	for k := range declared {
		if strings.Contains(scriptText, "$"+k) || strings.Contains(scriptText, "${"+k+"}") || strings.Contains(imgRef, "$"+k) {
			inSink = true
			break
		}
	}
	return collides, inSink
}

// ---- Duo flow signals (cat-13) ----

func duoFlowContextSources(duoFlow bool, jc jobContext) []any {
	out := []any{}
	if !duoFlow {
		return out
	}
	vis := mStr(jc.project, "visibility")
	if vis == "public" || vis == "internal" || mBool(jc.project, "forking_enabled") {
		out = append(out, "fork_mr")
	}
	out = append(out, "issue_comment")
	return out
}

func duoFlowSecretsInScope(proj map[string]any) bool {
	for _, raw := range mList(proj, "cicd_variables") {
		if !mBool(entMap(raw), "protected") {
			return true
		}
	}
	return false
}

var reDuoWriteAction = regexp.MustCompile(`(?i)post_comment|create_merge_request|push|call_api|write|commit`)

func duoFlowAutonomousWrite(agentCfg []byte) bool {
	if agentCfg == nil {
		return false
	}
	s := string(agentCfg)
	if !reDuoWriteAction.MatchString(s) {
		return false
	}
	return !strings.Contains(strings.ToLower(s), "approval") && !strings.Contains(strings.ToLower(s), "human")
}

func duoMCPUntrustedHost(jc jobContext) bool {
	endpoint := entStr(mGet(mMap(jc.project, "duo"), "mcp_endpoint"))
	if endpoint == "" {
		return false
	}
	host := hostOf(endpoint)
	return host != "" && host != jc.selfHost && !strings.HasSuffix(host, "."+jc.namespace)
}

var reAgentEndpoint = regexp.MustCompile(`(?i)endpoint\s*:\s*["']?(https?://[^\s"']+)`)

func duoExternalAgentUntrustedHost(jc jobContext) bool {
	for _, m := range reAgentEndpoint.FindAllStringSubmatch(string(jc.duoAgent), -1) {
		host := hostOf(m[1])
		if host != "" && host != jc.selfHost {
			return true
		}
	}
	return false
}
