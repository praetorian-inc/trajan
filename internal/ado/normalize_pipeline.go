package ado

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v4"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// Task-input keys whose value is a service-connection reference, which is what makes
// a step a structural USES_CONNECTION signal.
var scInputNames = []string{
	"azureSubscription", "connectedServiceName", "connectedServiceNameARM", "ConnectedServiceName",
	"connectedServiceNameAzureRM", "azureSubscriptionEndpoint", "azureResourceManagerConnection",
	"containerRegistry", "dockerRegistryServiceConnection", "azureContainerRegistry",
	"kubernetesServiceConnection", "awsCredentials", "serviceConnection", "externalEndpoint", "externalEndpoints",
}

const checkoutTaskID = "6d15af64-176c-496d-b583-fd2ae21d4df4"

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func normalizePipelines(ctx context.Context, prior engine.PriorPhase, cp engine.CurrentPhase, timer *engine.PhaseTimer) error {
	files, err := prior.IterJSON("00-collect/build-definition")
	if err != nil {
		return err
	}
	settingsCache := map[string]map[string]any{}
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		def := entDataOf(f.Data)
		if def == nil {
			continue
		}
		project := entStr(entGetIn(def, "project", "name"))
		id := entInt64(def["id"])
		if project == "" || id == 0 {
			timer.Errors = append(timer.Errors, fmt.Sprintf("pipeline %s: missing project/id", f.Rel))
			continue
		}
		process := entObj(def, "process")
		processType := entInt64(process["type"]) // 2=YAML, 1=classic/designer
		repo := entObj(def, "repository")

		gs, ok := settingsCache[project]
		if !ok {
			gs = settingsView(generalSettings(prior, project))
			settingsCache[project] = gs
		}
		requested := entStr(def["jobAuthorizationScope"])
		effective, identityScope, provenance := clampScope(requested, mBool(gs, "limit_job_auth_scope_to_current_project"), mBool(gs, "settings_observed"))
		// The project-effective posture flags are copied onto the pipeline node so a
		// pipeline-subject rule reaches them without a project join.
		enableShellSanitize := mBool(gs, "enable_shell_tasks_args_sanitizing")
		enforceSettableVar := mBool(gs, "enforce_settable_var")

		pipe := map[string]any{
			"_id":                     fmt.Sprintf("%s/%d", project, id),
			"kind":                    "Pipeline",
			"project":                 project,
			"id":                      id,
			"name":                    entStr(def["name"]),
			"yaml_path":               entStr(process["yamlFilename"]),
			"settings_source_type":    sourceType(processType),
			"queue_status":            entStr(def["queueStatus"]),
			"job_authorization_scope": requested,
			"effective_scope":         effective,
			"identity_scope":          identityScope,
			"enforce_provenance":      provenance,
			"repository": map[string]any{
				"id":             entStr(repo["id"]),
				"name":           entStr(repo["name"]),
				"type":           entStr(repo["type"]),
				"default_branch": entStr(repo["defaultBranch"]),
			},
			"triggers":    entListOrEmpty(def["triggers"]),
			"variables":   normalizePipelineVars(entObj(def, "variables")),
			"_provenance": prov(engine.CollectADOBuildDefFull(project, id)),
		}

		settable := settableVarSet(entObj(def, "variables"))
		facts, jobs := pipelineYAMLFacts{}, 0
		if processType == 2 && strings.EqualFold(entStr(repo["type"]), "TfsGit") {
			content := entryYAML(prior, project, id, repo, entStr(process["yamlFilename"]))
			if content != "" {
				facts, jobs, err = parsePipelineYAML(cp, timer, project, id, content, settable)
				if err != nil {
					return err
				}
			}
		}
		if jobs == 0 {
			if err := expandFromPreview(prior, cp, timer, project, id, settable); err != nil {
				return err
			}
		}
		pipe["extends_template"] = strOrNull(facts.extendsTemplate)
		pipe["extends_source"] = facts.extendsSource // resolved template source repo/ref (nil if none)
		pipe["template_sources"] = entListOrEmpty(facts.templateSources)
		pipe["variable_groups"] = toAnyList(facts.variableGroups) // pipeline-level declarations
		pipe["parameters"] = entListOrEmpty(facts.parameters)     // runtime params (freeform = cat-02 surface)
		pipe["ci_trigger"] = facts.ciTrigger                      // nil=implicit, "none"=disabled, else filter
		pipe["pr_trigger"] = facts.prTrigger
		pipe["enable_shell_tasks_args_sanitizing"] = enableShellSanitize
		pipe["enforce_settable_var"] = enforceSettableVar
		pipe["settings_observed"] = mBool(gs, "settings_observed")
		// The YAML restriction (nil = all overridable, [] = none) and the per-definition
		// allowOverride names are separate gates: the latter is the settable surface once
		// the org/project limit is enforced.
		pipe["settable_variables"] = facts.settableVariables
		pipe["definition_settable_variables"] = sortedSet(settable)

		if err := emit(cp, timer, engine.NormalizeADOPipeline(project, id), pipe); err != nil {
			return err
		}
	}
	return nil
}

func sourceType(t int64) string {
	if t == 1 {
		return "designer"
	}
	return "yaml"
}

func strOrNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ADO omits allowOverride when it is false, so an absent key means not overridable.
func normalizePipelineVars(vars map[string]any) []any {
	out := []any{}
	for _, name := range sortedKeys(vars) {
		vm := entMap(vars[name])
		out = append(out, map[string]any{
			"name":           name,
			"is_secret":      entBool(vm["isSecret"]),
			"allow_override": entBool(vm["allowOverride"]),
		})
	}
	return out
}

// Rebuilds the repoID@branch__yamlFilename stem the collector wrote, returning ""
// when that file is absent.
func entryYAML(prior engine.PriorPhase, project string, id int64, repo map[string]any, yamlFilename string) string {
	repoID := entStr(repo["id"])
	branch := stripRef(entStr(repo["defaultBranch"]))
	if branch == "" {
		branch = "main"
	}
	name := fmt.Sprintf("%s@%s__%s", repoID, branch, yamlFilename)
	d := entLoadData(prior, engine.CollectADOPipelineYAML(project, id, name))
	return entStr(d["content"])
}

// The root-level facts a caller stamps onto the :Pipeline node. A nil trigger is
// absent or implicit; "none" is explicitly off.
type pipelineYAMLFacts struct {
	extendsTemplate   string
	extendsSource     map[string]any // resolved source repo/ref of the extends template
	templateSources   []any          // all resources.repositories, resolved (cat-08 surface)
	variableGroups    []string
	parameters        []any // runtime parameters (queue-time settable; freeform = injectable)
	ciTrigger         any
	prTrigger         any
	settableVariables any // YAML root `settableVariables:` (nil = all overridable, [] = none)
}

// A string, number or object parameter with no `values:` allowlist is freeform, which
// makes it the queue-time-settable injection surface.
func normalizeParameters(v any) []any {
	out := []any{}
	list, ok := v.([]any)
	if !ok {
		return out
	}
	for _, raw := range list {
		pm, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name := yamlStr(pm["name"])
		if name == "" {
			continue
		}
		ptype := yamlStr(pm["type"])
		if ptype == "" {
			ptype = "string" // ADO defaults an untyped parameter to string
		}
		values, _ := pm["values"].([]any)
		hasAllowlist := len(values) > 0
		freeform := !hasAllowlist && (ptype == "string" || ptype == "object" || ptype == "number")
		out = append(out, map[string]any{
			"name":                 name,
			"type":                 ptype,
			"default":              pm["default"],
			"values":               entListOrEmpty(pm["values"]),
			"has_values_allowlist": hasAllowlist,
			"is_freeform":          freeform,
		})
	}
	return out
}

// Cross-project and unpinned sources are the writable-template surface, so both are
// flagged. An empty ref means the source floats on its default branch and is mutable.
func resolveTemplateSources(root map[string]any, pipelineProject string) (list []any, byAlias map[string]map[string]any) {
	list, byAlias = []any{}, map[string]map[string]any{}
	repos, ok := entGetIn(root, "resources", "repositories").([]any)
	if !ok {
		return list, byAlias
	}
	for _, raw := range repos {
		rm, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		alias := yamlStr(rm["repository"])
		name := yamlStr(rm["name"])
		ref := yamlStr(rm["ref"])
		rtype := yamlStr(rm["type"])
		srcProject, repoName := splitRepoName(name, pipelineProject)
		entry := map[string]any{
			"alias": alias, "name": name, "type": rtype,
			"source_project": srcProject, "repository": repoName,
			"ref": ref, "ref_pinned": ref != "",
			"is_cross_project": rtype == "git" && srcProject != "" && srcProject != pipelineProject,
			"endpoint":         yamlStr(rm["endpoint"]),
		}
		list = append(list, entry)
		if alias != "" {
			byAlias[alias] = entry
		}
	}
	return list, byAlias
}

// A bare "Repo" names a repo in the pipeline's own project; "Project/Repo" does not.
func splitRepoName(name, dfltProject string) (project, repo string) {
	if i := strings.IndexByte(name, '/'); i >= 0 {
		return name[:i], name[i+1:]
	}
	return dfltProject, name
}

// Variable groups are deliberately not merged down levels: each of Pipeline, Stage
// and Job carries only what it declares, which is what makes the CONSUMES_GROUP level
// recoverable later.
func parsePipelineYAML(cp engine.CurrentPhase, timer *engine.PhaseTimer, project string, pipelineID int64, content string, settable map[string]bool) (pipelineYAMLFacts, int, error) {
	var root map[string]any
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		timer.Errors = append(timer.Errors, fmt.Sprintf("pipeline %s/%d: yaml parse: %v", project, pipelineID, err))
		return pipelineYAMLFacts{}, 0, nil // a bad YAML doc is per-item non-fatal
	}
	facts := pipelineYAMLFacts{
		variableGroups:    variableGroups(root["variables"]),
		parameters:        normalizeParameters(root["parameters"]),
		ciTrigger:         root["trigger"],
		prTrigger:         root["pr"],
		settableVariables: settableVariablesOf(root["variables"]),
	}
	if err := emitPipelineResources(cp, timer, project, pipelineID, root); err != nil {
		return facts, 0, err
	}

	tsList, tsByAlias := resolveTemplateSources(root, project)
	facts.templateSources = tsList
	switch ext := root["extends"].(type) {
	case map[string]any:
		facts.extendsTemplate = yamlStr(ext["template"])
	case string:
		facts.extendsTemplate = ext
	}
	if facts.extendsTemplate != "" {
		if alias := splitTemplateRef(facts.extendsTemplate).alias; alias != "" {
			facts.extendsSource = tsByAlias[alias]
		}
	}
	if root["extends"] != nil {
		return facts, 0, nil // the jobs live in the template, recovered from the preview
	}
	n, err := emitStagesAndJobs(cp, timer, project, pipelineID, root, settable, engine.CollectADOBuildDefFull(project, pipelineID))
	return facts, n, err
}

func expandFromPreview(prior engine.PriorPhase, cp engine.CurrentPhase, timer *engine.PhaseTimer, project string, pipelineID int64, settable map[string]bool) error {
	rel := engine.CollectADOPipelinePreview(project, pipelineID)
	content := entStr(entLoadData(prior, rel)["finalYaml"])
	if content == "" {
		return nil
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		timer.Errors = append(timer.Errors, fmt.Sprintf("pipeline %s/%d: preview yaml parse: %v", project, pipelineID, err))
		return nil
	}
	_, err := emitStagesAndJobs(cp, timer, project, pipelineID, root, settable, rel)
	return err
}

func emitStagesAndJobs(cp engine.CurrentPhase, timer *engine.PhaseTimer, project string, pipelineID int64, root map[string]any, settable map[string]bool, provFile string) (int, error) {
	pipelinePool := root["pool"]
	if stages, ok := root["stages"].([]any); ok {
		n := 0
		for i, s := range stages {
			sm, ok := s.(map[string]any)
			if !ok {
				continue
			}
			if sm["template"] != nil && sm["stage"] == nil {
				continue
			}
			stageName := firstStr(sm, "stage", fmt.Sprintf("stage_%d", i))
			c, err := emitStageJobs(cp, timer, project, pipelineID, stageName, sm, pipelinePool, settable, provFile)
			if err != nil {
				return n, err
			}
			n += c
		}
		return n, nil
	}
	// With no stages the root plays pipeline, stage and job at once. Its variable groups
	// are already stamped on the Pipeline node, so they are stripped before the same map
	// stands in for the Stage/Job — otherwise one declaration is counted at every level
	// and CONSUMES_GROUP is emitted three times.
	delete(root, "variables")
	return emitStageJobs(cp, timer, project, pipelineID, "__default", root, pipelinePool, settable, provFile)
}

// A resources.pipelines entry is a pipeline-completion trigger, which is the
// trigger-laundering surface.
func emitPipelineResources(cp engine.CurrentPhase, timer *engine.PhaseTimer, project string, pipelineID int64, root map[string]any) error {
	pipes, ok := entGetIn(root, "resources", "pipelines").([]any)
	if !ok {
		return nil
	}
	for i, raw := range pipes {
		rm, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		alias := yamlStr(rm["pipeline"])
		rec := map[string]any{
			"kind": "TRIGGERS_ON_COMPLETION", "project": project, "pipeline_id": pipelineID,
			"alias": alias, "source_pipeline": yamlStr(rm["source"]), "source_project": yamlStr(rm["project"]),
			"trigger": rm["trigger"], "branches": rm["branches"], "tags": rm["tags"], "stages": rm["stages"],
		}
		key := fmt.Sprintf("%s__%d__%s", adoSafe(project), pipelineID, adoSafe(firstStr(rm, "pipeline", fmt.Sprintf("res_%d", i))))
		if err := emitEdge(cp, timer, "triggers-on-completion", key, rec); err != nil {
			return err
		}
	}
	return nil
}

func emitStageJobs(cp engine.CurrentPhase, timer *engine.PhaseTimer, project string, pipelineID int64, stage string, m map[string]any, inheritedPool any, settable map[string]bool, provFile string) (int, error) {
	stagePool := m["pool"]
	if stagePool == nil {
		stagePool = inheritedPool
	}

	stageRec := map[string]any{
		"_id":             fmt.Sprintf("%d/%s", pipelineID, stage),
		"kind":            "Stage",
		"project":         project,
		"pipeline_id":     pipelineID,
		"stage":           stage,
		"condition":       yamlStr(m["condition"]),
		"depends_on":      stringsOf(m["dependsOn"]),
		"variable_groups": toAnyList(variableGroups(m["variables"])), // stage-level declarations only
		"environment":     strOrNull(yamlStr(m["environment"])),      // stage-level env (deployment stages carry it on jobs)
		"_provenance":     prov(provFile),
	}
	if err := emit(cp, timer, engine.NormalizeADOStage(project, pipelineID, stage), stageRec); err != nil {
		return 0, err
	}

	jobs, ok := m["jobs"].([]any)
	if !ok {
		if err := emitJob(cp, timer, project, pipelineID, stage, "__default", m, stagePool, settable, provFile); err != nil {
			return 0, err
		}
		return 1, nil
	}
	n := 0
	for i, j := range jobs {
		jm, ok := j.(map[string]any)
		if !ok {
			continue
		}
		if jm["template"] != nil && jm["job"] == nil && jm["deployment"] == nil {
			continue
		}
		jobName := firstStr(jm, "job", firstStr(jm, "deployment", fmt.Sprintf("job_%d", i)))
		if err := emitJob(cp, timer, project, pipelineID, stage, jobName, jm, stagePool, settable, provFile); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func emitJob(cp engine.CurrentPhase, timer *engine.PhaseTimer, project string, pipelineID int64, stage, job string, m map[string]any, inheritedPool any, settable map[string]bool, provFile string) error {
	jobPool := m["pool"]
	if jobPool == nil {
		jobPool = inheritedPool
	}
	// A per-job settableVariables list widens the queue-time-settable surface that
	// annotates is_declared_settable on this job's macro sinks.
	if extra := settableVariablesOf(m["variables"]); extra != nil {
		settable = mergeSettable(settable, extra)
	}

	f := walkSteps(collectSteps(m), settable)
	// A parameter or runtime expression selecting pool or container steers the execution
	// target and identity, so both are compile-keyword sinks.
	scanCompileKeyword(&f, "pool", poolExpr(jobPool), -1, "", settable)
	scanCompileKeyword(&f, "container", yamlStr(m["container"]), -1, "", settable)

	rec := map[string]any{
		"_id":                         fmt.Sprintf("%d/%s/%s", pipelineID, stage, job),
		"kind":                        "Job",
		"project":                     project,
		"pipeline_id":                 pipelineID,
		"stage":                       stage,
		"job":                         job,
		"is_deployment":               m["deployment"] != nil,
		"condition":                   yamlStr(m["condition"]),
		"depends_on":                  stringsOf(m["dependsOn"]),
		"pool":                        normalizePool(jobPool),
		"variable_groups":             toAnyList(variableGroups(m["variables"])), // job-level declarations only
		"targets_environment":         strOrNull(jobEnvironment(m)),
		"service_connection_usages":   f.scUsages,
		"checkout_steps":              f.checkouts,
		"task_usages":                 f.taskUsages,
		"script_bodies":               f.scriptBodies,
		"macro_sinks":                 f.macroSinks,
		"parameter_sinks":             f.paramSinks,
		"vso_echo_sources":            f.vsoEchoSources,
		"ai_task_sinks":               f.aiTaskSinks,
		"variable_consumers":          f.varConsumers,
		"bare_binary_calls":           f.bareBinaries,
		"cred_writes":                 f.credWrites,
		"exec_sinks":                  f.execSinks,
		"executes_checked_out_code":   f.executesCheckedOutCode,
		"exposes_system_access_token": f.referencesAccessToken,
		"_provenance":                 prov(provFile),
	}
	return emit(cp, timer, engine.NormalizeADOJob(project, pipelineID, stage, job), rec)
}

// A deployment job nests steps under every lifecycle hook, not just deploy, and
// preDeploy/routeTraffic/postRouteTraffic and on.failure/on.success can each consume a
// connection or run a task, so all hooks are gathered in execution order.
func collectSteps(m map[string]any) []any {
	if s, ok := m["steps"].([]any); ok {
		return s
	}
	var out []any
	strategy := entMap(m["strategy"])
	for _, kind := range []string{"runOnce", "rolling", "canary"} {
		phase := entMap(strategy[kind])
		for _, hook := range []string{"preDeploy", "deploy", "routeTraffic", "postRouteTraffic"} {
			if s, ok := entMap(phase[hook])["steps"].([]any); ok {
				out = append(out, s...)
			}
		}
		on := entMap(phase["on"])
		for _, hook := range []string{"failure", "success"} {
			if s, ok := entMap(on[hook])["steps"].([]any); ok {
				out = append(out, s...)
			}
		}
	}
	return out
}

// The step facts collapsed onto a :Job: structural usages plus the sinks and sources
// the derived attack edges key on. Every slice stays non-nil so an empty one
// serializes as [] and a rule can still match it.
type jobFacts struct {
	scUsages               []any
	checkouts              []any
	taskUsages             []any
	scriptBodies           []any
	macroSinks             []any
	paramSinks             []any
	vsoEchoSources         []any
	aiTaskSinks            []any
	varConsumers           []any
	bareBinaries           []any
	credWrites             []any
	execSinks              []any
	executesCheckedOutCode bool
	referencesAccessToken  bool
}

func newJobFacts() jobFacts {
	return jobFacts{
		scUsages: []any{}, checkouts: []any{}, taskUsages: []any{}, scriptBodies: []any{},
		macroSinks: []any{}, paramSinks: []any{}, vsoEchoSources: []any{}, aiTaskSinks: []any{},
		varConsumers: []any{}, bareBinaries: []any{}, credWrites: []any{}, execSinks: []any{},
	}
}

func walkSteps(steps []any, settable map[string]bool) jobFacts {
	f := newJobFacts()
	for i, s := range steps {
		sm, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if strings.HasPrefix(yamlStr(sm["task"]), checkoutTaskID) {
			in := entMap(sm["inputs"])
			sm = map[string]any{
				"checkout": in["repository"], "clean": in["clean"], "fetchDepth": in["fetchDepth"],
				"persistCredentials": in["persistCredentials"], "submodules": in["submodules"],
			}
		}
		if ck, ok := sm["checkout"]; ok {
			f.checkouts = append(f.checkouts, map[string]any{
				"repository": yamlStr(ck), "clean": sm["clean"], "fetch_depth": sm["fetchDepth"],
				"persist_credentials": sm["persistCredentials"], "submodules": sm["submodules"], "step_index": i,
			})
			scanCompileKeyword(&f, "checkout", yamlStr(ck), i, "", settable)
			continue
		}
		if cond := yamlStr(sm["condition"]); cond != "" {
			for _, name := range conditionVars(cond) {
				f.varConsumers = append(f.varConsumers, map[string]any{"name": name, "step_index": i, "via": "condition"})
			}
		}
		f.scanEnv(entMap(sm["env"]))

		matched := false
		for _, key := range []string{"script", "bash", "powershell", "pwsh"} {
			if body := yamlStr(sm[key]); body != "" {
				f.scanScriptBody(shorthandShells[key], body, i, "", settable)
				matched = true
			}
		}
		if matched {
			continue
		}
		task := yamlStr(sm["task"])
		if task == "" {
			continue
		}
		inputs := entMap(sm["inputs"])
		f.taskUsages = append(f.taskUsages, taskUsageRec(task, i))
		for _, inputName := range scInputNames {
			if conn := yamlStr(inputs[inputName]); conn != "" {
				f.scUsages = append(f.scUsages, map[string]any{
					"task": task, "input_name": inputName, "connection_name": conn, "step_index": i,
				})
			}
		}
		if file, ok := credWritingTasks[task]; ok {
			f.credWrites = append(f.credWrites, map[string]any{"task": task, "step_index": i, "file": file})
		}
		if matchesAITask(task) {
			f.aiTaskSinks = append(f.aiTaskSinks, aiTaskRec(task, inputs, i))
		}
		et, isExecutor := executorTasks[task]
		if isExecutor {
			for _, in := range et.scriptInputs {
				if body := yamlStr(inputs[in]); body != "" {
					f.scanScriptBody(et.shell, body, i, task, settable)
				}
			}
			for _, in := range et.argInputs {
				if arg := yamlStr(inputs[in]); arg != "" {
					f.scanArgs(arg, i, task, settable)
				}
			}
		}
		for _, in := range sortedKeys(inputs) {
			if isExecutor && (slices.Contains(et.scriptInputs, in) || slices.Contains(et.argInputs, in)) {
				continue
			}
			if val := yamlStr(inputs[in]); val != "" {
				f.scanTaskInput(val, in, i, task, settable)
			}
		}
	}
	return f
}

func (f *jobFacts) scanScriptBody(shell, body string, stepIdx int, task string, settable map[string]bool) {
	f.scriptBodies = append(f.scriptBodies, map[string]any{"content": body, "shell": shell, "step_index": stepIdx})
	for _, name := range macroNames(body) {
		if macroKind(name) == "system" {
			continue
		}
		f.macroSinks = append(f.macroSinks, macroSinkRec(name, "script", task, stepIdx, settable))
		f.varConsumers = append(f.varConsumers, map[string]any{"name": name, "step_index": stepIdx, "via": "macro"})
	}
	for _, p := range paramNames(body) {
		f.paramSinks = append(f.paramSinks, paramSinkRec(p, "script", "", task, stepIdx))
	}
	if name, isExec := classifyExecSink(body); isExec {
		f.execSinks = append(f.execSinks, map[string]any{"name": name, "step_index": stepIdx})
		f.executesCheckedOutCode = true
	}
	for _, bin := range bareBinaryCalls(body) {
		f.bareBinaries = append(f.bareBinaries, map[string]any{"bin": bin, "step_index": stepIdx})
	}
	if matchesAICLI(body) {
		f.aiTaskSinks = append(f.aiTaskSinks, map[string]any{
			"task_id": "cli", "vendor": aiVendor(body), "capabilities": aiCapabilities(body),
			"inputs": map[string]any{}, "source": "script", "step_index": stepIdx,
			"generated_script": writesGeneratedScript(body),
		})
	}
	if strings.Contains(strings.ToLower(body), "system.accesstoken") {
		f.referencesAccessToken = true
	}
	if src, ok := untrustedEcho(body); ok {
		f.vsoEchoSources = append(f.vsoEchoSources, map[string]any{
			"untrusted_source": src, "echo_mechanism": echoMechanism(shell), "step_index": stepIdx,
			"has_literal_vso": reVsoLit.MatchString(body),
		})
	}
}

func (f *jobFacts) scanArgs(arg string, stepIdx int, task string, settable map[string]bool) {
	for _, name := range macroNames(arg) {
		if macroKind(name) == "system" {
			continue
		}
		f.macroSinks = append(f.macroSinks, macroSinkRec(name, "task_input", task, stepIdx, settable))
		f.varConsumers = append(f.varConsumers, map[string]any{"name": name, "step_index": stepIdx, "via": "macro"})
	}
	for _, p := range paramNames(arg) {
		f.paramSinks = append(f.paramSinks, paramSinkRec(p, "task_input", "arguments", task, stepIdx))
	}
}

func (f *jobFacts) scanTaskInput(val, inputName string, stepIdx int, task string, settable map[string]bool) {
	for _, name := range macroNames(val) {
		if macroKind(name) == "system" {
			continue
		}
		f.macroSinks = append(f.macroSinks, macroSinkRec(name, "task_input", task, stepIdx, settable))
	}
	if isCompileKeywordInput(inputName) { // input selects the identity/target (input_target_redirect)
		for _, p := range parameterRefs(val) {
			f.paramSinks = append(f.paramSinks, paramSinkRec(p, "compile_keyword", inputName, task, stepIdx))
		}
		for _, name := range runtimeVarRefs(val) {
			f.paramSinks = append(f.paramSinks, settableVarKeywordSink(name, inputName, task, stepIdx, settable))
		}
		return
	}
	for _, p := range paramNames(val) {
		f.paramSinks = append(f.paramSinks, paramSinkRec(p, "task_input", inputName, task, stepIdx))
	}
}

func (f *jobFacts) scanEnv(env map[string]any) {
	for _, k := range sortedKeys(env) {
		if strings.Contains(strings.ToLower(yamlStr(env[k])), "system.accesstoken") {
			f.referencesAccessToken = true
		}
	}
}

// `$(macro)` does not expand in a compile keyword, so only ${{ }} / $[ ] and
// predefined-untrusted references count. A ${{ parameters }} selector is always
// queue-settable; a $[ variables ] runtime expression is gated on settability.
func scanCompileKeyword(f *jobFacts, keyword, val string, stepIdx int, task string, settable map[string]bool) {
	if val == "" {
		return
	}
	for _, p := range parameterRefs(val) {
		f.paramSinks = append(f.paramSinks, paramSinkRec(p, "compile_keyword", keyword, task, stepIdx))
	}
	for _, name := range runtimeVarRefs(val) {
		f.paramSinks = append(f.paramSinks, settableVarKeywordSink(name, keyword, task, stepIdx, settable))
	}
}

func normalizePool(v any) map[string]any {
	switch p := v.(type) {
	case string:
		return map[string]any{"name": p}
	case map[string]any:
		return map[string]any{
			"name":     yamlStr(p["name"]),
			"vm_image": yamlStr(p["vmImage"]),
			"demands":  entListOrEmpty(p["demands"]),
		}
	}
	return map[string]any{}
}

func variableGroups(v any) []string {
	var out []string
	list, ok := v.([]any)
	if !ok {
		return out
	}
	for _, e := range list {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if g := yamlStr(em["group"]); g != "" {
			out = append(out, g)
		}
	}
	return out
}

func jobEnvironment(m map[string]any) string {
	switch e := m["environment"].(type) {
	case string:
		return e
	case map[string]any:
		return yamlStr(e["name"])
	}
	return ""
}

func yamlStr(v any) string {
	s, _ := v.(string)
	return s
}

func firstStr(m map[string]any, key, dflt string) string {
	if s := yamlStr(m[key]); s != "" {
		return s
	}
	return dflt
}

func stringsOf(v any) []any {
	switch x := v.(type) {
	case string:
		return []any{x}
	case []any:
		return x
	}
	return []any{}
}

func toAnyList(ss []string) []any {
	out := make([]any, 0, len(ss))
	for _, s := range ss {
		out = append(out, s)
	}
	return out
}

func adoSafe(s string) string {
	return strings.NewReplacer("/", "-", " ", "-").Replace(s)
}
