package ado

import (
	"context"
	"fmt"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v4"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// scInputNames is the registry of task-input keys whose value is a service
// connection reference (a structural USES_CONNECTION signal).
var scInputNames = []string{
	"azureSubscription", "connectedServiceName", "connectedServiceNameARM", "ConnectedServiceName",
	"connectedServiceNameAzureRM", "azureSubscriptionEndpoint", "azureResourceManagerConnection",
	"containerRegistry", "dockerRegistryServiceConnection", "azureContainerRegistry",
	"kubernetesServiceConnection", "awsCredentials", "serviceConnection", "externalEndpoint", "externalEndpoints",
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// normalizePipelines builds a Pipeline node per build definition and, for YAML
// pipelines, parses the entry YAML into Stage/Job records carrying the
// structural facts (service-connection usages, checkout, task refs, variable
// groups, environment targets, pool). Taint facts (macro/echo/script/ai sinks)
// are a later pass.
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
		// Project the project-effective posture flags a pipeline-subject rule needs
		// directly onto the node so it is reachable without a project join (cat-02).
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
			// schema §: the resolved Build Service identity scope lives on the node
			"effective_scope":    effective,
			"identity_scope":     identityScope,
			"enforce_provenance": provenance,
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

		facts := pipelineYAMLFacts{}
		if processType == 2 && strings.EqualFold(entStr(repo["type"]), "TfsGit") {
			content := entryYAML(prior, project, id, repo, entStr(process["yamlFilename"]))
			if content != "" {
				facts, err = parsePipelineYAML(cp, timer, project, id, content)
				if err != nil {
					return err
				}
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

// normalizePipelineVars projects definition variables; allowOverride absent =>
// false (ADO omits it when false).
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

// entryYAML reconstructs the entry-YAML filename the collector wrote (repoID@
// branch__yamlFilename) and returns its content, or "" if absent.
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

// pipelineYAMLFacts are the root-level facts a caller stamps onto the :Pipeline
// node: the extends-template reference, the pipeline-level variable groups, and
// the CI/PR trigger declarations (nil = absent/implicit; "none" = explicitly off).
type pipelineYAMLFacts struct {
	extendsTemplate string
	extendsSource   map[string]any // resolved source repo/ref of the extends template
	templateSources []any          // all resources.repositories, resolved (cat-08 surface)
	variableGroups  []string
	parameters      []any // runtime parameters (queue-time settable; freeform = injectable)
	ciTrigger       any
	prTrigger       any
}

// normalizeParameters projects the YAML root `parameters:` declarations. A
// string/number/object parameter with no `values:` allowlist is freeform — the
// queue-time-settable injection surface (cat-02).
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

// resolveTemplateSources parses resources.repositories into resolved external
// template-source refs, flagging cross-project and default-branch (unpinned)
// sources — the writable/poisoned-template surface (cat-08). An empty ref means
// the source floats on its default branch (mutable).
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

// splitRepoName splits an Azure Repos "Project/Repo" name into its parts; a bare
// "Repo" is same-project (the pipeline's project).
func splitRepoName(name, dfltProject string) (project, repo string) {
	if i := strings.IndexByte(name, '/'); i >= 0 {
		return name[:i], name[i+1:]
	}
	return dfltProject, name
}

// parsePipelineYAML walks the entry pipeline, emits Stage/Job nodes + the
// TRIGGERS_ON_COMPLETION edges, and returns the root-level facts. Variable groups
// are NOT merged down levels — each of Pipeline/Stage/Job carries only what it
// declares, so the CONSUMES_GROUP level (schema) is recoverable.
func parsePipelineYAML(cp engine.CurrentPhase, timer *engine.PhaseTimer, project string, pipelineID int64, content string) (pipelineYAMLFacts, error) {
	var root map[string]any
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		timer.Errors = append(timer.Errors, fmt.Sprintf("pipeline %s/%d: yaml parse: %v", project, pipelineID, err))
		return pipelineYAMLFacts{}, nil // a bad YAML doc is per-item non-fatal
	}
	facts := pipelineYAMLFacts{
		variableGroups: variableGroups(root["variables"]),
		parameters:     normalizeParameters(root["parameters"]),
		ciTrigger:      root["trigger"],
		prTrigger:      root["pr"],
	}
	if err := emitPipelineResources(cp, timer, project, pipelineID, root); err != nil {
		return facts, err
	}
	pipelinePool := root["pool"]

	tsList, tsByAlias := resolveTemplateSources(root, project)
	facts.templateSources = tsList
	switch ext := root["extends"].(type) {
	case map[string]any:
		facts.extendsTemplate = yamlStr(ext["template"]) // jobs live in the template (deferred pass)
	case string:
		facts.extendsTemplate = ext
	}
	if facts.extendsTemplate != "" {
		if alias := splitTemplateRef(facts.extendsTemplate).alias; alias != "" {
			facts.extendsSource = tsByAlias[alias]
		}
	}
	if root["extends"] != nil {
		return facts, nil // jobs live in the template (deferred pass)
	}

	if stages, ok := root["stages"].([]any); ok {
		for i, s := range stages {
			sm, ok := s.(map[string]any)
			if !ok {
				continue
			}
			stageName := firstStr(sm, "stage", fmt.Sprintf("stage_%d", i))
			if err := emitStageJobs(cp, timer, project, pipelineID, stageName, sm, pipelinePool); err != nil {
				return facts, err
			}
		}
		return facts, nil
	}
	// implicit single stage: root plays pipeline+stage+job. The pipeline-level
	// groups are stamped on the Pipeline node by the caller; the Stage/Job here
	// carry only their own (here: none extra), so no level is double-counted.
	return facts, emitStageJobs(cp, timer, project, pipelineID, "__default", root, pipelinePool)
}

// emitPipelineResources emits a TRIGGERS_ON_COMPLETION edge per resources.pipelines
// entry (a pipeline-completion trigger — the trigger-laundering surface, cat-11).
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
		if err := emit(cp, timer, engine.NormalizeADOEdges("triggers-on-completion", key), rec); err != nil {
			return err
		}
	}
	return nil
}

func emitStageJobs(cp engine.CurrentPhase, timer *engine.PhaseTimer, project string, pipelineID int64, stage string, m map[string]any, inheritedPool any) error {
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
		"_provenance":     prov(engine.CollectADOBuildDefFull(project, pipelineID)),
	}
	if err := emit(cp, timer, engine.NormalizeADOStage(project, pipelineID, stage), stageRec); err != nil {
		return err
	}

	jobs, ok := m["jobs"].([]any)
	if !ok {
		return emitJob(cp, timer, project, pipelineID, stage, "__default", m, stagePool)
	}
	for i, j := range jobs {
		jm, ok := j.(map[string]any)
		if !ok {
			continue
		}
		jobName := firstStr(jm, "job", firstStr(jm, "deployment", fmt.Sprintf("job_%d", i)))
		if err := emitJob(cp, timer, project, pipelineID, stage, jobName, jm, stagePool); err != nil {
			return err
		}
	}
	return nil
}

func emitJob(cp engine.CurrentPhase, timer *engine.PhaseTimer, project string, pipelineID int64, stage, job string, m map[string]any, inheritedPool any) error {
	steps := collectSteps(m)
	scUsages, checkouts, taskRefs := walkSteps(steps)
	jobPool := m["pool"]
	if jobPool == nil {
		jobPool = inheritedPool
	}

	rec := map[string]any{
		"_id":                       fmt.Sprintf("%d/%s/%s", pipelineID, stage, job),
		"kind":                      "Job",
		"project":                   project,
		"pipeline_id":               pipelineID,
		"stage":                     stage,
		"job":                       job,
		"is_deployment":             m["deployment"] != nil,
		"condition":                 yamlStr(m["condition"]),
		"depends_on":                stringsOf(m["dependsOn"]),
		"pool":                      normalizePool(jobPool),
		"variable_groups":           toAnyList(variableGroups(m["variables"])), // job-level declarations only
		"targets_environment":       strOrNull(jobEnvironment(m)),
		"service_connection_usages": scUsages,
		"checkout_steps":            checkouts,
		"task_usages":               taskRefs,
		"_provenance":               prov(engine.CollectADOBuildDefFull(project, pipelineID)),
	}
	return emit(cp, timer, engine.NormalizeADOJob(project, pipelineID, stage, job), rec)
}

// collectSteps returns the step list from a job/deployment strategy.
func collectSteps(m map[string]any) []any {
	if s, ok := m["steps"].([]any); ok {
		return s
	}
	// deployment jobs nest steps under strategy.runOnce/rolling.deploy.steps
	strat := entMap(m["strategy"])
	for _, kind := range []string{"runOnce", "rolling", "canary"} {
		phase := entMap(strat[kind])
		if dep := entMap(phase["deploy"]); dep != nil {
			if s, ok := dep["steps"].([]any); ok {
				return s
			}
		}
	}
	return nil
}

func walkSteps(steps []any) (scUsages, checkouts, taskRefs []any) {
	scUsages, checkouts, taskRefs = []any{}, []any{}, []any{}
	for i, s := range steps {
		sm, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if ck, ok := sm["checkout"]; ok {
			checkouts = append(checkouts, map[string]any{
				"repository":          yamlStr(ck),
				"clean":               sm["clean"],
				"fetch_depth":         sm["fetchDepth"],
				"persist_credentials": sm["persistCredentials"],
				"submodules":          sm["submodules"],
				"step_index":          i,
			})
			continue
		}
		task := yamlStr(sm["task"])
		if task == "" {
			continue
		}
		inputs := entMap(sm["inputs"])
		taskRefs = append(taskRefs, map[string]any{"task": task, "step_index": i})
		for _, inputName := range scInputNames {
			if conn := yamlStr(inputs[inputName]); conn != "" {
				scUsages = append(scUsages, map[string]any{
					"task":            task,
					"input_name":      inputName,
					"connection_name": conn,
					"step_index":      i,
				})
			}
		}
	}
	return
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

// variableGroups returns the names in a `variables:` block's `- group:` entries.
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

// ---- small YAML helpers ----

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
