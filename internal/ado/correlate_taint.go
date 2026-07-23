package ado

import (
	"fmt"
	"slices"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// deriveTaintEdges is the derived/attack-edge half of normalize (schema §5). It
// reads back the structural corpus the earlier joins wrote and emits the taint
// edges: READS (secret reach), QUEUE_TIME_INJECTION (cat-02),
// LOGGING_COMMAND_INJECTION (cat-13), AGENT_INJECTION (cat-12 injection half),
// and PIPELINE_POISONING (cat-01 injection half). The step-level sinks/sources
// these key on are already collapsed onto each :Job by walkSteps.
func deriveTaintEdges(prior engine.PriorPhase, cp engine.CurrentPhase, timer *engine.PhaseTimer, jobs, pipelines []map[string]any) error {
	pipeMeta := indexPipelines(pipelines)
	grants := loadGrants(prior)

	readsByJob, err := deriveReads(prior, cp, timer, jobs)
	if err != nil {
		return err
	}
	for _, j := range jobs {
		meta := pipeMeta[pipeKey(mStr(j, "project"), mInt64(j, "pipeline_id"))]
		if err := deriveQueueTimeInjection(cp, timer, j, meta, grants); err != nil {
			return err
		}
		if err := deriveLoggingInjection(cp, timer, j, meta, grants); err != nil {
			return err
		}
		if err := deriveAgentInjection(cp, timer, j, meta, grants); err != nil {
			return err
		}
		if err := derivePipelinePoisoning(cp, timer, j, meta, grants, readsByJob[jobKeyOf(j)]); err != nil {
			return err
		}
	}
	return nil
}

type pipeInfo struct {
	identityScope   string
	enforceSettable bool
	enableSanitize  bool
	settableVars    any  // nil=all overridable, []=none, list=restricted
	ciTrigger       any  // nil=implicit, "none"=off, else filter
	buildValidated  bool // a BUILD_VALIDATES policy targets this pipeline
	freeformParams  map[string]bool
	allowlistParams map[string]bool
	name            string
}

func pipeKey(project string, id int64) string { return fmt.Sprintf("%s/%d", project, id) }

func indexPipelines(pipelines []map[string]any) map[string]pipeInfo {
	out := map[string]pipeInfo{}
	for _, p := range pipelines {
		info := pipeInfo{
			identityScope:   mStr(p, "identity_scope"),
			enforceSettable: mBool(p, "enforce_settable_var"),
			enableSanitize:  mBool(p, "enable_shell_tasks_args_sanitizing"),
			settableVars:    mGet(p, "settable_variables"),
			ciTrigger:       mGet(p, "ci_trigger"),
			name:            mStr(p, "name"),
			freeformParams:  map[string]bool{},
			allowlistParams: map[string]bool{},
		}
		for _, raw := range mList(p, "parameters") {
			pm := entMap(raw)
			name := entStr(pm["name"])
			if entBool(pm["is_freeform"]) {
				info.freeformParams[name] = true
			}
			if entBool(pm["has_values_allowlist"]) {
				info.allowlistParams[name] = true
			}
		}
		out[pipeKey(mStr(p, "project"), mInt64(p, "id"))] = info
	}
	return out
}

// ---- READS (Job -> SecretVariable) ---------------------------------------

func deriveReads(prior engine.PriorPhase, cp engine.CurrentPhase, timer *engine.PhaseTimer, jobs []map[string]any) (map[string]bool, error) {
	readsByJob := map[string]bool{}
	secretsByGroup := map[int64][]map[string]any{}
	secrets, err := loadRecords(prior, "10-normalize/secret-variables")
	if err != nil {
		return nil, fmt.Errorf("correlate: load secret-variables: %w", err)
	}
	for _, s := range secrets {
		gid := mInt64(s, "group_id")
		secretsByGroup[gid] = append(secretsByGroup[gid], s)
	}
	vgGate := map[int64]map[string]any{}
	vgs, err := loadRecords(prior, "10-normalize/variable-groups")
	if err != nil {
		return nil, fmt.Errorf("correlate: load variable-groups: %w", err)
	}
	for _, g := range vgs {
		vgGate[mInt64(g, "id")] = g
	}
	cg, err := loadRecords(prior, "10-normalize/edges/consumes-group")
	if err != nil {
		return nil, fmt.Errorf("correlate: load consumes-group: %w", err)
	}

	for _, j := range jobs {
		project, pid := mStr(j, "project"), mInt64(j, "pipeline_id")
		stage, job := mStr(j, "stage"), mStr(j, "job")
		seen := map[int64]bool{}
		for _, e := range cg {
			if mStr(e, "project") != project || mInt64(e, "pipeline_id") != pid {
				continue
			}
			// a pipeline-level group reaches every job; a stage-level group every job
			// in the stage; a job-level group only its own job (schema §5 READS).
			reaches := false
			switch mStr(e, "level") {
			case "pipeline":
				reaches = true
			case "stage":
				reaches = mStr(e, "stage") == stage
			case "job":
				reaches = mStr(e, "stage") == stage && mStr(e, "job") == job
			}
			if !reaches {
				continue
			}
			gid := mInt64(e, "variable_group_id")
			if gid == 0 || seen[gid] {
				continue
			}
			seen[gid] = true
			strength, state, confidence := vgGateState(vgGate[gid])
			if len(secretsByGroup[gid]) > 0 {
				readsByJob[jobKeyOf(j)] = true
			}
			for _, s := range secretsByGroup[gid] {
				rec := map[string]any{
					"kind": "READS", "project": project, "pipeline_id": pid, "stage": stage, "job": job,
					"variable_group_id": gid, "secret_name": mStr(s, "name"), "secret_id": mStr(s, "_id"),
					"via_level": mStr(e, "level"), "gate_strength": strength, "gate_state": state, "confidence": confidence,
				}
				key := fmt.Sprintf("%s__%d__%s__%s__%d__%s", adoSafe(project), pid, adoSafe(stage), adoSafe(job), gid, adoSafe(mStr(s, "name")))
				if err := emit(cp, timer, engine.NormalizeADOEdges("reads", key), rec); err != nil {
					return nil, err
				}
			}
		}
	}
	return readsByJob, nil
}

func vgGateState(vg map[string]any) (strength, state, confidence string) {
	if vg != nil && len(mList(vg, "checks")) > 0 {
		return "strong", "real", "low"
	}
	return "none", "absent", "high"
}

// ---- QUEUE_TIME_INJECTION (source -> Job) --------------------------------

func deriveQueueTimeInjection(cp engine.CurrentPhase, timer *engine.PhaseTimer, j map[string]any, meta pipeInfo, grants grantIndex) error {
	project := mStr(j, "project")
	sources := grants.principalsWith(project, buildNSKey, "QueueBuilds")
	target := jobID(j)

	blocksAllMacros := meta.enforceSettable && isEmptyList(meta.settableVars)

	emitEdge := func(sinkType, name, via, location, confidence string, ms map[string]any) error {
		rec := map[string]any{
			"kind": "QUEUE_TIME_INJECTION", "technique": "queue_time_injection",
			"project": project, "pipeline_id": mInt64(j, "pipeline_id"), "job": mStr(j, "job"),
			"source": "queue_build_principal", "source_permission": "QueueBuilds", "source_principals": sources,
			"sink_type": sinkType, "macro_name": name, "sink_location": location, "via": via,
			"enforce_settable_var": meta.enforceSettable, "enable_args_validation": meta.enableSanitize,
			"is_declared_settable": entBool(ms["is_declared_settable"]), "settable_variables": meta.settableVars,
			"identity_scope": meta.identityScope, "confidence": confidence,
			"target": target, "context": "azure_repos",
		}
		key := fmt.Sprintf("%s__%s__%s", jobKeyOf(j), adoSafe(via), adoSafe(name))
		return emit(cp, timer, engine.NormalizeADOEdges("queue-time-injection", key), rec)
	}

	for _, raw := range mList(j, "macro_sinks") {
		ms := entMap(raw)
		kind, loc, name := entStr(ms["macro_kind"]), entStr(ms["location"]), entStr(ms["macro_name"])
		if kind == "predefined_untrusted" {
			st := "macro_in_script"
			if loc == "task_input" {
				st = "macro_in_task_input"
			}
			if err := emitEdge(st, name, "predefined_variable", loc, "high", ms); err != nil {
				return err
			}
			continue
		}
		if blocksAllMacros { // settableVariables:[] with the limit on blocks every macro (deterministic)
			continue
		}
		switch loc {
		case "script":
			conf := "high"
			if meta.enforceSettable && !entBool(ms["is_declared_settable"]) {
				conf = "medium"
			}
			if err := emitEdge("macro_in_script", name, "unrestricted_macro", loc, conf, ms); err != nil {
				return err
			}
		case "task_input":
			conf := "high"
			if meta.enableSanitize {
				conf = "low" // shell-args validation hardens the arguments sink
			}
			if err := emitEdge("macro_in_task_input", name, "settable_var_arguments", loc, conf, ms); err != nil {
				return err
			}
		}
	}

	for _, raw := range mList(j, "parameter_sinks") {
		ps := entMap(raw)
		name, loc := entStr(ps["param_name"]), entStr(ps["location"])
		if meta.allowlistParams[name] {
			continue // values: allowlist is a deterministic sanitizer
		}
		switch loc {
		case "script":
			if err := emitEdge("parameter_in_script", name, "freeform_parameter", "script", "high", ps); err != nil {
				return err
			}
		case "compile_keyword":
			if err := emitEdge("parameter_in_compile_keyword", name, "input_target_redirect", entStr(ps["keyword"]), "high", ps); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---- LOGGING_COMMAND_INJECTION (source -> Job) ---------------------------

func deriveLoggingInjection(cp engine.CurrentPhase, timer *engine.PhaseTimer, j map[string]any, meta pipeInfo, grants grantIndex) error {
	echoes := mList(j, "vso_echo_sources")
	if len(echoes) == 0 {
		return nil
	}
	project := mStr(j, "project")
	sources := grants.principalsWith(project, gitNSKey, "GenericContribute", "PullRequestContribute")

	emitEdge := func(cmdType, via, effect, source string, echoStep int, consumer map[string]any, confidence string) error {
		rec := map[string]any{
			"kind": "LOGGING_COMMAND_INJECTION", "technique": "logging_command_injection",
			"project": project, "pipeline_id": mInt64(j, "pipeline_id"), "job": mStr(j, "job"),
			"command_type": cmdType, "untrusted_source": source, "echo_step": echoStep,
			"via": via, "effect": effect, "consumer_step": consumer["step_index"],
			"target_resource": consumer["resource"], "source_principals": sources,
			"identity_scope": meta.identityScope, "confidence": confidence,
			"target": jobID(j), "context": "azure_repos",
		}
		key := fmt.Sprintf("%s__%s__%d__%v", jobKeyOf(j), adoSafe(via), echoStep, consumer["step_index"])
		return emit(cp, timer, engine.NormalizeADOEdges("logging-command-injection", key), rec)
	}

	scUsages := mList(j, "service_connection_usages")
	bareBins := mList(j, "bare_binary_calls")
	varCons := mList(j, "variable_consumers")
	credWrites := mList(j, "cred_writes")

	for _, raw := range echoes {
		echo := entMap(raw)
		e := int(entInt64(echo["step_index"]))
		src := entStr(echo["untrusted_source"])
		conf := loggingConfidence(src)

		for _, u := range scUsages { // setendpoint: connection used after the echo
			um := entMap(u)
			if int(entInt64(um["step_index"])) > e {
				if err := emitEdge("setendpoint", "setendpoint_redirect", "connection_url_redirect", src, e,
					map[string]any{"step_index": um["step_index"], "resource": entStr(um["connection_name"])}, conf); err != nil {
					return err
				}
			}
		}
		for _, b := range bareBins { // prependpath: bare binary invoked after the echo
			bm := entMap(b)
			if int(entInt64(bm["step_index"])) > e {
				if err := emitEdge("prependpath", "prependpath_shadow", "path_binary_shadow", src, e,
					map[string]any{"step_index": bm["step_index"], "resource": entStr(bm["bin"])}, conf); err != nil {
					return err
				}
			}
		}
		for _, v := range varCons { // setvariable: variable read after the echo
			vm := entMap(v)
			if int(entInt64(vm["step_index"])) > e {
				if err := emitEdge("setvariable", "setvariable_control_flip", "variable_control_flip", src, e,
					map[string]any{"step_index": vm["step_index"], "resource": entStr(vm["name"])}, conf); err != nil {
					return err
				}
			}
		}
		for _, c := range credWrites { // artifact.upload: a secret file written before the echo
			cm := entMap(c)
			if int(entInt64(cm["step_index"])) < e {
				if err := emitEdge("artifact.upload", "artifact_upload_exfil", "file_exfiltration", src, e,
					map[string]any{"step_index": cm["step_index"], "resource": entStr(cm["file"])}, conf); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func loggingConfidence(src string) string {
	switch src {
	case "literal_vso", "variable_value":
		return "medium"
	}
	return "high"
}

// ---- AGENT_INJECTION (source -> Job) -------------------------------------

func deriveAgentInjection(cp engine.CurrentPhase, timer *engine.PhaseTimer, j map[string]any, meta pipeInfo, grants grantIndex) error {
	ai := mList(j, "ai_task_sinks")
	if len(ai) == 0 {
		return nil
	}
	project := mStr(j, "project")
	sources := grants.principalsWith(project, gitNSKey, "GenericContribute", "PullRequestContribute")

	for i, raw := range ai {
		sink := entMap(raw)
		caps := mList(sink, "capabilities")
		conf := "medium"
		if slices.ContainsFunc(caps, func(c any) bool { s, _ := c.(string); return s == "tool_exec" || s == "egress" }) {
			conf = "high"
		}
		via := "direct"
		if b, _ := sink["generated_script"].(bool); b {
			via = "generate_then_execute"
		}
		rec := map[string]any{
			"kind": "AGENT_INJECTION", "technique": "prompt_injection",
			"project": project, "pipeline_id": mInt64(j, "pipeline_id"), "job": mStr(j, "job"),
			"via": via, "source_kind": "pr_description", "vendor": entStr(sink["vendor"]),
			"capabilities": caps, "gate_state": "absent", "source_principals": sources,
			"identity_scope": meta.identityScope, "confidence": conf,
			"target": jobID(j), "context": "azure_repos",
		}
		key := fmt.Sprintf("%s__%d", jobKeyOf(j), i)
		if err := emit(cp, timer, engine.NormalizeADOEdges("agent-injection", key), rec); err != nil {
			return err
		}
	}
	return nil
}

// ---- PIPELINE_POISONING (source -> Job) ----------------------------------

func derivePipelinePoisoning(cp engine.CurrentPhase, timer *engine.PhaseTimer, j map[string]any, meta pipeInfo, grants grantIndex, reads bool) error {
	// Necessary conjuncts (schema §5): an execution trigger runs the repo's YAML,
	// and the pipeline has an authorized blast radius worth stealing — a secret
	// reach (READS), a service connection, the collection-scoped access token, or
	// a deployment target. A resource-less `echo build` pipeline is not a finding.
	trigger, via := poisonTrigger(meta)
	if trigger == "" {
		return nil
	}
	blastRadius := reads || len(mList(j, "service_connection_usages")) > 0 ||
		mBool(j, "exposes_system_access_token") || meta.identityScope == "collection" ||
		mStr(j, "targets_environment") != ""
	if !blastRadius {
		return nil
	}
	project := mStr(j, "project")
	sources := grants.principalsWith(project, gitNSKey, "GenericContribute", "PullRequestContribute")

	sinkKind := "checkout"
	if mBool(j, "executes_checked_out_code") {
		sinkKind = "script"
	}
	confidence := "medium"
	if via == "build_validation" {
		confidence = "high" // runs before any reviewer approves
	}
	rec := map[string]any{
		"kind": "PIPELINE_POISONING", "technique": "pipeline_poisoning",
		"project": project, "pipeline_id": mInt64(j, "pipeline_id"), "job": mStr(j, "job"),
		"trigger": trigger, "via": via, "sink_kind": sinkKind, "sink_form": "script",
		"exposes_system_access_token": mBool(j, "exposes_system_access_token"),
		"identity_scope":              meta.identityScope, "source_principals": sources,
		"gate_state": "absent", "confidence": confidence,
		"target": jobID(j), "context": "azure_repos",
	}
	return emit(cp, timer, engine.NormalizeADOEdges("pipeline-poisoning", jobKeyOf(j)), rec)
}

// poisonTrigger resolves the strongest execution trigger a Contributor can drive.
func poisonTrigger(meta pipeInfo) (trigger, via string) {
	switch {
	case meta.buildValidated:
		return "build_validation", "build_validation"
	case meta.ciTrigger != nil && meta.ciTrigger != "none":
		return "ci_push", "ci_trigger"
	default:
		// no CI trigger declared: a Contributor still pushes modified YAML to a
		// branch and queues a build against it (schema §5 via: branch_queue).
		return "manual_queue", "branch_queue"
	}
}

// ---- source-principal resolution -----------------------------------------

const (
	gitNSKey      = "git"
	buildNSKey    = "build"
	endpointNSKey = "endpoint"
)

type grantIndex struct {
	byProjectAction map[string]map[string][]map[string]any
}

// loadGrants indexes HAS_ROLE edges by (project, namespace-tagged action) -> the
// principal grants (descriptor + expanded leaf members) — the source side of the
// injection edges (who holds Queue builds / Contribute).
func loadGrants(prior engine.PriorPhase) grantIndex {
	idx := grantIndex{byProjectAction: map[string]map[string][]map[string]any{}}
	roles, err := loadRecords(prior, "10-normalize/edges/has-role")
	if err != nil {
		return idx
	}
	projByID := map[string]string{}
	if projs, err := loadRecords(prior, "10-normalize/projects"); err == nil {
		for _, p := range projs {
			projByID[mStr(p, "_id")] = mStr(p, "project")
		}
	}
	repoProj := map[string]string{}
	if repos, err := loadRecords(prior, "10-normalize/repos"); err == nil {
		for _, r := range repos {
			repoProj[mStr(r, "_id")] = mStr(r, "project")
		}
	}
	nsTag := map[string]string{gitNS: gitNSKey, buildNS: buildNSKey, endpointNS: endpointNSKey}
	for _, role := range roles {
		project := ""
		switch mStr(role, "resource_kind") {
		case "Project":
			project = projByID[mStr(role, "resource_id")]
		case "Repository":
			project = repoProj[mStr(role, "resource_id")]
		}
		if project == "" {
			continue
		}
		nsk := nsTag[mStr(role, "namespace")]
		grant := map[string]any{"descriptor": mStr(role, "graph_descriptor"), "members": listOrEmpty(role, "expanded_members")}
		for _, a := range mList(role, "allowed_actions") {
			action, _ := a.(string)
			if action == "" {
				continue
			}
			tagged := nsk + ":" + action
			if idx.byProjectAction[project] == nil {
				idx.byProjectAction[project] = map[string][]map[string]any{}
			}
			idx.byProjectAction[project][tagged] = append(idx.byProjectAction[project][tagged], grant)
		}
	}
	return idx
}

func (g grantIndex) principalsWith(project, ns string, actions ...string) []any {
	byAction := g.byProjectAction[project]
	seen := map[string]bool{}
	out := []any{}
	for _, action := range actions {
		for _, grant := range byAction[ns+":"+action] {
			d, _ := grant["descriptor"].(string)
			if d == "" || seen[d] {
				continue
			}
			seen[d] = true
			out = append(out, grant)
		}
	}
	return out
}

// ---- small helpers -------------------------------------------------------

func jobID(j map[string]any) string { return mStr(j, "_id") }

func jobKeyOf(j map[string]any) string {
	return fmt.Sprintf("%s__%d__%s__%s", adoSafe(mStr(j, "project")), mInt64(j, "pipeline_id"),
		adoSafe(mStr(j, "stage")), adoSafe(mStr(j, "job")))
}

func isEmptyList(v any) bool {
	l, ok := v.([]any)
	return ok && len(l) == 0
}

func hasCap(caps []any, want string) bool {
	for _, c := range caps {
		if s, _ := c.(string); s == want {
			return true
		}
	}
	return false
}
