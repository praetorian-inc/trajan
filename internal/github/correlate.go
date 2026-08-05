package github

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// correlate reads the normalized corpus back off disk as generic maps (so chain
// records match the .get()-keyed shapes field-for-field) rather than the typed
// jobs slice, which it ignores.
func correlate(prior engine.PriorPhase, cp engine.CurrentPhase, _ []Job) error {
	jobs, err := loadRecords(prior, "10-normalize/jobs")
	if err != nil {
		return fmt.Errorf("correlate: load jobs: %w", err)
	}
	repos, err := loadRecords(prior, "10-normalize/repos")
	if err != nil {
		return fmt.Errorf("correlate: load repos: %w", err)
	}
	rulesets, err := loadRecords(prior, "10-normalize/rulesets")
	if err != nil {
		return fmt.Errorf("correlate: load rulesets: %w", err)
	}
	envs, err := loadRecords(prior, "10-normalize/environments")
	if err != nil {
		return fmt.Errorf("correlate: load environments: %w", err)
	}
	apps, err := loadRecords(prior, "10-normalize/apps")
	if err != nil {
		return fmt.Errorf("correlate: load apps: %w", err)
	}
	principals, err := loadRecords(prior, "10-normalize/principals")
	if err != nil {
		return fmt.Errorf("correlate: load principals: %w", err)
	}
	deployKeys, err := loadRecords(prior, "10-normalize/deploy-keys")
	if err != nil {
		return fmt.Errorf("correlate: load normalized deploy-keys: %w", err)
	}
	deployKeyFiles, err := prior.IterJSON("00-collect/deploy-keys")
	if err != nil {
		return fmt.Errorf("correlate: load deploy-keys: %w", err)
	}
	branchesByRepo, err := loadBranchInventory(prior)
	if err != nil {
		return fmt.Errorf("correlate: load branches: %w", err)
	}

	coverage, coverageEntries := deriveBranchCoverage(repos, rulesets, branchesByRepo)
	effective, effectiveEntries := deriveEffectiveRuleset(coverageEntries, rulesets, repos)
	mintable, mintRepos := deriveAppMintable(jobs, apps)

	writers := []func() error{
		func() error { return cp.Write(chainPath("reusable-callgraph"), deriveReusableCallgraph(jobs)) },
		func() error { return cp.Write(chainPath("trigger-channels"), deriveTriggerChannels(jobs)) },
		func() error { return cp.Write(chainPath("cache-keyspace"), deriveCacheKeyspace(jobs)) },
		func() error { return cp.Write(chainPath("branch-coverage"), coverage) },
		func() error { return cp.Write(chainPath("effective-ruleset"), effective) },
		func() error {
			return cp.Write(chainPath("capability-edges"),
				deriveCapabilityEdges(effectiveEntries, principals, deployKeys, repos, apps, mintRepos))
		},
		func() error { return cp.Write(chainPath("app-mintable"), mintable) },
		func() error { return cp.Write(chainPath("env-deployments"), deriveEnvDeployments(jobs, envs)) },
		func() error { return cp.Write(chainPath("deploy-key-reuse"), deriveDeployKeyReuse(deployKeyFiles)) },
		func() error { return cp.Write(chainPath("job-output-flow"), deriveJobOutputFlow(jobs)) },
	}
	for _, w := range writers {
		if err := w(); err != nil {
			return fmt.Errorf("correlate: write chain: %w", err)
		}
	}

	if err := deriveIndices(jobs, cp); err != nil {
		return fmt.Errorf("correlate: write indices: %w", err)
	}
	return nil
}

func chainPath(name string) string { return path.Join("10-normalize", "chains", name+".json") }
func indexDir(name string) string  { return path.Join("10-normalize", "chains", "indices", name) }
func indexPath(name, key string) string {
	return path.Join(indexDir(name), key+".json")
}

func loadRecords(prior engine.PriorPhase, dir string) ([]map[string]any, error) {
	files, err := prior.IterJSON(dir)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(files))
	for _, f := range files {
		var rec map[string]any
		if err := json.Unmarshal(f.Data, &rec); err != nil {
			return nil, fmt.Errorf("%s: %w", f.Rel, err)
		}
		out = append(out, rec)
	}
	return out, nil
}

func mGet(m map[string]any, key string) any {
	if m == nil {
		return nil
	}
	return m[key]
}

func mStr(m map[string]any, key string) string {
	s, _ := mGet(m, key).(string)
	return s
}

func mBool(m map[string]any, key string) bool {
	b, _ := mGet(m, key).(bool)
	return b
}

func mMap(m map[string]any, key string) map[string]any {
	v, _ := mGet(m, key).(map[string]any)
	return v
}

func mList(m map[string]any, key string) []any {
	v, _ := mGet(m, key).([]any)
	return v
}

func asStrings(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// listOrEmpty defaults to a non-nil empty list so it serializes as [] not null.
func listOrEmpty(m map[string]any, key string) []any {
	if v, ok := mGet(m, key).([]any); ok {
		return v
	}
	return []any{}
}

func deriveReusableCallgraph(jobs []map[string]any) map[string]any {
	edges := []map[string]any{}
	for _, job := range jobs {
		for _, c := range mList(job, "calls_reusable_workflows") {
			callee, _ := c.(map[string]any)
			if callee == nil {
				continue
			}
			ref := mGet(callee, "ref")
			refStr, _ := ref.(string)
			kind, mutable := classifyCalleeRef(refStr, ref == nil)
			usesVal := mGet(callee, "uses")
			usesStr, _ := usesVal.(string)
			isLocal := mStr(callee, "kind") == "local" || strings.HasPrefix(usesStr, "./")
			inputs := mGet(callee, "inputs")
			if inputs == nil {
				inputs = map[string]any{}
			}
			secrets := mGet(callee, "secrets")
			if secrets == nil {
				secrets = map[string]any{}
			}
			usesID := "?"
			if usesStr != "" {
				usesID = usesStr
			}
			edges = append(edges, map[string]any{
				"_id": fmt.Sprintf("%s__calls__%s", mStr(job, "_id"), usesID),
				"caller": map[string]any{
					"_id":               mGet(job, "_id"),
					"repo":              mGet(job, "repo"),
					"workflow_filename": mGet(job, "workflow_filename"),
					"job_id":            mGet(job, "job_id"),
					"triggers":          mGet(job, "triggers"),
				},
				"callee": map[string]any{
					"uses":            usesVal,
					"owner":           mGet(callee, "owner"),
					"repo":            mGet(callee, "repo"),
					"path":            mGet(callee, "path"),
					"ref":             ref,
					"ref_kind":        kind,
					"ref_mutable":     mutable,
					"is_local":        isLocal,
					"inputs":          inputs,
					"secrets":         secrets,
					"secrets_inherit": mBool(callee, "secrets_inherit"),
				},
			})
		}
	}
	return map[string]any{
		"chain":      "reusable-callgraph",
		"edges":      edges,
		"edge_count": len(edges),
	}
}

// deriveJobOutputFlow emits one edge per consumer-step needs.<job>.outputs.<var>
// reference, joined single-hop to the producer job in the same workflow. needs
// is intra-workflow and names the producer explicitly, so the join key is
// (repo, workflow_filename, job_id); a producer absent from the workflow is
// silently skipped (no recursion).
func deriveJobOutputFlow(jobs []map[string]any) map[string]any {
	byKey := map[[3]string]map[string]any{}
	for _, j := range jobs {
		byKey[[3]string{mStr(j, "repo"), mStr(j, "workflow_filename"), mStr(j, "job_id")}] = j
	}

	edges := []map[string]any{}
	for _, consumer := range jobs {
		if len(mList(consumer, "needs_output_refs")) == 0 {
			continue
		}
		repo := mStr(consumer, "repo")
		wf := mStr(consumer, "workflow_filename")
		emit := func(stepIdx int, ctxName, jobID, outputName string) {
			producer, ok := byKey[[3]string{repo, wf, jobID}]
			if !ok {
				return
			}
			matched := matchProducerOutput(producer, outputName)
			if matched == nil {
				return
			}
			influenced := len(asStrings(mGet(matched, "attacker_context_fields_referenced"))) > 0 ||
				len(asStrings(mGet(matched, "producing_step_attacker_exec_refs"))) > 0
			edges = append(edges, map[string]any{
				"_id": fmt.Sprintf("jof__%s__%s__%s__s%d__%s", mStr(producer, "_id"), mStr(consumer, "_id"), outputName, stepIdx, ctxName),
				"producer": map[string]any{
					"_id":      mGet(producer, "_id"),
					"job_id":   mGet(producer, "job_id"),
					"triggers": listOrEmpty(producer, "triggers"),
					"outputs":  []any{matched},
				},
				"consumer": map[string]any{
					"_id":         mGet(consumer, "_id"),
					"job_id":      mGet(consumer, "job_id"),
					"step_index":  stepIdx,
					"output_name": outputName,
					"triggers":    listOrEmpty(consumer, "triggers"),
					"context":     ctxName,
				},
				"attacker_influenced": influenced,
				"attacker_path":       jobOutputAttackerPath(producer, matched),
			})
		}

		stepRefs := map[[2]string]bool{}
		for stepIdx, s := range mList(consumer, "steps") {
			step, _ := s.(map[string]any)
			for _, ctx := range []struct {
				key  string
				name string
			}{{"needs_output_refs_exec", "exec"}, {"needs_output_refs_binding", "binding"}} {
				for _, r := range mList(step, ctx.key) {
					ref, _ := r.(map[string]any)
					jobID := mStr(ref, "job_id")
					outputName := mStr(ref, "output_name")
					stepRefs[[2]string{jobID, outputName}] = true
					emit(stepIdx, ctx.name, jobID, outputName)
				}
			}
		}

		// Job-level exec refs not carried by any step come from the strategy/matrix
		// block (e.g. fromJSON(needs.<job>.outputs.matrix)); emit them at step -1.
		for _, r := range mList(consumer, "needs_output_refs_exec") {
			ref, _ := r.(map[string]any)
			jobID := mStr(ref, "job_id")
			outputName := mStr(ref, "output_name")
			if stepRefs[[2]string{jobID, outputName}] {
				continue
			}
			emit(-1, "exec", jobID, outputName)
		}
	}

	return map[string]any{
		"chain":      "job-output-flow",
		"edges":      edges,
		"edge_count": len(edges),
	}
}

func matchProducerOutput(producer map[string]any, name string) map[string]any {
	for _, o := range mList(producer, "outputs") {
		out, _ := o.(map[string]any)
		if mStr(out, "name") == name {
			return out
		}
	}
	return nil
}

func jobOutputAttackerPath(producer, output map[string]any) []any {
	steps := []any{
		fmt.Sprintf("producer job %s output %s", mStr(producer, "job_id"), mStr(output, "name")),
	}
	if sid := mGet(output, "references_step_id"); sid != nil {
		steps = append(steps, fmt.Sprintf("producing step %v", sid))
	}
	for _, f := range asStrings(mGet(output, "attacker_context_fields_referenced")) {
		steps = append(steps, "value expr references "+f)
	}
	for _, f := range asStrings(mGet(output, "producing_step_attacker_exec_refs")) {
		steps = append(steps, "producing step exec references "+f)
	}
	return steps
}

func classifyCalleeRef(ref string, isNil bool) (kind string, mutable bool) {
	if isNil || ref == "" {
		return "unknown", true
	}
	if !isMutableRef(ref) {
		return "sha", false
	}
	return "tag-or-branch", true
}

var shaRefRe = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)

func isMutableRef(ref string) bool { return !shaRefRe.MatchString(ref) }

func deriveTriggerChannels(jobs []map[string]any) map[string]any {
	wfByName := map[[2]string][]map[string]any{}
	for _, j := range jobs {
		repo := mStr(j, "repo")
		wfname := mStr(j, "workflow_name")
		wffile := mStr(j, "workflow_filename")
		idents := map[string]bool{wfname: true, wffile: true}
		if wffile != "" {
			idents[".github/workflows/"+wffile] = true
		}
		for ident := range idents {
			if ident == "" {
				continue
			}
			key := [2]string{repo, ident}
			wfByName[key] = append(wfByName[key], j)
		}
	}

	workflowRunPairs := []map[string]any{}
	seenPair := map[string]bool{}
	for _, j := range jobs {
		if !slices.Contains(asStrings(mGet(j, "triggers")), "workflow_run") {
			continue
		}
		wfRunFilter := mMap(mMap(j, "trigger_filters"), "workflow_run")
		upstreamNames := asStrings(mGet(wfRunFilter, "workflows"))
		eventTypes := listOrEmpty(wfRunFilter, "types")
		for _, upName := range upstreamNames {
			for _, up := range wfByName[[2]string{mStr(j, "repo"), upName}] {
				pairID := fmt.Sprintf("wfrun__%s__%s", mStr(up, "_id"), mStr(j, "_id"))
				if seenPair[pairID] {
					continue
				}
				seenPair[pairID] = true
				workflowRunPairs = append(workflowRunPairs, map[string]any{
					"_id":         pairID,
					"upstream":    jobSummaryFull(up),
					"downstream":  jobSummaryFull(j),
					"event_types": eventTypes,
				})
			}
		}
	}

	artifactHandoffs := []map[string]any{}
	calleeInputs := calleeInputsByWorkflow(jobs)
	writersByRepoName := map[[2]string][]map[string]any{}
	for _, j := range jobs {
		for _, name := range artifactNames(j, "artifact_writes") {
			key := [2]string{mStr(j, "repo"), resolveInputRef(name, calleeInputs[calleeWorkflow(j)])}
			writersByRepoName[key] = append(writersByRepoName[key], j)
		}
	}
	for _, j := range jobs {
		for _, raw := range artifactNames(j, "artifact_reads") {
			name := resolveInputRef(raw, calleeInputs[calleeWorkflow(j)])
			for _, writer := range writersByRepoName[[2]string{mStr(j, "repo"), name}] {
				if mStr(writer, "_id") == mStr(j, "_id") {
					continue
				}
				artifactHandoffs = append(artifactHandoffs, map[string]any{
					"_id":           fmt.Sprintf("art__%s__%s__%s", mStr(writer, "_id"), mStr(j, "_id"), name),
					"artifact_name": name,
					"writer":        jobSummaryFull(writer),
					"reader":        jobSummaryFull(j),
				})
			}
		}
	}

	repositoryDispatchLinks := []map[string]any{}
	var emitters, receivers []map[string]any
	for _, j := range jobs {
		if containsRepoDispatchEmit(j) {
			emitters = append(emitters, j)
		}
		if slices.Contains(asStrings(mGet(j, "triggers")), "repository_dispatch") {
			receivers = append(receivers, j)
		}
	}
	for _, e := range emitters {
		for _, r := range receivers {
			if mStr(e, "repo") != mStr(r, "repo") {
				continue
			}
			repositoryDispatchLinks = append(repositoryDispatchLinks, map[string]any{
				"_id":      fmt.Sprintf("rd__%s__%s", mStr(e, "_id"), mStr(r, "_id")),
				"emitter":  jobSummaryFull(e),
				"receiver": jobSummaryFull(r),
			})
		}
	}

	workflowDispatchJobs := []map[string]any{}
	for _, j := range jobs {
		if slices.Contains(asStrings(mGet(j, "triggers")), "workflow_dispatch") {
			item := jobSummaryFull(j)
			item["_id"] = mGet(j, "_id")
			workflowDispatchJobs = append(workflowDispatchJobs, item)
		}
	}

	return map[string]any{
		"chain":                     "trigger-channels",
		"workflow_run_pairs":        workflowRunPairs,
		"artifact_handoffs":         artifactHandoffs,
		"repository_dispatch_links": repositoryDispatchLinks,
		"workflow_dispatch_jobs":    workflowDispatchJobs,
	}
}

func jobSummaryFull(job map[string]any) map[string]any {
	return map[string]any{
		"_id":                                mGet(job, "_id"),
		"repo":                               mGet(job, "repo"),
		"workflow_name":                      mGet(job, "workflow_name"),
		"workflow_filename":                  mGet(job, "workflow_filename"),
		"job_id":                             mGet(job, "job_id"),
		"triggers":                           listOrEmpty(job, "triggers"),
		"trigger_filters":                    orEmptyMap(mGet(job, "trigger_filters")),
		"trigger_class_summary":              mGet(job, "trigger_class_summary"),
		"executes_checked_out_code":          mGet(job, "executes_checked_out_code"),
		"has_checkout_of_pr_ref":             mGet(job, "has_checkout_of_pr_ref"),
		"attacker_context_fields_referenced": listOrEmpty(job, "attacker_context_fields_referenced"),
		"attacker_context_fields_referenced_exec":    listOrEmpty(job, "attacker_context_fields_referenced_exec"),
		"attacker_context_fields_referenced_binding": listOrEmpty(job, "attacker_context_fields_referenced_binding"),
		"sinks":                 listOrEmpty(job, "sinks"),
		"permissions":           mGet(job, "permissions"),
		"if_conditions_summary": mGet(job, "if_conditions_summary"),
		"secrets_referenced":    listOrEmpty(job, "secrets_referenced"),
		"artifact_reads":        listOrEmpty(job, "artifact_reads"),
		"artifact_writes":       listOrEmpty(job, "artifact_writes"),
		"_provenance":           mGet(job, "_provenance"),
	}
}

func orEmptyMap(v any) any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// A reusable callee names its artifacts "${{ inputs.X }}" and only the call site
// knows X, so without resolving it the handoff from the caller's writer to the
// callee's reader is invisible.
// Two call sites disagreeing on an input leaves that input unresolvable: picking
// either value would name an artifact the other caller never produces.
func calleeInputsByWorkflow(jobs []map[string]any) map[[2]string]map[string]any {
	out := map[[2]string]map[string]any{}
	disputed := map[[2]string]map[string]bool{}
	for _, j := range jobs {
		for _, c := range mList(j, "calls_reusable_workflows") {
			call, _ := c.(map[string]any)
			repo := cmp.Or(mStr(call, "repo"), mStr(j, "repo"))
			k := [2]string{repo, path.Base(mStr(call, "path"))}
			if out[k] == nil {
				out[k] = map[string]any{}
				disputed[k] = map[string]bool{}
			}
			for name, v := range mMap(call, "inputs") {
				if prev, seen := out[k][name]; seen && fmt.Sprint(prev) != fmt.Sprint(v) {
					disputed[k][name] = true
				}
				out[k][name] = v
			}
		}
	}
	for k, names := range disputed {
		for name := range names {
			delete(out[k], name)
		}
	}
	return out
}

func calleeWorkflow(job map[string]any) [2]string {
	return [2]string{mStr(job, "repo"), mStr(job, "workflow_filename")}
}

func resolveInputRef(name string, inputs map[string]any) string {
	ref, ok := strings.CutPrefix(name, "${{")
	if !ok {
		return name
	}
	if ref, ok = strings.CutSuffix(ref, "}}"); !ok {
		return name
	}
	if ref, ok = strings.CutPrefix(strings.TrimSpace(ref), "inputs."); !ok {
		return name
	}
	if v, _ := inputs[ref].(string); v != "" && !strings.Contains(v, "${{") {
		return v
	}
	return name
}

func artifactNames(job map[string]any, key string) []string {
	var out []string
	for _, a := range mList(job, key) {
		switch art := a.(type) {
		case map[string]any:
			if name, ok := art["name"].(string); ok && name != "" {
				out = append(out, name)
			}
		case string:
			if art != "" {
				out = append(out, art)
			}
		}
	}
	return out
}

func containsRepoDispatchEmit(job map[string]any) bool {
	for _, s := range mList(job, "steps") {
		step, _ := s.(map[string]any)
		run, _ := mGet(step, "run").(string)
		if run == "" {
			continue
		}
		if strings.Contains(run, "repos/") && strings.Contains(run, "/dispatches") {
			return true
		}
		if strings.Contains(run, "gh api") && strings.Contains(run, "dispatches") {
			return true
		}
	}
	return false
}

// GitHub scopes caches per repository, so two repos writing "npm-..." share no
// cache and the (repo, prefix) pair is the entity, not the prefix.
type cacheScope struct{ repo, prefix string }

func deriveCacheKeyspace(jobs []map[string]any) map[string]any {
	writesByPrefix := map[string][]map[string]any{}
	readsByPrefix := map[string][]map[string]any{}

	collect := func(job map[string]any, opKey string, dst map[string][]map[string]any) {
		for _, c := range mList(job, opKey) {
			var key, scope string
			var restore any
			switch cm := c.(type) {
			case map[string]any:
				key, _ = mGet(cm, "key_template").(string)
				if key == "" {
					key, _ = mGet(cm, "key").(string)
				}
				scope, _ = mGet(cm, "scope").(string)
				restore = mGet(cm, "restore_keys")
			case string:
				key = cm
			}
			prefix, ok := strings.CutPrefix(scope, "scope-prefix:")
			if !ok {
				prefix = cacheKeyPrefix(key)
			}
			if prefix == "" {
				continue
			}
			dst[prefix] = append(dst[prefix], map[string]any{
				"job":          cacheJobSummary(job),
				"key":          nilIfEmpty(key, c),
				"scope":        nilIfEmptyScope(scope, c),
				"restore_keys": restore,
			})
		}
	}
	for _, job := range jobs {
		collect(job, "cache_writes", writesByPrefix)
		collect(job, "cache_reads", readsByPrefix)
	}

	writesByScope, readsByScope := groupByCacheScope(writesByPrefix), groupByCacheScope(readsByPrefix)
	scopes := map[cacheScope]bool{}
	for s := range writesByScope {
		scopes[s] = true
	}
	for s := range readsByScope {
		scopes[s] = true
	}
	sortedScopes := slices.SortedFunc(maps.Keys(scopes), func(a, b cacheScope) int {
		return cmp.Or(cmp.Compare(a.repo, b.repo), cmp.Compare(a.prefix, b.prefix))
	})

	prefixOverlaps := []map[string]any{}
	for _, sc := range sortedScopes {
		ws := writesByScope[sc]
		rs := readsByScope[sc]
		allJobs := map[string]map[string]any{}
		order := []string{}
		add := func(entries []map[string]any) {
			for _, e := range entries {
				jb, _ := e["job"].(map[string]any)
				id, _ := jb["_id"].(string)
				if _, seen := allJobs[id]; !seen {
					order = append(order, id)
				}
				allJobs[id] = jb
			}
		}
		add(ws)
		add(rs)
		if len(allJobs) < 2 {
			continue
		}
		lowTrust := false
		for _, id := range order {
			for _, tr := range asStrings(mGet(allJobs[id], "triggers")) {
				if lowTrustTriggers[tr] || mediumTrustTriggers[tr] {
					lowTrust = true
					break
				}
			}
			if lowTrust {
				break
			}
		}
		prefixOverlaps = append(prefixOverlaps, map[string]any{
			"_id":                   "cache_overlap__" + sc.repo + "__" + sc.prefix,
			"repo":                  sc.repo,
			"key_prefix":            sc.prefix,
			"writer_count":          len(ws),
			"reader_count":          len(rs),
			"writers":               nonNilSlice(ws),
			"readers":               nonNilSlice(rs),
			"low_trust_participant": lowTrust,
		})
	}

	return map[string]any{
		"chain":            "cache-keyspace",
		"writes_by_prefix": nonNilMapList(writesByPrefix),
		"reads_by_prefix":  nonNilMapList(readsByPrefix),
		"prefix_overlaps":  prefixOverlaps,
	}
}

// nilIfEmpty: a map-source op with no key, or a nil source, serializes as null
// (Python's None default); a bare string op keeps its string even when empty.
func nilIfEmpty(key string, src any) any {
	if _, isMap := src.(map[string]any); isMap && key == "" {
		return nil
	}
	if key == "" && src == nil {
		return nil
	}
	return key
}

func nilIfEmptyScope(scope string, src any) any {
	if _, isMap := src.(map[string]any); !isMap {
		return nil
	}
	if scope == "" {
		return nil
	}
	return scope
}

func groupByCacheScope(byPrefix map[string][]map[string]any) map[cacheScope][]map[string]any {
	out := map[cacheScope][]map[string]any{}
	for prefix, entries := range byPrefix {
		for _, e := range entries {
			job, _ := e["job"].(map[string]any)
			sc := cacheScope{mStr(job, "repo"), prefix}
			out[sc] = append(out[sc], e)
		}
	}
	return out
}

func cacheJobSummary(job map[string]any) map[string]any {
	return map[string]any{
		"_id":                       mGet(job, "_id"),
		"repo":                      mGet(job, "repo"),
		"workflow_filename":         mGet(job, "workflow_filename"),
		"job_id":                    mGet(job, "job_id"),
		"triggers":                  listOrEmpty(job, "triggers"),
		"trigger_class_summary":     mGet(job, "trigger_class_summary"),
		"executes_checked_out_code": mGet(job, "executes_checked_out_code"),
		"has_checkout_of_pr_ref":    mGet(job, "has_checkout_of_pr_ref"),
		"sinks":                     listOrEmpty(job, "sinks"),
		"_provenance":               mGet(job, "_provenance"),
	}
}

func deriveBranchCoverage(repos, rulesets []map[string]any, branchesByRepo map[string][]string) (map[string]any, []map[string]any) {
	var orgRulesets []map[string]any
	for _, rs := range rulesets {
		if mStr(rs, "scope") == "org" && !mBool(rs, "_empty") && !mBool(rs, "_unavailable") && targetsBranch(rs) {
			orgRulesets = append(orgRulesets, rs)
		}
	}

	coverage := []map[string]any{}
	for _, repo := range repos {
		repoName := mStr(repo, "repo")
		if repoName == "" {
			repoName = mStr(repo, "_id")
		}
		repoIDf, _ := numericValue(mGet(repo, "repo_id"))
		repoID := int64(repoIDf)
		def := mStr(repo, "default_branch")
		if def == "" {
			def = "main"
		}

		var repoRulesets []map[string]any
		unavailable := false
		for _, rs := range rulesets {
			if mStr(rs, "scope") != "repo" || mStr(rs, "repo") != repoName {
				continue
			}
			if mBool(rs, "_unavailable") {
				unavailable = true
				continue
			}
			if mBool(rs, "_empty") || !targetsBranch(rs) {
				continue
			}
			repoRulesets = append(repoRulesets, rs)
		}

		branches := branchesByRepo[repoName]
		if len(branches) == 0 {
			branches = []string{def}
		}

		for _, branch := range branches {
			applicable := []map[string]any{}
			unevaluable := []any{}
			for _, rs := range append(append([]map[string]any{}, orgRulesets...), repoRulesets...) {
				conds := mMap(rs, "conditions")
				refConds := mMap(conds, "ref_name")
				refIncludes := asStrings(mGet(refConds, "include"))
				refExcludes := asStrings(mGet(refConds, "exclude"))
				if !refMatchAny(branch, def, refIncludes) {
					continue
				}
				if len(refExcludes) > 0 && refMatchAny(branch, def, refExcludes) {
					continue
				}
				if mStr(rs, "scope") == "org" {
					decoded := decodeConditions(conds)
					if !orgRepoGate(decoded, repoName, repoID, nil) {
						// Repo properties are not collected, so a property-scoped
						// org ruleset fails the gate for want of data rather than
						// because it does not apply.
						if decoded.RepositoryProperty != nil {
							unevaluable = append(unevaluable, mGet(rs, "ruleset_id"))
						}
						continue
					}
				}
				applicable = append(applicable, map[string]any{
					"ruleset_id":                      mGet(rs, "ruleset_id"),
					"scope":                           mGet(rs, "scope"),
					"name":                            mGet(rs, "name"),
					"enforcement":                     mGet(rs, "enforcement"),
					"requires_pull_request":           mGet(rs, "requires_pull_request"),
					"required_approving_review_count": mGet(rs, "required_approving_review_count"),
					"any_bypass_present":              mGet(mMap(rs, "bypass"), "any_bypass_present"),
				})
			}

			// Legacy protection is fetched for the default branch only, so on any
			// other branch its absence is unknown rather than false.
			isDefault := branch == def
			legacyPresent := mGet(repo, "default_branch_protection_present")
			legacyBP := mMap(repo, "default_branch_protection_summary")
			if !isDefault {
				legacyPresent, legacyBP = nil, nil
			}

			coverage = append(coverage, map[string]any{
				"_id":                 repoName + "__" + engine.BranchSlug(branch),
				"repo":                repoName,
				"branch":              branch,
				"is_default_branch":   isDefault,
				"ref_unavailable":     unavailable,
				"applicable_rulesets": applicable,
				"applicable_count":    len(applicable),
				"has_active_ruleset":  anyApplicable(applicable, func(a map[string]any) bool { return mStr(a, "enforcement") == "active" }),
				"has_pr_required_ruleset": anyApplicable(applicable, func(a map[string]any) bool {
					return mBool(a, "requires_pull_request") && mStr(a, "enforcement") == "active"
				}),
				"org_rulesets_unevaluable":         unevaluable,
				"legacy_protection_present":        legacyPresent,
				"legacy_protection_unknown":        !isDefault,
				"legacy_protection_summary":        legacyBP,
				"legacy_required_reviews":          mGet(legacyBP, "required_reviews"),
				"legacy_enforce_admins":            mGet(legacyBP, "enforce_admins"),
				"can_approve_pull_request_reviews": mGet(repo, "can_approve_pull_request_reviews"),
				"any_bypass_present_in_active": anyApplicable(applicable, func(a map[string]any) bool {
					return mBool(a, "any_bypass_present") && mStr(a, "enforcement") == "active"
				}),
				"_provenance": []any{map[string]any{"file": path.Join("10-normalize", "repos", repoName+".json")}},
			})
		}
	}

	return map[string]any{
		"chain":                "branch-coverage",
		"repo_branch_coverage": coverage,
	}, coverage
}

// A ruleset that omits target is a branch ruleset — "branch" is the API default.
func targetsBranch(rs map[string]any) bool {
	t := mGet(rs, "target")
	return t == nil || t == "branch"
}

func setList(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k, ok := range set {
		if ok {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

func anyApplicable(items []map[string]any, pred func(map[string]any) bool) bool {
	for _, it := range items {
		if pred(it) {
			return true
		}
	}
	return false
}

// correlate sees conditions as a decoded map while orgRepoGate takes the typed
// shape collect parses; round-tripping keeps one implementation of the gate
// rather than a second, subtly different copy.
func decodeConditions(conds map[string]any) rulesetConditions {
	var out rulesetConditions
	if b, err := json.Marshal(conds); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

// A run collected before 00-collect/branches existed yields an empty map, and
// deriveBranchCoverage falls back to the repo's default branch.
func loadBranchInventory(prior engine.PriorPhase) (map[string][]string, error) {
	recs, err := loadRecords(prior, "00-collect/branches")
	if err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(recs))
	for _, rec := range recs {
		data := mMap(rec, "data")
		if repo := mStr(data, "repo"); repo != "" {
			out[repo] = asStrings(mGet(data, "branches"))
		}
	}
	return out, nil
}

// CODEOWNERS is read off the repository's default branch, so the coverage it
// reports is only claimed for the branch that file governs; is_default_branch
// rides along so a rule can say so.
func deriveEffectiveRuleset(entries, rulesets, repos []map[string]any) (map[string]any, []map[string]any) {
	fullByID := map[string]map[string]any{}
	for _, rs := range rulesets {
		if rid := idKey(mGet(rs, "ruleset_id")); rid != "" {
			fullByID[rid] = rs
		}
	}
	codeowners := map[string]map[string]any{}
	for _, r := range repos {
		codeowners[mStr(r, "repo")] = r
	}

	effective := []map[string]any{}
	for _, entry := range entries {
		var active []map[string]any
		rulesetsByID := map[string]any{}
		applicable, _ := entry["applicable_rulesets"].([]map[string]any)
		for _, am := range applicable {
			rid := idKey(mGet(am, "ruleset_id"))
			full, ok := fullByID[rid]
			if !ok {
				continue
			}
			bypass := mMap(full, "bypass")
			rulesetsByID[rid] = map[string]any{
				"id":                    mGet(full, "ruleset_id"),
				"scope":                 mGet(full, "scope"),
				"enforcement":           mGet(full, "enforcement"),
				"rule_types":            listOrEmpty(full, "rule_types"),
				"requires_pull_request": mGet(full, "requires_pull_request"),
				"bypass_always":         listOrEmpty(bypass, "bypass_always"),
				"bypass_pull_request":   listOrEmpty(bypass, "bypass_pull_request_only"),
			}
			if mStr(full, "enforcement") == "active" {
				active = append(active, full)
			}
		}

		ruleTypesActive := map[string]bool{}
		bypassPerRule := map[string][]any{}
		requirePRWithBypass := false
		codeOwnerReview, dismissStale, lastPushApproval := false, false, false
		var effectiveApproving any
		var activeIDs []any
		for _, rs := range active {
			activeIDs = append(activeIDs, mGet(rs, "ruleset_id"))
			codeOwnerReview = codeOwnerReview || mGet(rs, "require_code_owner_review") == true
			dismissStale = dismissStale || mGet(rs, "dismiss_stale_reviews_on_push") == true
			lastPushApproval = lastPushApproval || mGet(rs, "require_last_push_approval") == true
			ruleTypes := asStrings(mGet(rs, "rule_types"))
			for _, rt := range ruleTypes {
				ruleTypesActive[rt] = true
			}
			bypass := mMap(rs, "bypass")
			if mBool(bypass, "any_bypass_present") {
				always := listOrEmpty(bypass, "bypass_always")
				for _, rt := range ruleTypes {
					bypassPerRule[rt] = append(bypassPerRule[rt], always...)
				}
				if mBool(rs, "requires_pull_request") {
					requirePRWithBypass = true
				}
			}
			if rac, ok := numericValue(mGet(rs, "required_approving_review_count")); ok {
				if cur, have := numericValue(effectiveApproving); !have || rac > cur {
					effectiveApproving = mGet(rs, "required_approving_review_count")
				}
			}
		}

		legacyBP := mMap(entry, "legacy_protection_summary")
		legacyRequiresPR := mGet(legacyBP, "required_pull_request_reviews")
		requiresPR := ruleTypesActive["pull_request"] || legacyRequiresPR == true
		controlUnknown := mBool(entry, "ref_unavailable") || mBool(entry, "legacy_protection_unknown")

		approvals := effectiveApproving
		if legacy, ok := numericValue(mGet(legacyBP, "required_reviews")); ok {
			if cur, have := numericValue(approvals); !have || legacy > cur {
				approvals = mGet(legacyBP, "required_reviews")
			}
		}
		approvalCount, _ := numericValue(approvals)

		gaps := setList(map[string]bool{
			"no_control":                 len(active) == 0 && !controlUnknown && mGet(entry, "legacy_protection_present") != true,
			"no_approvals_required":      requiresPR && approvalCount == 0,
			"single_approval_required":   requiresPR && approvalCount == 1,
			"no_status_checks":           !ruleTypesActive["required_status_checks"] && mGet(legacyBP, "required_status_checks") != true,
			"code_owner_review_absent":   !codeOwnerReview && mGet(legacyBP, "require_code_owner_reviews") != true,
			"stale_approvals_survive":    !dismissStale && mGet(legacyBP, "dismiss_stale_reviews") != true,
			"last_push_unapproved":       !lastPushApproval && mGet(legacyBP, "require_last_push_approval") != true,
			"actions_can_approve":        mGet(entry, "can_approve_pull_request_reviews") == true,
			"control_visibility_unknown": controlUnknown,
		})

		effective = append(effective, map[string]any{
			"_id":                                       mGet(entry, "_id"),
			"repo":                                      mGet(entry, "repo"),
			"branch":                                    mGet(entry, "branch"),
			"is_default_branch":                         mGet(entry, "is_default_branch"),
			"codeowners":                                mGet(codeowners[mStr(entry, "repo")], "codeowners"),
			"active_ruleset_ids":                        nonNilSlice(activeIDs),
			"active_ruleset_count":                      len(active),
			"rule_types_active":                         nonNilSlice(slices.Sorted(maps.Keys(ruleTypesActive))),
			"requires_pull_request_active":              ruleTypesActive["pull_request"],
			"requires_required_status_checks":           ruleTypesActive["required_status_checks"],
			"requires_non_fast_forward":                 ruleTypesActive["non_fast_forward"],
			"requires_branch_creation_only_admins":      ruleTypesActive["creation"],
			"restricts_deletions":                       ruleTypesActive["deletion"],
			"restricts_updates":                         ruleTypesActive["update"],
			"signed_commits_required":                   ruleTypesActive["required_signatures"],
			"rulesets_by_id":                            rulesetsByID,
			"bypass_present_per_rule":                   nonNilAnyMapList(bypassPerRule),
			"any_bypass_present_in_active":              mGet(entry, "any_bypass_present_in_active"),
			"require_pr_with_bypass":                    requirePRWithBypass,
			"effective_required_approving_review_count": approvals,
			"require_code_owner_review_active":          codeOwnerReview,
			"require_last_push_approval_active":         lastPushApproval,
			"dismiss_stale_reviews_on_push_active":      dismissStale,
			"legacy_protection_present":                 mGet(entry, "legacy_protection_present"),
			"legacy_required_reviews":                   mGet(entry, "legacy_required_reviews"),
			"legacy_requires_pull_request":              legacyRequiresPR,
			"legacy_enforce_admins":                     mGet(entry, "legacy_enforce_admins"),
			"legacy_lock_branch":                        mGet(legacyBP, "lock_branch"),
			"control_unknown":                           controlUnknown,
			"org_rulesets_unevaluable":                  listOrEmpty(entry, "org_rulesets_unevaluable"),
			"gaps":                                      gaps,
			"_provenance":                               mGet(entry, "_provenance"),
		})
	}

	return map[string]any{
		"chain":                "effective-ruleset",
		"effective_per_branch": effective,
	}, effective
}

type writePrincipal struct {
	Kind    string
	ID      string
	Name    string
	Via     string
	Perm    any
	IsAdmin bool
	UserID  string
	AppID   string
	TeamIDs []string
	Prov    []any
}

// deriveCapabilityEdges joins every write-capable principal against the branches
// effective-ruleset resolved a control state for, one record per (principal,
// branch). The branch-level gaps live on the effective record; the edge carries
// only what depends on the principal — which controls it circumvents and which
// routes onto the branch that leaves open.
func deriveCapabilityEdges(effective, principals, deployKeys, repos, apps []map[string]any, mintRepos map[string][]string) map[string]any {
	defaultBranch := map[string]string{}
	archived := map[string]bool{}
	// Whether a run's GITHUB_TOKEN can cast an approving review at all. Neither
	// half sits on a branch record, so no query over the graph can recover it.
	tokenCanApprove := map[string]bool{}
	for _, r := range repos {
		defaultBranch[mStr(r, "repo")] = mStr(r, "default_branch")
		archived[mStr(r, "repo")] = mBool(r, "archived")
		tokenCanApprove[mStr(r, "repo")] = mBool(r, "actions_enabled") &&
			mBool(r, "can_approve_pull_request_reviews")
	}

	teamsOf := map[string][]string{}
	for _, p := range principals {
		tid := idKey(mGet(p, "team_id"))
		if mStr(p, "kind") != "team" || tid == "" {
			continue
		}
		for _, m := range mList(p, "members") {
			mm, _ := m.(map[string]any)
			if login := mStr(mm, "login"); login != "" {
				teamsOf[login] = append(teamsOf[login], tid)
			}
		}
	}

	byRepo := map[string][]writePrincipal{}
	for _, p := range principals {
		kind := mStr(p, "kind")
		name := cmp.Or(mStr(p, "login"), mStr(p, "slug"))
		for _, g := range mList(p, "repo_grants") {
			gm, _ := g.(map[string]any)
			repo := mStr(gm, "repo")
			if repo == "" || !mBool(gm, "can_push") {
				continue
			}
			wp := writePrincipal{
				Kind:    kind,
				ID:      mStr(p, "_id"),
				Name:    name,
				Via:     "team_grant",
				Perm:    mGet(gm, "permission"),
				IsAdmin: mBool(gm, "is_admin"),
				TeamIDs: []string{idKey(mGet(p, "team_id"))},
				Prov:    listOrEmpty(p, "_provenance"),
			}
			if kind == "user" {
				wp.Via = "direct_collaborator"
				if mBool(gm, "via_outside_collaboration") {
					wp.Via = "outside_collaborator"
				}
				wp.UserID = idKey(mGet(p, "user_id"))
				wp.TeamIDs = teamsOf[name]
			}
			byRepo[repo] = append(byRepo[repo], wp)
		}
	}
	for _, k := range deployKeys {
		repo := mStr(k, "repo")
		if repo == "" || !mBool(k, "can_push") {
			continue
		}
		byRepo[repo] = append(byRepo[repo], writePrincipal{
			Kind: "deploy_key",
			ID:   mStr(k, "_id"),
			Name: cmp.Or(mStr(k, "title"), mStr(k, "fingerprint")),
			Via:  "deploy_key",
			Prov: listOrEmpty(k, "_provenance"),
		})
	}
	// repository_selection "all" IS the repo set. A "selected" installation needs
	// the installation-repositories list collect never fetches, so its scope is
	// narrowed to the repositories where a job actually mints its token — sound
	// without that call, and the only repositories where the grant is reachable
	// from a workflow anyway. administration:write is the app analog of repo
	// admin — it is the permission that removes the control itself.
	for _, a := range apps {
		perms := mMap(a, "permissions")
		if mStr(perms, "contents") != "write" {
			continue
		}
		slug := mStr(a, "app_slug")
		scope, via := mintRepos[slug], "app_token_mint"
		if mStr(a, "repository_selection") == "all" {
			scope, via = nil, "app_installation"
			for _, r := range repos {
				if repo := mStr(r, "repo"); repo != "" {
					scope = append(scope, repo)
				}
			}
		}
		wp := writePrincipal{
			Kind:    "app",
			ID:      mStr(a, "_id"),
			Name:    slug,
			Via:     via,
			IsAdmin: mStr(perms, "administration") == "write",
			AppID:   idKey(mGet(a, "app_id")),
			Prov:    listOrEmpty(a, "_provenance"),
		}
		for _, repo := range scope {
			byRepo[repo] = append(byRepo[repo], wp)
		}
	}

	edges := []map[string]any{}
	for _, eff := range effective {
		repo, branch := mStr(eff, "repo"), mStr(eff, "branch")
		active := activeRulesetDetail(eff)
		legacyLock := mGet(eff, "legacy_lock_branch") == true
		legacyRequiresPR := mGet(eff, "legacy_requires_pull_request") == true
		legacyExemptsAdmins := mGet(eff, "legacy_enforce_admins") == false
		// An org-scope ruleset survives repo admin; legacy protection and a
		// repo-scope ruleset do not.
		removable := mGet(eff, "legacy_protection_present") == true ||
			slices.ContainsFunc(active, func(rs map[string]any) bool { return mStr(rs, "scope") == "repo" })
		approvals, _ := numericValue(mGet(eff, "effective_required_approving_review_count"))

		for _, wp := range byRepo[repo] {
			matched := []any{}
			unproven := false
			directBlockers, directBypassed, anyModeBypassed := 0, 0, 0
			appliedDirect, appliedPR := map[string]bool{}, map[string]bool{}
			for _, rs := range active {
				types := asStrings(mGet(rs, "rule_types"))
				always, unresolvedAlways := capabilityBypassMatch(listOrEmpty(rs, "bypass_always"), wp)
				prOnly, unresolvedPR := capabilityBypassMatch(listOrEmpty(rs, "bypass_pull_request"), wp)
				matched = append(append(matched, always...), prOnly...)

				if slices.Contains(types, "pull_request") || slices.Contains(types, "update") {
					directBlockers++
					unproven = unproven || unresolvedAlways || unresolvedPR
					if len(always) > 0 {
						directBypassed++
					}
					if len(always) > 0 || len(prOnly) > 0 {
						anyModeBypassed++
					}
				}
				if len(always) > 0 {
					continue
				}
				for _, t := range types {
					appliedDirect[t] = true
					if len(prOnly) == 0 {
						appliedPR[t] = true
					}
				}
			}

			bypassAll := directBlockers > 0 && directBypassed == directBlockers
			bypassPR := directBlockers > 0 && anyModeBypassed == directBlockers && !bypassAll

			legacyBlocksDirect := legacyLock || (legacyRequiresPR && !(wp.IsAdmin && legacyExemptsAdmins))

			// An update rule alone locks the ref outright; paired with a pull_request
			// rule it only forces the merge through the PR.
			open := map[string]bool{
				"direct_push":  !archived[repo] && !legacyBlocksDirect && !appliedDirect["pull_request"] && !appliedDirect["update"],
				"pull_request": !archived[repo] && wp.Kind != "deploy_key" && !legacyLock && !(appliedPR["update"] && !appliedPR["pull_request"]),
			}
			// The PR route is only a control if an approval is actually demanded of
			// this principal, and the token's approval only counts when the gate
			// still binds them — a bypass holder was never gated in the first place.
			// Exactly one, not one-or-more: a repository has a single Actions
			// identity and GitHub refuses a self-review, so two required approvals
			// still cost the attacker a human.
			prGate := appliedPR["pull_request"] || (legacyRequiresPR && !(wp.IsAdmin && legacyExemptsAdmins))
			selfApproves := open["pull_request"] && prGate && approvals == 1 && tokenCanApprove[repo]

			routesOpen, routesBlocked := []string{}, []string{}
			for _, r := range []string{"direct_push", "pull_request"} {
				if open[r] {
					routesOpen = append(routesOpen, r)
				} else {
					routesBlocked = append(routesBlocked, r)
				}
			}

			edges = append(edges, map[string]any{
				"_id": fmt.Sprintf("cap__%s__%s__%s", repo, branch, wp.ID),

				"principal_kind": wp.Kind,
				"principal_id":   wp.ID,
				"principal_name": wp.Name,
				"write_via":      wp.Via,
				"permission":     wp.Perm,
				"is_admin":       wp.IsAdmin,

				"repo":              repo,
				"branch":            branch,
				"is_default_branch": branch == defaultBranch[repo],

				"circumvents": setList(map[string]bool{
					"bypass_always":                   bypassAll,
					"bypass_pull_request":             bypassPR,
					"bypass_unproven":                 unproven,
					"admin_can_remove_control":        wp.IsAdmin && removable,
					"admin_can_unarchive":             wp.IsAdmin && archived[repo],
					"approval_count_self_satisfiable": selfApproves,
				}),
				"routes_open":           routesOpen,
				"routes_blocked":        routesBlocked,
				"bypass_actors_matched": matched,

				// Carried for the rule that reads this chain, not for the graph edge:
				// emitCanLandCode copies an explicit field list and takes neither.
				"code_owner_review_active":       mGet(eff, "require_code_owner_review_active"),
				"codeowners_covers_ci_execution": mBool(mMap(eff, "codeowners"), "covers_ci_execution"),

				"_provenance": append(slices.Clone(wp.Prov), listOrEmpty(eff, "_provenance")...),
			})
		}
	}

	return map[string]any{
		"chain":      "capability-edges",
		"edges":      edges,
		"edge_count": len(edges),
	}
}

func activeRulesetDetail(eff map[string]any) []map[string]any {
	byID := mMap(eff, "rulesets_by_id")
	out := make([]map[string]any, 0, len(byID))
	for _, id := range listOrEmpty(eff, "active_ruleset_ids") {
		if rs := mMap(byID, idKey(id)); rs != nil {
			out = append(out, rs)
		}
	}
	return out
}

// A RepositoryRole actor names a role the principal's own grant already states,
// so it resolves for a user or a team; OrganizationAdmin does not, because
// nothing collected maps it back to a login, and a human facing one is reported
// unresolved rather than guessed — the gate is unproven, not proven absent.
// Neither role reaches a non-human principal: a deploy key and an app
// installation hold no repository role, and an app is named by app_id through the
// Integration actor instead.
func capabilityBypassMatch(actors []any, wp writePrincipal) ([]any, bool) {
	matched := []any{}
	unresolved := false
	human := wp.Kind == "user" || wp.Kind == "team"
	for _, a := range actors {
		am, _ := a.(map[string]any)
		aid := idKey(mGet(am, "actor_id"))
		switch mStr(am, "actor_type") {
		case "Team":
			if aid != "" && slices.Contains(wp.TeamIDs, aid) {
				matched = append(matched, am)
			}
		case "User":
			if aid != "" && aid == wp.UserID {
				matched = append(matched, am)
			}
		case "RepositoryRole":
			actorRank, principalRank := baseRoleRank(aid), principalRoleRank(wp)
			switch {
			case !human:
			case actorRank == 0 || principalRank == 0:
				unresolved = true
			case principalRank >= actorRank:
				matched = append(matched, am)
			}
		case "DeployKey":
			if wp.Kind == "deploy_key" {
				matched = append(matched, am)
			}
		case "Integration":
			if aid != "" && aid == wp.AppID {
				matched = append(matched, am)
			}
		default:
			unresolved = unresolved || human
		}
	}
	return matched, unresolved
}

var baseRoleRanks = map[string]int{
	"read": 1, "pull": 1,
	"triage": 2,
	"write":  3, "push": 3,
	"maintain": 4,
	"admin":    5,
}

// Base repository role ids 1..5 ascend read, triage, write, maintain, admin, and
// a role bypass covers every role at or above it — an admin bypasses a
// triage-scoped actor. The ordering is GitHub's; nothing collected maps an id to
// a role name, so it cannot be confirmed against a run. An id outside 1..5 is a
// custom role and stays unresolved rather than ranked.
func baseRoleRank(actorID string) int {
	switch actorID {
	case "1", "2", "3", "4", "5":
		return int(actorID[0] - '0')
	}
	return 0
}

func principalRoleRank(wp writePrincipal) int {
	if wp.IsAdmin {
		return 5
	}
	perm, _ := wp.Perm.(string)
	return baseRoleRanks[strings.ToLower(perm)]
}

// A generic minter takes the App identity as an app-id input. An action that
// authenticates as its own published App has no such input — its slug is fixed
// by the action itself, and the token it hands the job carries that App's
// installation permissions whatever the workflow declared.
var minterActions = []struct{ prefix, appIDKey, appSlug string }{
	{prefix: "actions/create-github-app-token", appIDKey: "app-id"},
	{prefix: "tibdex/github-app-token", appIDKey: "app_id"},
	{prefix: "getsentry/action-github-app-token", appIDKey: "app_id"},
	{prefix: "peter-evans/create-github-app-token", appIDKey: "app_id"},
	{prefix: "anthropics/claude-code-action", appSlug: "claude"},
}

// The second return maps an app slug to the repositories a job mints its token
// in; it is the only repository scope a "selected" installation has, since the
// installation's repository list is never collected.
func deriveAppMintable(jobs, apps []map[string]any) (map[string]any, map[string][]string) {
	appsByID, appsBySlug := map[string]map[string]any{}, map[string]map[string]any{}
	for _, rec := range apps {
		if aid := coerceAppID(mGet(rec, "app_id")); aid != "" {
			appsByID[aid] = rec
		}
		if slug := mStr(rec, "app_slug"); slug != "" {
			appsBySlug[slug] = rec
		}
	}

	mintRepos := map[string][]string{}
	mints := []map[string]any{}
	for _, job := range jobs {
		for _, h := range jobAppMinterHits(job) {
			appIDValue := coerceAppID(h["app_id_value"])
			var resolved map[string]any
			switch slug, _ := h["app_slug"].(string); {
			case slug != "":
				// The out-of-band token only exists where that App is installed;
				// without the installation the action falls back to whatever
				// token the workflow handed it, which is not a mint.
				if resolved = appsBySlug[slug]; resolved == nil {
					continue
				}
			case appIDValue != "":
				resolved = appsByID[appIDValue]
			}
			if resolved != nil {
				slug := mStr(resolved, "app_slug")
				if repo := mStr(job, "repo"); repo != "" && !slices.Contains(mintRepos[slug], repo) {
					mintRepos[slug] = append(mintRepos[slug], repo)
				}
			}
			var appField any
			if resolved != nil {
				appField = map[string]any{
					"slug":               mGet(resolved, "app_slug"),
					"app_id":             mGet(resolved, "app_id"),
					"permissions":        mGet(resolved, "permissions"),
					"broad_admin_writes": listOrEmpty(resolved, "broad_admin_writes"),
					"write_permissions":  listOrEmpty(resolved, "write_permissions"),
				}
			}
			ref, _ := h["ref"].(string)
			mints = append(mints, map[string]any{
				"_id": fmt.Sprintf("mint__%s__%s", mStr(job, "_id"), ref),
				"minter": map[string]any{
					"_id":                   mGet(job, "_id"),
					"repo":                  mGet(job, "repo"),
					"workflow_filename":     mGet(job, "workflow_filename"),
					"job_id":                mGet(job, "job_id"),
					"triggers":              listOrEmpty(job, "triggers"),
					"trigger_class_summary": mGet(job, "trigger_class_summary"),
					"_provenance":           mGet(job, "_provenance"),
				},
				"action":          h["action"],
				"action_ref":      h["ref"],
				"app_id_literal":  nilIfBlank(appIDValue),
				"app_id_resolved": resolved != nil,
				"app":             appField,
			})
		}
	}

	return map[string]any{
		"chain":        "app-mintable",
		"mints":        mints,
		"minter_count": len(mints),
	}, mintRepos
}

func jobAppMinterHits(job map[string]any) []map[string]any {
	var hits []map[string]any
	for _, s := range mList(job, "steps") {
		step, _ := s.(map[string]any)
		uses, _ := mGet(step, "uses").(string)
		if uses == "" {
			continue
		}
		for _, ma := range minterActions {
			if uses == ma.prefix || strings.HasPrefix(uses, ma.prefix+"@") {
				hits = append(hits, map[string]any{
					"action":       ma.prefix,
					"ref":          uses,
					"app_id_value": mGet(mMap(step, "with"), ma.appIDKey),
					"app_slug":     ma.appSlug,
					"step_name":    mGet(step, "name"),
				})
			}
		}
	}
	return hits
}

func coerceAppID(v any) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", v))
}

func nilIfBlank(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func deriveEnvDeployments(jobs, envs []map[string]any) map[string]any {
	envByKey := map[[2]string]map[string]any{}
	for _, env := range envs {
		envByKey[[2]string{mStr(env, "repo"), mStr(env, "name")}] = env
	}

	deploys := []map[string]any{}
	for _, job := range jobs {
		env := mMap(job, "environment")
		envName := mStr(env, "name")
		if envName == "" {
			continue
		}
		envRecord := envByKey[[2]string{mStr(job, "repo"), envName}]
		present := envRecord != nil
		envOut := any(envRecord)
		if !present {
			envOut = map[string]any{}
		}
		noReviewers := !present || len(mList(envRecord, "reviewers_required")) == 0
		noBranchPolicy := !present || mStr(mMap(envRecord, "deployment_branch_policy"), "type") == ""
		adminsBypass := present && mGet(envRecord, "can_admins_bypass") == true
		deploys = append(deploys, map[string]any{
			"_id":                  fmt.Sprintf("deploy__%s__%s", mStr(job, "_id"), envName),
			"job":                  envJobSummary(job),
			"env_name":             envName,
			"env_record_present":   present,
			"env":                  envOut,
			"env_no_reviewers":     noReviewers,
			"env_no_branch_policy": noBranchPolicy,
			"env_admins_bypass":    adminsBypass,
		})
	}

	return map[string]any{
		"chain":        "env-deployments",
		"deploys":      deploys,
		"deploy_count": len(deploys),
	}
}

func envJobSummary(job map[string]any) map[string]any {
	return map[string]any{
		"_id":                            mGet(job, "_id"),
		"repo":                           mGet(job, "repo"),
		"workflow_filename":              mGet(job, "workflow_filename"),
		"job_id":                         mGet(job, "job_id"),
		"triggers":                       listOrEmpty(job, "triggers"),
		"trigger_class_summary":          mGet(job, "trigger_class_summary"),
		"reads_any_secret":               mGet(job, "reads_any_secret"),
		"secrets_referenced":             listOrEmpty(job, "secrets_referenced"),
		"environment_chosen_dynamically": mGet(job, "environment_chosen_dynamically"),
		"_provenance":                    mGet(job, "_provenance"),
	}
}

func deriveDeployKeyReuse(files []engine.PhaseFile) map[string]any {
	byPubKey := map[string][]map[string]any{}
	order := []string{}
	for _, f := range files {
		var rec map[string]any
		if err := json.Unmarshal(f.Data, &rec); err != nil {
			continue
		}
		data := mMap(rec, "data")
		repo := mGet(data, "repo")
		for _, k := range mList(data, "deploy_keys") {
			key, _ := k.(map[string]any)
			pub, _ := mGet(key, "key").(string)
			if pub == "" {
				continue
			}
			body := pub
			if parts := strings.SplitN(strings.TrimSpace(pub), " ", 2); len(parts) > 0 {
				body = parts[len(parts)-1]
			}
			if _, seen := byPubKey[body]; !seen {
				order = append(order, body)
			}
			byPubKey[body] = append(byPubKey[body], map[string]any{
				"repo":       repo,
				"key_id":     mGet(key, "id"),
				"title":      mGet(key, "title"),
				"read_only":  mGet(key, "read_only"),
				"created_at": mGet(key, "created_at"),
			})
		}
	}

	reused := []map[string]any{}
	for _, pub := range order {
		hits := byPubKey[pub]
		if len(hits) < 2 {
			continue
		}
		anyWrite := false
		repos := []any{}
		for _, h := range hits {
			if h["read_only"] == false {
				anyWrite = true
			}
			repos = append(repos, h["repo"])
		}
		reused = append(reused, map[string]any{
			"_id":               "deploykey_reuse__" + safePrefix(pub, 16),
			"repo_count":        len(hits),
			"repos":             repos,
			"any_write_capable": anyWrite,
			"instances":         nonNilSlice(hits),
		})
	}

	return map[string]any{
		"chain":       "deploy-key-reuse",
		"reused_keys": reused,
		"reuse_count": len(reused),
	}
}

func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func deriveIndices(jobs []map[string]any, cp engine.CurrentPhase) error {
	byTrigger := newOrderedIndex()
	bySecret := newOrderedIndex()
	byEnvironment := newOrderedIndex()
	byRunnerGroup := newOrderedIndex()
	byActionRef := newOrderedIndex()
	byActionClass := newOrderedIndex()

	for _, job := range jobs {
		jid := mStr(job, "_id")
		for _, tr := range asStrings(mGet(job, "triggers")) {
			byTrigger.append(tr, jid)
		}
		for _, s := range mList(job, "secrets_referenced") {
			sec, _ := s.(map[string]any)
			scope := mStr(sec, "scope")
			if scope == "" {
				scope = "unknown"
			}
			name := mStr(sec, "name")
			if name == "" {
				name = "?"
			}
			bySecretKey := scope + "__" + name
			bySecret.append(bySecretKey, map[string]any{"job": jid, "step_index": mGet(sec, "step_index")})
		}
		env := mMap(job, "environment")
		if env != nil && mStr(env, "name") != "" {
			byEnvironment.append(mStr(job, "repo")+"__"+mStr(env, "name"), jid)
		}
		if rg := mGet(job, "runner_group"); rg != nil {
			byRunnerGroup.append(fmt.Sprintf("%v", rg), jid)
		}
		for _, r := range mList(job, "action_refs") {
			ref, _ := r.(map[string]any)
			if uses := mStr(ref, "uses"); uses != "" {
				byActionRef.append(uses, jid)
			}
		}
		for _, s := range mList(job, "steps") {
			step, _ := s.(map[string]any)
			cls := mStr(mMap(step, "classifiers"), "sink_class")
			if cls != "" {
				byActionClass.appendUnique(cls, jid)
			}
		}
	}

	indices := []struct {
		name string
		idx  *orderedIndex
	}{
		{"by-trigger", byTrigger},
		{"by-secret", bySecret},
		{"by-environment", byEnvironment},
		{"by-runner-group", byRunnerGroup},
		{"by-action-ref", byActionRef},
		{"by-action-class", byActionClass},
	}
	for _, ix := range indices {
		for _, key := range ix.idx.order {
			out := map[string]any{
				"index": ix.name,
				"key":   key,
				"items": ix.idx.items[key],
			}
			if err := cp.Write(indexPath(ix.name, safeIndexFilename(key)), out); err != nil {
				return err
			}
		}
	}
	return nil
}

type orderedIndex struct {
	order []string
	items map[string][]any
}

func newOrderedIndex() *orderedIndex {
	return &orderedIndex{items: map[string][]any{}}
}

func (o *orderedIndex) append(key string, val any) {
	if _, ok := o.items[key]; !ok {
		o.order = append(o.order, key)
	}
	o.items[key] = append(o.items[key], val)
}

func (o *orderedIndex) appendUnique(key string, val any) {
	if _, ok := o.items[key]; !ok {
		o.order = append(o.order, key)
	}
	for _, existing := range o.items[key] {
		if existing == val {
			return
		}
	}
	o.items[key] = append(o.items[key], val)
}

func safeIndexFilename(s string) string {
	s = strings.ReplaceAll(s, "/", "__")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, " ", "_")
	return s
}

func numericValue(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

func idKey(v any) string {
	switch n := v.(type) {
	case nil:
		return ""
	case float64:
		return fmt.Sprintf("%v", int64(n))
	case string:
		return n
	default:
		return fmt.Sprintf("%v", n)
	}
}

func nonNilMapList(m map[string][]map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = nonNilSlice(v)
	}
	return out
}

func nonNilAnyMapList(m map[string][]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = nonNilSlice(v)
	}
	return out
}
