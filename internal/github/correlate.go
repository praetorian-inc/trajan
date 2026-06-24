package github

import (
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
	deployKeyFiles, err := prior.IterJSON("00-collect/deploy-keys")
	if err != nil {
		return fmt.Errorf("correlate: load deploy-keys: %w", err)
	}

	coverage, coverageEntries := deriveBranchCoverage(repos, rulesets)

	writers := []func() error{
		func() error { return cp.Write(chainPath("reusable-callgraph"), deriveReusableCallgraph(jobs)) },
		func() error { return cp.Write(chainPath("trigger-channels"), deriveTriggerChannels(jobs)) },
		func() error { return cp.Write(chainPath("cache-keyspace"), deriveCacheKeyspace(jobs)) },
		func() error { return cp.Write(chainPath("branch-coverage"), coverage) },
		func() error {
			return cp.Write(chainPath("effective-ruleset"), deriveEffectiveRuleset(coverageEntries, rulesets))
		},
		func() error { return cp.Write(chainPath("app-mintable"), deriveAppMintable(jobs, apps)) },
		func() error { return cp.Write(chainPath("env-deployments"), deriveEnvDeployments(jobs, envs)) },
		func() error { return cp.Write(chainPath("deploy-key-reuse"), deriveDeployKeyReuse(deployKeyFiles)) },
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
					"uses":        usesVal,
					"owner":       mGet(callee, "owner"),
					"repo":        mGet(callee, "repo"),
					"path":        mGet(callee, "path"),
					"ref":         ref,
					"ref_kind":    kind,
					"ref_mutable": mutable,
					"is_local":    isLocal,
					"inputs":      inputs,
					"secrets":     secrets,
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
	writersByRepoName := map[[2]string][]map[string]any{}
	for _, j := range jobs {
		for _, name := range artifactNames(j, "artifact_writes") {
			key := [2]string{mStr(j, "repo"), name}
			writersByRepoName[key] = append(writersByRepoName[key], j)
		}
	}
	for _, j := range jobs {
		for _, name := range artifactNames(j, "artifact_reads") {
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

var cacheExprRe = regexp.MustCompile(`(?s)\$\{\{.*?\}\}`)
var cacheChunkRe = regexp.MustCompile(`[-_/]+`)

func literalPrefix(key string) string {
	cleaned := cacheExprRe.ReplaceAllString(key, "")
	var out []string
	for _, c := range cacheChunkRe.Split(cleaned, -1) {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		out = append(out, c)
		if len(out) >= 2 {
			break
		}
	}
	return strings.Join(out, "/")
}

func deriveCacheKeyspace(jobs []map[string]any) map[string]any {
	writesByPrefix := map[string][]map[string]any{}
	readsByPrefix := map[string][]map[string]any{}

	collect := func(job map[string]any, opKey string, dst map[string][]map[string]any) {
		for _, c := range mList(job, opKey) {
			var key, scope string
			var restore any
			if cm, ok := c.(map[string]any); ok {
				key, _ = (mGet(cm, "key_template")).(string)
				if key == "" {
					key, _ = mGet(cm, "key").(string)
				}
				scope, _ = mGet(cm, "scope").(string)
				restore = mGet(cm, "restore_keys")
			} else if s, ok := c.(string); ok {
				key = s
			}
			prefix := literalPrefix(key)
			if prefix == "" && strings.HasPrefix(scope, "scope-prefix:") {
				prefix = strings.SplitN(scope, ":", 2)[1]
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

	prefixes := map[string]bool{}
	for p := range writesByPrefix {
		prefixes[p] = true
	}
	for p := range readsByPrefix {
		prefixes[p] = true
	}
	sortedPrefixes := slices.Sorted(maps.Keys(prefixes))

	prefixOverlaps := []map[string]any{}
	for _, prefix := range sortedPrefixes {
		ws := writesByPrefix[prefix]
		rs := readsByPrefix[prefix]
		allJobs := map[string]map[string]any{}
		order := []string{}
		add := func(entries []map[string]any) {
			for _, e := range entries {
				jb := e["job"].(map[string]any)
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
			"_id":                   "cache_overlap__" + prefix,
			"key_prefix":            prefix,
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

func deriveBranchCoverage(repos, rulesets []map[string]any) (map[string]any, []map[string]any) {
	var orgRulesets []map[string]any
	for _, rs := range rulesets {
		if mStr(rs, "scope") == "org" && !mBool(rs, "_empty") && !mBool(rs, "_unavailable") {
			orgRulesets = append(orgRulesets, rs)
		}
	}

	coverage := []map[string]any{}
	for _, repo := range repos {
		repoName := mStr(repo, "repo")
		if repoName == "" {
			repoName = mStr(repo, "_id")
		}
		branch := mStr(repo, "default_branch")
		if branch == "" {
			branch = "main"
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
			if mBool(rs, "_empty") {
				continue
			}
			repoRulesets = append(repoRulesets, rs)
		}

		applicable := []map[string]any{}
		for _, rs := range append(append([]map[string]any{}, orgRulesets...), repoRulesets...) {
			conds := mMap(rs, "conditions")
			refConds := mMap(conds, "ref_name")
			refIncludes := asStrings(mGet(refConds, "include"))
			refExcludes := asStrings(mGet(refConds, "exclude"))
			if !refPatternMatches(branch, refIncludes) {
				continue
			}
			if len(refExcludes) > 0 && refPatternMatches(branch, refExcludes) {
				continue
			}
			if mStr(rs, "scope") == "org" {
				repoConds := mMap(conds, "repository_name")
				rInc := asStrings(mGet(repoConds, "include"))
				rExc := asStrings(mGet(repoConds, "exclude"))
				if len(rInc) > 0 && !(slices.Contains(rInc, "~ALL") || refPatternMatches(repoName, rInc)) {
					continue
				}
				if len(rExc) > 0 && refPatternMatches(repoName, rExc) {
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

		legacyBP := mMap(repo, "default_branch_protection_summary")
		coverage = append(coverage, map[string]any{
			"_id":                 repoName + "__" + branch,
			"repo":                repoName,
			"branch":              branch,
			"ref_unavailable":     unavailable,
			"applicable_rulesets": applicable,
			"applicable_count":    len(applicable),
			"has_active_ruleset":  anyApplicable(applicable, func(a map[string]any) bool { return mStr(a, "enforcement") == "active" }),
			"has_pr_required_ruleset": anyApplicable(applicable, func(a map[string]any) bool {
				return mBool(a, "requires_pull_request") && mStr(a, "enforcement") == "active"
			}),
			"legacy_protection_present": mGet(repo, "default_branch_protection_present"),
			"legacy_required_reviews":   mGet(legacyBP, "required_reviews"),
			"legacy_enforce_admins":     mGet(legacyBP, "enforce_admins"),
			"any_bypass_present_in_active": anyApplicable(applicable, func(a map[string]any) bool {
				return mBool(a, "any_bypass_present") && mStr(a, "enforcement") == "active"
			}),
			"_provenance": []any{map[string]any{"file": path.Join("10-normalize", "repos", repoName+".json")}},
		})
	}

	return map[string]any{
		"chain":                "branch-coverage",
		"repo_branch_coverage": coverage,
	}, coverage
}

func anyApplicable(items []map[string]any, pred func(map[string]any) bool) bool {
	for _, it := range items {
		if pred(it) {
			return true
		}
	}
	return false
}

func refPatternMatches(branch string, patterns []string) bool {
	for _, p := range patterns {
		if p == "~ALL" || p == "~DEFAULT_BRANCH" || p == branch {
			return true
		}
		if fnmatchCase(branch, p) {
			return true
		}
		if strings.HasPrefix(p, "refs/heads/") && fnmatchCase("refs/heads/"+branch, p) {
			return true
		}
	}
	return false
}

func deriveEffectiveRuleset(entries, rulesets []map[string]any) map[string]any {
	fullByID := map[string]map[string]any{}
	for _, rs := range rulesets {
		if rid := idKey(mGet(rs, "ruleset_id")); rid != "" {
			fullByID[rid] = rs
		}
	}

	effective := []map[string]any{}
	for _, entry := range entries {
		var active []map[string]any
		applicable, _ := entry["applicable_rulesets"].([]map[string]any)
		for _, am := range applicable {
			rid := idKey(mGet(am, "ruleset_id"))
			if full, ok := fullByID[rid]; ok && mStr(full, "enforcement") == "active" {
				active = append(active, full)
			}
		}

		ruleTypesActive := map[string]bool{}
		bypassPerRule := map[string][]any{}
		requirePRWithBypass := false
		var effectiveApproving any
		var activeIDs []any
		for _, rs := range active {
			activeIDs = append(activeIDs, mGet(rs, "ruleset_id"))
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

		effective = append(effective, map[string]any{
			"_id":                                       mGet(entry, "_id"),
			"repo":                                      mGet(entry, "repo"),
			"branch":                                    mGet(entry, "branch"),
			"active_ruleset_ids":                        nonNilSlice(activeIDs),
			"active_ruleset_count":                      len(active),
			"rule_types_active":                         slices.Sorted(maps.Keys(ruleTypesActive)),
			"requires_pull_request_active":              ruleTypesActive["pull_request"],
			"requires_required_status_checks":           ruleTypesActive["required_status_checks"],
			"requires_non_fast_forward":                 ruleTypesActive["non_fast_forward"],
			"requires_branch_creation_only_admins":      ruleTypesActive["creation"],
			"restricts_deletions":                       ruleTypesActive["deletion"],
			"signed_commits_required":                   ruleTypesActive["required_signatures"],
			"bypass_present_per_rule":                   nonNilAnyMapList(bypassPerRule),
			"any_bypass_present_in_active":              mGet(entry, "any_bypass_present_in_active"),
			"require_pr_with_bypass":                    requirePRWithBypass,
			"min_required_approving_review_count":       effectiveApproving,
			"effective_required_approving_review_count": effectiveApproving,
			"legacy_protection_present":                 mGet(entry, "legacy_protection_present"),
			"_provenance":                               mGet(entry, "_provenance"),
		})
	}

	return map[string]any{
		"chain":                "effective-ruleset",
		"effective_per_branch": effective,
	}
}

var minterActions = [][2]string{
	{"actions/create-github-app-token", "app-id"},
	{"tibdex/github-app-token", "app_id"},
	{"getsentry/action-github-app-token", "app_id"},
	{"peter-evans/create-github-app-token", "app_id"},
}

func deriveAppMintable(jobs, apps []map[string]any) map[string]any {
	appsByID := map[string]map[string]any{}
	for _, rec := range apps {
		if aid := coerceAppID(mGet(rec, "app_id")); aid != "" {
			appsByID[aid] = rec
		}
	}

	mints := []map[string]any{}
	for _, job := range jobs {
		for _, h := range jobAppMinterHits(job) {
			appIDValue := coerceAppID(h["app_id_value"])
			var resolved map[string]any
			if appIDValue != "" {
				resolved = appsByID[appIDValue]
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
	}
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
			prefix, appIDKey := ma[0], ma[1]
			if uses == prefix || strings.HasPrefix(uses, prefix+"@") {
				hits = append(hits, map[string]any{
					"action":       prefix,
					"ref":          uses,
					"app_id_value": mGet(mMap(step, "with"), appIDKey),
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

// fnmatchCase replicates Python fnmatch.fnmatchcase: whole-string anchored,
// case-sensitive shell wildcards.
func fnmatchCase(name, pattern string) bool {
	re, err := regexp.Compile("^" + fnmatchToRegex(pattern) + "$")
	if err != nil {
		return false
	}
	return re.MatchString(name)
}

func fnmatchToRegex(pattern string) string {
	var b strings.Builder
	for i := 0; i < len(pattern); {
		c := pattern[i]
		switch c {
		case '*':
			b.WriteString(".*")
			i++
		case '?':
			b.WriteString(".")
			i++
		case '[':
			j := i + 1
			if j < len(pattern) && (pattern[j] == '!' || pattern[j] == '^') {
				j++
			}
			if j < len(pattern) && pattern[j] == ']' {
				j++
			}
			for j < len(pattern) && pattern[j] != ']' {
				j++
			}
			if j >= len(pattern) {
				b.WriteString(`\[`)
				i++
				continue
			}
			set := pattern[i+1 : j]
			b.WriteByte('[')
			if strings.HasPrefix(set, "!") {
				b.WriteByte('^')
				set = set[1:]
			}
			b.WriteString(strings.ReplaceAll(set, `\`, `\\`))
			b.WriteByte(']')
			i = j + 1
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
			i++
		}
	}
	return b.String()
}
