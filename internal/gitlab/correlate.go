package gitlab

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// correlate loads the normalized corpus back as generic maps and writes the nine
// chains/<join>.json files the chain rules read. Each file is one JSON object
// carrying its tuples under the exact for_each key the rules iterate (an unset or
// mismatched key silently iterates nothing), with each tuple nesting the
// participant records under their role prefix (producer./consumer./source./…) so
// a rule's chain_of.where resolves role.field by nested map access.
//
// A join that fails to load its inputs is a phase-fatal error; per-tuple issues
// (a job whose project record is missing, a malformed member map) are skipped so
// one bad subject never sinks the run.
func correlate(ctx context.Context, prior engine.PriorPhase, cp engine.CurrentPhase, org string, timer *engine.PhaseTimer) error {
	jobs, err := loadRecords(prior, "10-normalize/jobs")
	if err != nil {
		return fmt.Errorf("correlate: load jobs: %w", err)
	}
	projects, err := loadRecords(prior, "10-normalize/projects")
	if err != nil {
		return fmt.Errorf("correlate: load projects: %w", err)
	}
	groups, err := loadRecords(prior, "10-normalize/groups")
	if err != nil {
		return fmt.Errorf("correlate: load groups: %w", err)
	}
	instances, err := loadRecords(prior, "10-normalize/instance")
	if err != nil {
		return fmt.Errorf("correlate: load instance: %w", err)
	}
	runners, err := loadRecords(prior, "10-normalize/runners")
	if err != nil {
		return fmt.Errorf("correlate: load runners: %w", err)
	}
	agents, err := loadRecords(prior, "10-normalize/agents")
	if err != nil {
		return fmt.Errorf("correlate: load agents: %w", err)
	}
	credentials, err := loadRecords(prior, "10-normalize/credentials")
	if err != nil {
		return fmt.Errorf("correlate: load credentials: %w", err)
	}

	c := &correlator{
		org:       org,
		jobs:      jobs,
		projects:  indexByID(projects),
		groups:    indexByID(groups),
		instance:  firstOrEmpty(instances),
		runners:   runners,
		agents:    agents,
		creds:     credentials,
		projList:  projects,
		groupList: groups,
	}

	for _, w := range []struct {
		join string
		fn   func() map[string]any
	}{
		{"job-token-allowlist", c.jobTokenAllowlist},
		{"protected-var-reachability", c.protectedVarReachability},
		{"dotenv-flow", c.dotenvFlow},
		{"cache-keyspace", c.cacheKeyspace},
		{"cross-project-artifact", c.crossProjectArtifact},
		{"deploy-key-reuse", c.deployKeyReuse},
		{"agent-ci-access", c.agentCIAccess},
		{"runner-reachability", c.runnerReachability},
		{"group-runner-reachability", c.groupRunnerReachability},
	} {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := emit(cp, timer, engine.NormalizeGLChain(w.join), w.fn()); err != nil {
			return fmt.Errorf("correlate: write %s: %w", w.join, err)
		}
	}
	return nil
}

type correlator struct {
	org       string
	jobs      []map[string]any
	projects  map[string]map[string]any
	groups    map[string]map[string]any
	instance  map[string]any
	runners   []map[string]any
	agents    []map[string]any
	creds     []map[string]any
	projList  []map[string]any
	groupList []map[string]any
}

func indexByID(recs []map[string]any) map[string]map[string]any {
	out := make(map[string]map[string]any, len(recs))
	for _, r := range recs {
		out[mStr(r, "_id")] = r
	}
	return out
}

func firstOrEmpty(recs []map[string]any) map[string]any {
	if len(recs) > 0 {
		return recs[0]
	}
	return map[string]any{}
}

// jobProject splits a job _id ("project/path:jobname") into its project path.
func jobProject(job map[string]any) string {
	id := mStr(job, "_id")
	i := strings.LastIndex(id, ":")
	if i < 0 {
		return ""
	}
	return id[:i]
}

// ---- JOIN 1: job-token-allowlist (for_each: edges) — heaviest, x6 rules ----
//
// A source project whose CI uses another project's job token (needs:project: or
// a CI_JOB_TOKEN script use) is the token-bearing side; the target project's
// inbound allowlist is what admits it. The edge carries the source posture, the
// target allowlist, and the triggerer role so cat-01/04/09 rules read literals.
func (c *correlator) jobTokenAllowlist() map[string]any {
	edges := []map[string]any{}
	for _, job := range c.jobs {
		srcPath := jobProject(job)
		src := c.projects[srcPath]
		if src == nil {
			continue
		}
		targets := jobTokenTargets(job)
		if len(targets) == 0 {
			continue
		}
		srcPart := map[string]any{
			"_id":                                  srcPath,
			"inbound_job_token_scope_enabled":      mBool(src, "inbound_job_token_scope_enabled"),
			"source_ci_writable_by_lower_trust":    mGet(job, "source_ci_writable_by_lower_trust"),
			"job_token_push_allowed":               mBool(src, "job_token_push_allowed"),
			"job_token_cross_project_push_allowed": mBool(src, "job_token_cross_project_push_allowed"),
			"job_token_cross_project_use":          mStr(job, "job_token_cross_project_use"),
		}
		triggerer := c.triggererRole(src)
		for _, tgtPath := range targets {
			tgt := c.projects[tgtPath]
			allowlist := map[string]any{"mode": "open", "entries": []any{}, "fine_grained": false}
			tgtInbound := false
			var tgtVisibility any
			if tgt != nil {
				if al := mMap(tgt, "job_token_allowlist"); al != nil {
					allowlist = al
				}
				tgtInbound = mBool(tgt, "inbound_job_token_scope_enabled")
				tgtVisibility = mGet(tgt, "visibility")
			}
			admits := allowlistAdmits(allowlist, srcPath)
			// trusts_source is the admit flag the rules read at
			// target.job_token_allowlist.trusts_source; kept also at
			// target.source_in_allowlist for older references.
			allowlist = withTrustsSource(allowlist, admits)
			edges = append(edges, map[string]any{
				"_id":    fmt.Sprintf("jtoken__%s__%s", srcPath, tgtPath),
				"source": srcPart,
				"target": map[string]any{
					"_id":                                    tgtPath,
					"present":                                tgt != nil,
					"job_token_allowlist":                    allowlist,
					"inbound_job_token_scope_enabled":        tgtInbound,
					"source_in_allowlist":                    admits,
					"visibility":                             tgtVisibility,
					"uses_managed_terraform_state":           tgt != nil && mBool(tgt, "uses_managed_terraform_state"),
					"job_token_push_allowed":                 tgt != nil && mBool(tgt, "job_token_push_allowed"),
					"job_token_cross_project_push_allowed":   tgt != nil && mBool(tgt, "job_token_cross_project_push_allowed"),
					"developer_writable_protected_branch":    tgt != nil && mBool(tgt, "developer_writable_protected_branch"),
					"has_developer_pushable_unprotected_ref": tgt != nil && mBool(tgt, "has_developer_pushable_unprotected_ref"),
				},
				"triggerer": triggerer,
			})
		}
	}
	return map[string]any{"chain": "job-token-allowlist", "edges": edges, "edge_count": len(edges)}
}

// jobTokenTargets is the set of other projects a job reaches with its job token:
// explicit needs:project: targets, plus (when the script drives CI_JOB_TOKEN at
// another project we cannot name statically) the source project itself as a
// self-referential marker so the token-posture rules still see an edge.
func jobTokenTargets(job map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, raw := range mList(job, "cross_project_needs") {
		add(mStr(entMap(raw), "project"))
	}
	if mStr(job, "job_token_cross_project_use") != "none" {
		add(jobProject(job))
	}
	sort.Strings(out)
	return out
}

// withTrustsSource returns a shallow copy of the allowlist carrying trusts_source
// so the shared target-project record map is never mutated in place.
func withTrustsSource(allowlist map[string]any, admits bool) map[string]any {
	out := make(map[string]any, len(allowlist)+1)
	for k, v := range allowlist {
		out[k] = v
	}
	out["trusts_source"] = admits
	return out
}

func allowlistAdmits(allowlist map[string]any, srcPath string) bool {
	switch mStr(allowlist, "mode") {
	case "disabled", "open":
		return true
	}
	for _, e := range mList(allowlist, "entries") {
		if entStr(e) == srcPath {
			return true
		}
	}
	return false
}

// triggererRole summarizes the identity that can start the source pipeline. The
// access_level is the highest role held by any member; is_bot / is_schedule_owner
// reflect whether a bot member or a schedule owner is present.
func (c *correlator) triggererRole(src map[string]any) map[string]any {
	var maxLevel int64
	bot := false
	for _, raw := range mList(src, "members") {
		m := entMap(raw)
		if lvl := entInt64(m["access_level"]); lvl > maxLevel {
			maxLevel = lvl
		}
		if entBool(m["is_bot"]) {
			bot = true
		}
	}
	return map[string]any{
		"access_level":      maxLevel,
		"is_bot":            bot,
		"is_schedule_owner": mBool(src, "is_schedule_owner"),
	}
}

// ---- JOIN 2: protected-var-reachability (for_each: reachable_vars) ----
//
// Self-resolving join (x4 rules): its output tuple pairs a protected variable
// with a ref (protected branch / tag) and a member that can push to it, BUT the
// normalizer resolves the two correlations the DSL cannot express — (a) the ref's
// owning project lies in the variable's inheritance scope, and (b) the member
// belongs to the same project as the ref. Only tuples where both hold are
// emitted, so the rules carry only literal-valued predicates.
func (c *correlator) protectedVarReachability() map[string]any {
	tuples := []map[string]any{}

	// A project-scoped variable is reachable only from that project's own
	// protected refs and members (both correlations trivially satisfied).
	for _, p := range c.projList {
		for _, raw := range mList(p, "cicd_variables") {
			v := entMap(raw)
			if !entBool(v["protected"]) {
				continue
			}
			c.emitVarTuples(&tuples, p, v, "project", c.varScopeGroup(mStr(p, "_id")))
		}
	}
	// A group-scoped variable inherits to every descendant project (correlation
	// (a) = descendant membership); each descendant's own refs+members satisfy (b).
	for _, g := range c.groupList {
		gpath := mStr(g, "_id")
		for _, raw := range mList(g, "cicd_variables") {
			v := entMap(raw)
			if !entBool(v["protected"]) {
				continue
			}
			for _, dp := range c.descendantProjects(g) {
				if p := c.projects[dp]; p != nil {
					c.emitVarTuples(&tuples, p, v, "group:"+gpath, g)
				}
			}
		}
	}
	// An instance-scoped CI/CD variable (self-managed /admin/ci/variables) inherits
	// to every project on the instance (correlation (a) = any project); each
	// project's own refs+members satisfy (b).
	for _, raw := range mList(c.instance, "cicd_variables") {
		v := entMap(raw)
		if !entBool(v["protected"]) {
			continue
		}
		for _, p := range c.projList {
			c.emitVarTuples(&tuples, p, v, "instance", map[string]any{})
		}
	}
	return map[string]any{"chain": "protected-var-reachability", "reachable_vars": tuples, "var_count": len(tuples)}
}

// emitVarTuples pairs a reachable protected variable with each (protected ref ×
// member) of the project it reaches. scopeTag disambiguates project vs group
// origin in the tuple _id; group is the owning group participant (or empty).
func (c *correlator) emitVarTuples(tuples *[]map[string]any, p, v map[string]any, scopeTag string, group map[string]any) {
	proj := mStr(p, "_id")
	members := mList(p, "members")
	scopeLevel := "project"
	switch {
	case strings.HasPrefix(scopeTag, "group"):
		scopeLevel = "group"
	case scopeTag == "instance":
		scopeLevel = "instance"
	}
	provHere := []provenance{{"project_path": proj}}
	pair := func(refKind string, ref map[string]any) {
		refPart := withProvenance(ref, provHere)
		for _, mraw := range members {
			m := entMap(mraw)
			tup := map[string]any{
				"_id":     fmt.Sprintf("pvr__%s__%s__%s:%s__m:%d", scopeTag, mStr(v, "key"), refKind, entStr(ref["pattern"]), entInt64(m["access_level"])),
				"var":     varParticipant(v, scopeLevel, proj),
				"branch":  map[string]any{},
				"tag":     map[string]any{},
				"group":   group,
				"member":  withProvenance(memberParticipant(m), provHere),
				"project": proj,
			}
			tup[refKind] = refPart
			*tuples = append(*tuples, tup)
		}
	}
	for _, braw := range mList(p, "protected_branches") {
		pair("branch", entMap(braw))
	}
	for _, traw := range mList(p, "protected_tags") {
		pair("tag", entMap(traw))
	}
}

// withProvenance returns a shallow copy of a participant carrying _provenance so
// evidence templates that read {project_path} resolve; the source record map is
// never mutated in place.
func withProvenance(m map[string]any, prov []provenance) map[string]any {
	out := make(map[string]any, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	out["_provenance"] = prov
	return out
}

func varParticipant(v map[string]any, scopeLevel, proj string) map[string]any {
	return map[string]any{
		"key":               mStr(v, "key"),
		"protected":         mBool(v, "protected"),
		"masked":            mBool(v, "masked"),
		"environment_scope": mStr(v, "environment_scope"),
		"scope_level":       scopeLevel,
		"project":           proj,
	}
}

func memberParticipant(m map[string]any) map[string]any {
	return map[string]any{
		"access_level": entInt64(m["access_level"]),
		"is_bot":       entBool(m["is_bot"]),
	}
}

// varScopeGroup surfaces the owning group participant for a project-scoped
// variable (empty when the project has no parent group in the corpus).
func (c *correlator) varScopeGroup(proj string) map[string]any {
	if g := c.groups[parentGroup(proj)]; g != nil {
		return g
	}
	return map[string]any{}
}

func (c *correlator) descendantProjects(g map[string]any) []string {
	var out []string
	for _, raw := range mList(g, "descendants") {
		if s := entStr(raw); s != "" {
			if _, isProject := c.projects[s]; isProject {
				out = append(out, s)
			}
		}
	}
	return out
}

// ---- JOIN 3: dotenv-flow (for_each: edges) — x3 rules ----
//
// A dotenv artifact produced by one job flows into every consuming job in the
// same project (dotenv is inherited via the pipeline's needs/dependencies graph).
func (c *correlator) dotenvFlow() map[string]any {
	byProject := map[string][]map[string]any{}
	for _, job := range c.jobs {
		byProject[jobProject(job)] = append(byProject[jobProject(job)], job)
	}
	edges := []map[string]any{}
	for _, jobs := range byProject {
		var producers, consumers []map[string]any
		for _, j := range jobs {
			if mBool(j, "produces_dotenv") {
				producers = append(producers, j)
			}
			if mBool(j, "consumes_dotenv") {
				consumers = append(consumers, j)
			}
		}
		for _, prod := range producers {
			for _, cons := range consumers {
				if mStr(prod, "_id") == mStr(cons, "_id") {
					continue
				}
				edges = append(edges, map[string]any{
					"_id":      fmt.Sprintf("dotenv__%s__%s", mStr(prod, "_id"), mStr(cons, "_id")),
					"producer": dotenvProducer(prod),
					"consumer": dotenvConsumer(cons),
				})
			}
		}
	}
	sortByID(edges)
	return map[string]any{"chain": "dotenv-flow", "edges": edges, "edge_count": len(edges)}
}

func dotenvProducer(j map[string]any) map[string]any {
	return map[string]any{
		"_id":                                  mStr(j, "_id"),
		"produces_dotenv":                      mBool(j, "produces_dotenv"),
		"runs_on_untrusted_ref":                mBool(j, "runs_on_untrusted_ref"),
		"runs_on_protected_ref":                mBool(j, "runs_on_protected_ref"),
		"dotenv_content_attacker_influenced":   mBool(j, "dotenv_content_attacker_influenced"),
		"dotenv_content_from_untrusted_source": mBool(j, "dotenv_content_from_untrusted_source"),
		"triggers":                             listOrEmptyGL(j, "triggers"),
	}
}

func dotenvConsumer(j map[string]any) map[string]any {
	return map[string]any{
		"_id":                              mStr(j, "_id"),
		"consumes_dotenv":                  mBool(j, "consumes_dotenv"),
		"dotenv_inheritance_unnarrowed":    mBool(j, "dotenv_inheritance_unnarrowed"),
		"image_from_variable":              mGet(j, "image_from_variable"),
		"inherited_var_in_exec_sink":       mBool(j, "inherited_var_in_exec_sink"),
		"dotenv_key_collides_declared_var": mBool(j, "dotenv_key_collides_declared_var"),
		"colliding_var_in_exec_sink":       mBool(j, "colliding_var_in_exec_sink"),
		"cross_project_needs":              listOrEmptyGL(j, "cross_project_needs"),
		"runs_on_protected_ref":            mBool(j, "runs_on_protected_ref"),
		"protected_ref_gate":               mStr(j, "protected_ref_gate"),
		"triggers":                         listOrEmptyGL(j, "triggers"),
	}
}

// ---- JOIN 4: cache-keyspace (for_each: prefix_overlaps) — x2 rules ----
//
// Jobs sharing a static cache-key prefix can poison each other's cache across a
// trust boundary. Group cache entries by literal key prefix; emit an overlap
// where ≥2 distinct jobs share it.
func (c *correlator) cacheKeyspace() map[string]any {
	byPrefix := map[string][]map[string]any{}
	for _, job := range c.jobs {
		for _, raw := range mList(job, "cache") {
			cache := entMap(raw)
			prefix := cacheKeyPrefix(mStr(cache, "key"))
			if prefix == "" {
				continue
			}
			byPrefix[prefix] = append(byPrefix[prefix], map[string]any{"job": job, "cache": cache})
		}
	}
	prefixes := make([]string, 0, len(byPrefix))
	for p := range byPrefix {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)

	overlaps := []map[string]any{}
	for _, prefix := range prefixes {
		participants := byPrefix[prefix]
		ids := map[string]bool{}
		for _, part := range participants {
			ids[mStr(mMap(part, "job"), "_id")] = true
		}
		if len(ids) < 2 {
			continue
		}
		writers := []map[string]any{}
		readers := []map[string]any{}
		var producer, consumer map[string]any
		untrustedWriter := false
		for _, part := range participants {
			job := mMap(part, "job")
			cache := mMap(part, "cache")
			p := cacheParticipant(job, cache)
			if cachePolicyWritesGL(cache) {
				writers = append(writers, p)
				if mBool(job, "runs_on_untrusted_ref") {
					untrustedWriter = true
					if producer == nil {
						producer = p
					}
				}
			} else {
				readers = append(readers, p)
			}
			if consumer == nil && mStr(job, "protected_ref_gate") == "strong" {
				consumer = p
			}
		}
		overlaps = append(overlaps, map[string]any{
			"_id":                   "cache_overlap__" + prefix,
			"key_prefix":            prefix,
			"producer":              firstOrEmptyMap(producer),
			"consumer":              firstOrEmptyMap(consumer),
			"writer":                firstParticipant(writers),
			"reader":                firstParticipant(readers),
			"writers":               nonNilList(writers),
			"readers":               nonNilList(readers),
			"writer_count":          len(writers),
			"reader_count":          len(readers),
			"low_trust_participant": untrustedWriter,
		})
	}
	return map[string]any{"chain": "cache-keyspace", "prefix_overlaps": overlaps, "overlap_count": len(overlaps)}
}

func cacheParticipant(job, cache map[string]any) map[string]any {
	return map[string]any{
		"_id":                               mStr(job, "_id"),
		"runs_on_untrusted_ref":             mBool(job, "runs_on_untrusted_ref"),
		"protected_ref_gate":                mStr(job, "protected_ref_gate"),
		"cache_paths_executable":            mBool(job, "cache_paths_executable"),
		"cache_key_files_attacker_writable": mBool(job, "cache_key_files_attacker_writable"),
		"cache_key_static_cross_boundary":   mBool(job, "cache_key_static_cross_boundary"),
		"cache_policy_writes":               mBool(job, "cache_policy_writes"),
		"cache_separation_enabled":          mBool(job, "cache_separation_enabled"),
		"triggers":                          listOrEmptyGL(job, "triggers"),
		"cache":                             cache,
	}
}

func firstOrEmptyMap(m map[string]any) map[string]any {
	if m != nil {
		return m
	}
	return map[string]any{}
}

func firstParticipant(list []map[string]any) map[string]any {
	if len(list) > 0 {
		return list[0]
	}
	return map[string]any{}
}

// cacheKeyPrefix extracts the literal (non-interpolated) prefix of a cache key.
// A per-ref key ($CI_COMMIT_REF_SLUG) or a files:-derived key has no shared
// static prefix and cannot collide across a boundary — return "".
func cacheKeyPrefix(key string) string {
	if key == "" {
		return ""
	}
	if i := strings.IndexByte(key, '$'); i >= 0 {
		key = key[:i]
	}
	return strings.Trim(key, "-_/")
}

func cachePolicyWritesGL(cache map[string]any) bool {
	return mStr(cache, "policy") != "pull"
}

// ---- JOIN 5: cross-project-artifact (for_each: edges) — x1 ----
//
// A consumer job with needs:project: reaches into a producer project; the edge
// carries the producer's trust posture so cat-02/09 rules see whether the
// fetched artifact comes from a lower-trust, developer-reachable source.
func (c *correlator) crossProjectArtifact() map[string]any {
	edges := []map[string]any{}
	for _, job := range c.jobs {
		needs := mList(job, "cross_project_needs")
		if len(needs) == 0 {
			continue
		}
		consumer := crossArtifactConsumer(job)
		consumerPath := jobProject(job)
		for _, raw := range needs {
			need := entMap(raw)
			prodPath := entStr(need["project"])
			prod := c.projects[prodPath]
			producer := map[string]any{"_id": prodPath, "present": prod != nil}
			if prod != nil {
				devPushable := mBool(prod, "has_developer_pushable_unprotected_ref") || mBool(prod, "developer_writable_protected_branch")
				producer["visibility"] = mGet(prod, "visibility")
				producer["has_developer_reachable_secret"] = mBool(prod, "has_developer_reachable_secret")
				producer["has_developer_pushable_unprotected_ref"] = mBool(prod, "has_developer_pushable_unprotected_ref")
				producer["developer_writable_protected_branch"] = mBool(prod, "developer_writable_protected_branch")
				producer["source_ref_developer_pushable"] = devPushable
				producer["on_consumer_job_token_allowlist"] = allowlistAdmits(mMap(prod, "job_token_allowlist"), consumerPath)
			}
			edges = append(edges, map[string]any{
				"_id":      fmt.Sprintf("xpart__%s__%s", mStr(job, "_id"), prodPath),
				"consumer": consumer,
				"producer": producer,
				"need":     need,
			})
		}
	}
	return map[string]any{"chain": "cross-project-artifact", "edges": edges, "edge_count": len(edges)}
}

func crossArtifactConsumer(job map[string]any) map[string]any {
	return map[string]any{
		"_id":                                        mStr(job, "_id"),
		"cross_project_needs":                        listOrEmptyGL(job, "cross_project_needs"),
		"fetches_cross_project_artifact":             mBool(job, "fetches_cross_project_artifact"),
		"executes_fetched_artifact":                  mBool(job, "executes_fetched_artifact"),
		"artifact_integrity_checked":                 mBool(job, "artifact_integrity_checked"),
		"child_pipeline_from_cross_project_artifact": mBool(job, "child_pipeline_from_cross_project_artifact"),
		"artifact_source_ref_mutable":                mBool(job, "artifact_source_ref_mutable"),
		"runs_on_protected_ref":                      mBool(job, "runs_on_protected_ref"),
		"triggers":                                   listOrEmptyGL(job, "triggers"),
	}
}

// ---- JOIN 6: deploy-key-reuse (for_each: reused_keys) — x1 ----
//
// The same deploy-key fingerprint added to ≥2 projects spans a trust boundary:
// a push using the key on the low-trust project inherits access to the others.
func (c *correlator) deployKeyReuse() map[string]any {
	type inst struct {
		project string
		rec     map[string]any
	}
	byFP := map[string][]inst{}
	var order []string
	for _, cred := range c.creds {
		if mStr(cred, "kind") != "deploy_key" {
			continue
		}
		fp, _ := mGet(cred, "deploy_key_fingerprint").(string)
		if fp == "" {
			continue
		}
		if _, seen := byFP[fp]; !seen {
			order = append(order, fp)
		}
		byFP[fp] = append(byFP[fp], inst{project: credProject(cred), rec: cred})
	}

	reused := []map[string]any{}
	for _, fp := range order {
		hits := byFP[fp]
		projSet := map[string]bool{}
		for _, h := range hits {
			projSet[h.project] = true
		}
		if len(projSet) < 2 {
			continue
		}
		anyWrite := false
		creatorHasAccess := false
		srcUnprotectedVar := false
		tgtHoldsProtected := false
		instances := []any{}
		projects := []any{}
		for _, h := range hits {
			if mBool(h.rec, "can_push") {
				anyWrite = true
			}
			if mBool(h.rec, "creator_has_target_protected_access") {
				creatorHasAccess = true
			}
			if mBool(h.rec, "in_unprotected_variable") {
				srcUnprotectedVar = true
			}
			holds := false
			if p := c.projects[h.project]; p != nil {
				holds = mBool(p, "holds_protected_resources")
			}
			if holds {
				tgtHoldsProtected = true
			}
			instances = append(instances, map[string]any{
				"project":                             h.project,
				"can_push":                            mBool(h.rec, "can_push"),
				"deploy_key_fingerprint":              mGet(h.rec, "deploy_key_fingerprint"),
				"access_level":                        mGet(h.rec, "access_level"),
				"in_unprotected_variable":             mBool(h.rec, "in_unprotected_variable"),
				"creator_has_target_protected_access": mBool(h.rec, "creator_has_target_protected_access"),
				"holds_protected_resources":           holds,
			})
			projects = append(projects, h.project)
		}
		reused = append(reused, map[string]any{
			"_id": "deploykey_reuse__" + safePrefixGL(fp, 16),
			"key": map[string]any{
				"kind":                                "deploy_key",
				"deploy_key_fingerprint":              fp,
				"can_push":                            anyWrite,
				"creator_has_target_protected_access": creatorHasAccess,
			},
			"source":            map[string]any{"in_unprotected_variable": srcUnprotectedVar},
			"target":            map[string]any{"holds_protected_resources": tgtHoldsProtected},
			"project_count":     len(projSet),
			"projects":          projects,
			"any_write_capable": anyWrite,
			"instances":         instances,
		})
	}
	return map[string]any{"chain": "deploy-key-reuse", "reused_keys": reused, "reuse_count": len(reused)}
}

// credProject reads the project path off the credential's _provenance scope
// ("project:<path>").
func credProject(cred map[string]any) string {
	for _, raw := range mList(cred, "_provenance") {
		if s := entStr(entMap(raw)["scope"]); strings.HasPrefix(s, "project:") {
			return strings.TrimPrefix(s, "project:")
		}
	}
	return ""
}

// ---- JOIN 7: agent-ci-access (for_each: grants) — x1 ----
//
// A GitLab agent's ci_access grant lets pipelines in the target project(s)
// impersonate the agent against the cluster; the grant tuple carries the agent's
// guard (protected_branches_only, environments_filter) and each target project's
// protected-branch posture so cat-12/15 rules resolve reachability.
func (c *correlator) agentCIAccess() map[string]any {
	grants := []map[string]any{}
	for _, agent := range c.agents {
		agentPart := agentParticipant(agent)
		targets := mList(agent, "ci_access_targets")
		if len(targets) == 0 {
			// implicit_config_project: the agent's own project is the only target.
			targets = []any{agentProject(agent)}
		}
		for _, raw := range targets {
			tgtPath := entStr(raw)
			if tgtPath == "" {
				continue
			}
			project := map[string]any{"_id": tgtPath, "present": false, "protected_branches": []any{}}
			if p := c.projects[tgtPath]; p != nil {
				project = map[string]any{
					"_id":                                    tgtPath,
					"present":                                true,
					"protected_branches":                     listOrEmptyGL(p, "protected_branches"),
					"developer_writable_protected_branch":    mBool(p, "developer_writable_protected_branch"),
					"has_developer_pushable_unprotected_ref": mBool(p, "has_developer_pushable_unprotected_ref"),
					"default_branch_protected":               mGet(p, "default_branch_protected"),
					"auto_devops_enabled":                    mBool(p, "auto_devops_enabled"),
					"has_cicd_config":                        mBool(p, "has_cicd_config"),
					"has_reachable_runner":                   mBool(p, "has_reachable_runner"),
				}
			}
			grants = append(grants, map[string]any{
				"_id":     fmt.Sprintf("agentci__%s__%s", mStr(agent, "_id"), tgtPath),
				"agent":   agentPart,
				"project": project,
			})
		}
	}
	return map[string]any{"chain": "agent-ci-access", "grants": grants, "grant_count": len(grants)}
}

func agentParticipant(agent map[string]any) map[string]any {
	return map[string]any{
		"_id":                          mStr(agent, "_id"),
		"ci_access_scope":              mStr(agent, "ci_access_scope"),
		"ci_access_targets":            listOrEmptyGL(agent, "ci_access_targets"),
		"protected_branches_only":      mBool(agent, "protected_branches_only"),
		"environments_filter":          listOrEmptyGL(agent, "environments_filter"),
		"environments_filter_wildcard": mBool(agent, "environments_filter_wildcard"),
		"impersonation":                mGet(agent, "impersonation"),
		"default_permissions":          mBool(agent, "default_permissions"),
	}
}

func agentProject(agent map[string]any) string {
	id := mStr(agent, "_id")
	if i := strings.LastIndex(id, "/"); i >= 0 {
		return id[:i]
	}
	return id
}

// ---- JOIN 8: runner-reachability (for_each: reachable_runners) — x1 ----
//
// An instance/shared runner is reachable by any account when the instance permits
// open project creation; the tuple pairs the runner posture with the instance
// governance so a cat-12 rule reads both as literals.
func (c *correlator) runnerReachability() map[string]any {
	instancePart := map[string]any{
		"_id":                    "instance",
		"open_project_creation":  mGet(c.instance, "open_project_creation"),
		"signup_enabled":         mGet(c.instance, "signup_enabled"),
		"shared_runners_enabled": mGet(c.instance, "shared_runners_enabled"),
	}
	tuples := []map[string]any{}
	for _, r := range c.runners {
		if mStr(r, "runner_type") != "instance_type" && !mBool(r, "is_shared") {
			continue
		}
		tuples = append(tuples, map[string]any{
			"_id":      "runreach__" + mStr(r, "_id"),
			"runner":   runnerParticipant(r),
			"instance": instancePart,
		})
	}
	return map[string]any{"chain": "runner-reachability", "reachable_runners": tuples, "runner_count": len(tuples)}
}

// ---- JOIN 9: group-runner-reachability (for_each: reachable_runners) — x1 ----
//
// A group-scoped runner is reachable by any account that can create a project in
// the owning group (governance inherited to all descendants); the tuple pairs the
// runner with the group's group_open_project_creation posture.
func (c *correlator) groupRunnerReachability() map[string]any {
	tuples := []map[string]any{}
	for _, r := range c.runners {
		if mStr(r, "runner_type") != "group_type" {
			continue
		}
		gpath := runnerScopeGroup(r)
		group := map[string]any{"_id": gpath, "present": false}
		if g := c.groups[gpath]; g != nil {
			group = map[string]any{
				"_id":                         gpath,
				"present":                     true,
				"group_open_project_creation": mBool(g, "group_open_project_creation"),
				"project_creation_role":       mGet(g, "project_creation_role"),
			}
		}
		tuples = append(tuples, map[string]any{
			"_id":    "grpreach__" + mStr(r, "_id"),
			"runner": runnerParticipant(r),
			"group":  group,
		})
	}
	return map[string]any{"chain": "group-runner-reachability", "reachable_runners": tuples, "runner_count": len(tuples)}
}

func runnerParticipant(r map[string]any) map[string]any {
	return map[string]any{
		"_id":           mStr(r, "_id"),
		"runner_type":   mStr(r, "runner_type"),
		"is_shared":     mBool(r, "is_shared"),
		"run_untagged":  mBool(r, "run_untagged"),
		"ref_protected": mBool(r, "ref_protected"),
		"self_managed":  mBool(r, "self_managed"),
		"locked":        mBool(r, "locked"),
		"tags":          listOrEmptyGL(r, "tags"),
		"projects":      listOrEmptyGL(r, "projects"),
	}
}

// runnerScopeGroup reads the owning group path off the runner's _provenance
// scope ("group:<path>").
func runnerScopeGroup(r map[string]any) string {
	for _, raw := range mList(r, "_provenance") {
		if s := entStr(entMap(raw)["scope"]); strings.HasPrefix(s, "group:") {
			return strings.TrimPrefix(s, "group:")
		}
	}
	return ""
}

// ---- shared helpers ----

func listOrEmptyGL(m map[string]any, key string) []any {
	if v, ok := mGet(m, key).([]any); ok {
		return v
	}
	return []any{}
}

func nonNilList(list []map[string]any) []any {
	out := make([]any, 0, len(list))
	for _, e := range list {
		out = append(out, e)
	}
	return out
}

func sortByID(edges []map[string]any) {
	sort.Slice(edges, func(i, j int) bool { return mStr(edges[i], "_id") < mStr(edges[j], "_id") })
}

func safePrefixGL(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
