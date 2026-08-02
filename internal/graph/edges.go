package graph

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
)

func edgeID(t EdgeType, from, to string) string {
	return string(t) + "|" + esc(from) + "|" + esc(to)
}

// endpoint is an identity tuple, not a node: the edge writer never emits nodes.
// Keys outside IdentityKey are dropped on construction, so a caller may supply
// scope_key unconditionally and let the schema decide whether it identifies.
type endpoint struct {
	label NodeLabel
	key   map[string]string
	id    string
}

func nd(l NodeLabel, kv ...string) endpoint {
	want := IdentityKey(l)
	e := endpoint{label: l, key: make(map[string]string, len(want))}
	for i := 0; i+1 < len(kv); i += 2 {
		if slices.Contains(want, kv[i]) {
			e.key[kv[i]] = kv[i+1]
		}
	}
	if e.complete() {
		e.id = nodeID(l, e.key)
	}
	return e
}

// resolved names a node the node writer already emitted and whose identity the
// edge writer cannot rebuild — a Secret, whose canonical scope_key is only
// recoverable from the secret record, not from the job reference that cites it.
func resolved(l NodeLabel, id string) endpoint { return endpoint{label: l, id: id} }

func (e endpoint) complete() bool {
	if e.id != "" {
		return true
	}
	want := IdentityKey(e.label)
	if len(want) == 0 {
		return false
	}
	for _, k := range want {
		if e.key[k] == "" {
			return false
		}
	}
	return true
}

type edge struct {
	ID         string         `json:"id"`
	Type       EdgeType       `json:"type"`
	From       string         `json:"from"`
	To         string         `json:"to"`
	FromLabel  NodeLabel      `json:"from_label"`
	ToLabel    NodeLabel      `json:"to_label"`
	Properties map[string]any `json:"properties"`
	Findings   []findingRef   `json:"findings"`
}

type edgeSet struct {
	byID    map[string]*edge
	unbuilt map[EdgeType]int
	illegal map[string]int
}

func newEdgeSet() *edgeSet {
	return &edgeSet{byID: map[string]*edge{}, unbuilt: map[EdgeType]int{}, illegal: map[string]int{}}
}

// add merges into the existing edge when (type, from, to) repeats: parallel
// edges of one type between one pair do not exist in this model. An endpoint
// with an incomplete identity is dropped and counted rather than invented,
// because every consumer of this graph asks reachability questions.
func (s *edgeSet) add(t EdgeType, from, to endpoint, props map[string]any) {
	if !from.complete() || !to.complete() {
		s.unbuilt[t]++
		return
	}
	if !ValidEdge(t, from.label, to.label) {
		s.illegal[fmt.Sprintf("%s{%s,%s}", t, from.label, to.label)]++
		return
	}
	id := edgeID(t, from.id, to.id)
	e := s.byID[id]
	if e == nil {
		e = &edge{
			ID: id, Type: t, From: from.id, To: to.id,
			FromLabel: from.label, ToLabel: to.label,
			Properties: map[string]any{}, Findings: []findingRef{},
		}
		s.byID[id] = e
	}
	for _, k := range slices.Sorted(maps.Keys(props)) {
		v := props[k]
		old, seen := e.Properties[k]
		if !seen {
			e.Properties[k] = v
			continue
		}
		ao, aok := old.([]any)
		an, nok := v.([]any)
		if aok && nok {
			e.Properties[k] = unionArray(ao, an)
		}
	}
	e.Properties["graph_id"] = id
}

func (s *edgeSet) miss(t EdgeType, n int) { s.unbuilt[t] += n }

func (s *edgeSet) all() []edge {
	out := make([]edge, 0, len(s.byID))
	for _, e := range s.byID {
		out = append(out, *e)
	}
	slices.SortFunc(out, func(a, b edge) int {
		return cmp.Or(cmp.Compare(a.Type, b.Type), cmp.Compare(a.From, b.From), cmp.Compare(a.To, b.To))
	})
	return out
}

func (s *edgeSet) byType() map[EdgeType]int {
	out := make(map[EdgeType]int, len(edgeEndpoints))
	for _, t := range EdgeTypes() {
		out[t] = 0
	}
	for _, e := range s.byID {
		out[e.Type]++
	}
	return out
}

// err reports rejected endpoint pairs. A pair the schema forbids is a builder
// bug, not a data gap, so the caller aborts the phase on it.
func (s *edgeSet) err() error {
	if len(s.illegal) == 0 {
		return nil
	}
	return fmt.Errorf("%d illegal endpoint pair(s): %v", len(s.illegal), s.illegal)
}

func buildEdges(ctx context.Context, c *corpus, n *nodeSet) (*edgeSet, error) {
	s := newEdgeSet()
	for _, emit := range []func(*corpus, *nodeSet, *edgeSet){
		emitContains, emitMemberOf, emitHasAccess, emitInstalledOn, emitGoverns,
		emitProtectedBy, emitCanBypass, emitCanLandCode, emitCanApprove,
		emitUsesAction, emitSecretReads, emitArtifactIO, emitCacheIO, emitNeeds,
		emitCalls, emitTriggers, emitTargets, emitDefines, emitDeployableFrom,
		emitCanAssume,
		emitUnbuildable,
	} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		emit(c, n, s)
	}
	return s, s.err()
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// list returns a JSON array field as a non-nil slice: an empty capability list
// is a fact consumers key on and must serialize as [], never be omitted.
func list(v any) []any {
	a, _ := v.([]any)
	if a == nil {
		return []any{}
	}
	return a
}

func source(rel string) map[string]any { return map[string]any{"_source": []any{rel}} }

func jobEndpoint(c *corpus, f map[string]any) endpoint {
	return nd(Job,
		"repo", c.full(str(f["repo"])),
		"workflow", workflowPath(str(f["workflow_filename"])),
		"job_id", str(f["job_id"]))
}

func workflowEndpoint(c *corpus, f map[string]any) endpoint {
	return nd(Workflow, "repo", c.full(str(f["repo"])), "path", workflowPath(str(f["workflow_filename"])))
}

func repoEndpoint(c *corpus, repo string) endpoint {
	return nd(Repository, "full_name", c.full(repo))
}

func branchEndpoint(c *corpus, repo, name string) endpoint {
	return nd(Branch, "repo", c.full(repo), "name", name)
}

func envEndpoint(c *corpus, repo, name string) endpoint {
	return nd(Environment, "repo", c.full(repo), "name", name)
}

func rulesetEndpoint(f map[string]any, idField string) endpoint {
	return nd(Ruleset, "scope", str(f["scope"]), "id", decimal(f[idField]))
}

func emitCanAssume(c *corpus, _ *nodeSet, s *edgeSet) {
	for _, r := range c.dirs["jobs"] {
		for _, cr := range list(r.fields["cloud_roles"]) {
			m := obj(cr)
			id := str(m["identifier"])
			if id == "" {
				s.miss(CanAssume, 1)
				continue
			}
			s.add(CanAssume, jobEndpoint(c, r.fields), nd(CloudRole, "identifier", id),
				source(r.rel))
		}
	}
}

func emitContains(c *corpus, _ *nodeSet, s *edgeSet) {
	org := nd(Organization, "login", c.org)
	for _, r := range c.dirs["repos"] {
		s.add(Contains, org, repoEndpoint(c, str(r.fields["repo"])), source(r.rel))
	}
	for _, r := range c.dirs["principals"] {
		if str(r.fields["kind"]) == "team" {
			s.add(Contains, org, nd(Team, "org", c.org, "slug", str(r.fields["slug"])), source(r.rel))
		}
	}
	for _, r := range c.dirs["apps"] {
		s.add(Contains, org, nd(App, "app_slug", str(r.fields["app_slug"])), source(r.rel))
	}
	for _, r := range c.dirs["runner-groups"] {
		s.add(Contains, org, nd(RunnerGroup, "org", str(r.fields["org"]), "id", decimal(r.fields["group_id"])), source(r.rel))
	}
	for _, r := range c.dirs["rulesets"] {
		if truthy(r.fields["_empty"]) {
			continue
		}
		rs := rulesetEndpoint(r.fields, "ruleset_id")
		if str(r.fields["scope"]) == "org" {
			s.add(Contains, org, rs, source(r.rel))
		} else {
			s.add(Contains, repoEndpoint(c, str(r.fields["repo"])), rs, source(r.rel))
		}
	}
	for _, r := range c.dirs["org"] {
		for _, e := range objects(r.fields["org_actions_secrets"]) {
			s.add(Contains, org, nd(Secret, "scope", "org", "scope_key", c.org, "name", str(e["name"])),
				source(r.rel+"#org_actions_secrets"))
		}
	}
	for _, e := range c.chainArray("effective-ruleset", "effective_per_branch") {
		s.add(Contains, repoEndpoint(c, str(e["repo"])), branchEndpoint(c, str(e["repo"]), str(e["branch"])),
			source(c.chainSource("effective-ruleset", "effective_per_branch")))
	}
	for _, r := range c.dirs["jobs"] {
		wf := workflowEndpoint(c, r.fields)
		s.add(Contains, repoEndpoint(c, str(r.fields["repo"])), wf, source(r.rel))
		s.add(Contains, wf, jobEndpoint(c, r.fields), source(r.rel))
	}
	for _, r := range c.dirs["environments"] {
		s.add(Contains, repoEndpoint(c, str(r.fields["repo"])), envEndpoint(c, str(r.fields["repo"]), str(r.fields["name"])), source(r.rel))
	}
	for _, r := range c.dirs["secrets"] {
		sec := nd(Secret, "scope", str(r.fields["scope"]), "scope_key", c.secretScopeKey(r.fields), "name", str(r.fields["name"]))
		switch str(r.fields["scope"]) {
		case "org":
			s.add(Contains, org, sec, source(r.rel))
		case "repo":
			s.add(Contains, repoEndpoint(c, str(r.fields["repo"])), sec, source(r.rel))
		case "environment":
			s.add(Contains, envEndpoint(c, str(r.fields["repo"]), str(r.fields["environment"])), sec, source(r.rel))
		}
	}
}

func emitMemberOf(c *corpus, _ *nodeSet, s *edgeSet) {
	org := nd(Organization, "login", c.org)
	for _, r := range c.dirs["principals"] {
		switch str(r.fields["kind"]) {
		case "user":
			if truthy(r.fields["is_org_member"]) {
				s.add(MemberOf, nd(User, "login", str(r.fields["login"])), org, source(r.rel))
			}
		case "team":
			team := nd(Team, "org", c.org, "slug", str(r.fields["slug"]))
			for _, m := range objects(r.fields["members"]) {
				s.add(MemberOf, nd(User, "login", str(m["login"])), team, source(r.rel+"#members"))
			}
		}
	}
}

func emitHasAccess(c *corpus, _ *nodeSet, s *edgeSet) {
	for _, r := range c.dirs["principals"] {
		var from endpoint
		switch str(r.fields["kind"]) {
		case "user":
			from = nd(User, "login", str(r.fields["login"]))
		case "team":
			from = nd(Team, "org", c.org, "slug", str(r.fields["slug"]))
		default:
			continue
		}
		for _, g := range objects(r.fields["repo_grants"]) {
			s.add(HasAccess, from, repoEndpoint(c, str(g["repo"])), map[string]any{
				"permission":                g["permission"],
				"can_push":                  truthy(g["can_push"]),
				"is_admin":                  truthy(g["is_admin"]),
				"via_outside_collaboration": truthy(g["via_outside_collaboration"]),
				"_source":                   []any{r.rel + "#repo_grants"},
			})
		}
	}
}

// deploy-keys/ rather than chains/deploy-key-reuse: the chain is empty here and
// its instances[] carry no fingerprint even when populated.
func emitInstalledOn(c *corpus, _ *nodeSet, s *edgeSet) {
	for _, r := range c.dirs["deploy-keys"] {
		s.add(InstalledOn, nd(DeployKey, "fingerprint", str(r.fields["fingerprint"])),
			repoEndpoint(c, str(r.fields["repo"])), map[string]any{
				"key_id":    r.fields["key_id"],
				"title":     str(r.fields["title"]),
				"read_only": truthy(r.fields["read_only"]),
				"can_push":  truthy(r.fields["can_push"]),
				"_source":   []any{r.rel},
			})
	}
}

func emitGoverns(c *corpus, _ *nodeSet, s *edgeSet) {
	for _, r := range c.dirs["rulesets"] {
		if truthy(r.fields["_empty"]) {
			continue
		}
		props := map[string]any{
			"name":        str(r.fields["name"]),
			"enforcement": str(r.fields["enforcement"]),
			"target":      str(r.fields["target"]),
			"_source":     []any{r.rel},
		}
		from := rulesetEndpoint(r.fields, "ruleset_id")
		if str(r.fields["scope"]) == "org" {
			s.add(Governs, from, nd(Organization, "login", c.org), props)
		} else {
			s.add(Governs, from, repoEndpoint(c, str(r.fields["repo"])), props)
		}
	}
}

// branch-coverage rather than effective-ruleset.active_ruleset_ids: the latter
// omits the enforcement:"disabled" ruleset that fr-11-15 exists to test.
func emitProtectedBy(c *corpus, _ *nodeSet, s *edgeSet) {
	src := c.chainSource("branch-coverage", "repo_branch_coverage")
	for _, b := range c.chainArray("branch-coverage", "repo_branch_coverage") {
		from := branchEndpoint(c, str(b["repo"]), str(b["branch"]))
		for _, a := range objects(b["applicable_rulesets"]) {
			s.add(ProtectedBy, from, rulesetEndpoint(a, "ruleset_id"), map[string]any{
				"enforcement":           str(a["enforcement"]),
				"ruleset_name":          str(a["name"]),
				"any_bypass_present":    truthy(a["any_bypass_present"]),
				"requires_pull_request": truthy(a["requires_pull_request"]),
				"_source":               []any{src},
			})
		}
	}
}

// rulesets/ rather than chains/capability-edges: the chain's bypass_actors_matched
// names an actor but never the ruleset it bypasses.
func emitCanBypass(c *corpus, _ *nodeSet, s *edgeSet) {
	users, teams, apps := map[string]string{}, map[string]string{}, map[string]string{}
	for _, r := range c.dirs["principals"] {
		switch str(r.fields["kind"]) {
		case "user":
			users[decimal(r.fields["user_id"])] = str(r.fields["login"])
		case "team":
			teams[decimal(r.fields["team_id"])] = str(r.fields["slug"])
		}
	}
	for _, r := range c.dirs["apps"] {
		apps[decimal(r.fields["app_id"])] = str(r.fields["app_slug"])
	}

	for _, r := range c.dirs["rulesets"] {
		if truthy(r.fields["_empty"]) {
			continue
		}
		to := rulesetEndpoint(r.fields, "ruleset_id")
		bypass := obj(r.fields["bypass"])
		for _, field := range []string{"bypass_always", "bypass_pull_request_only"} {
			for _, a := range objects(bypass[field]) {
				id := decimal(a["actor_id"])
				var from endpoint
				switch {
				case str(a["actor_type"]) == "User" && users[id] != "":
					from = nd(User, "login", users[id])
				case str(a["actor_type"]) == "Team" && teams[id] != "":
					from = nd(Team, "org", c.org, "slug", teams[id])
				case str(a["actor_type"]) == "Integration" && apps[id] != "":
					from = nd(App, "app_slug", apps[id])
				default:
					s.miss(CanBypass, 1)
					continue
				}
				s.add(CanBypass, from, to, map[string]any{
					"bypass_mode": str(a["bypass_mode"]),
					"actor_type":  str(a["actor_type"]),
					"_source":     []any{r.rel + "#bypass." + field},
				})
			}
		}
	}
}

func deployKeyFingerprints(c *corpus) map[string]string {
	out := map[string]string{}
	for _, r := range c.dirs["deploy-keys"] {
		out[r.id] = str(r.fields["fingerprint"])
	}
	return out
}

func capabilityPrincipal(c *corpus, fingerprints map[string]string, e map[string]any) endpoint {
	switch str(e["principal_kind"]) {
	case "user":
		return nd(User, "login", str(e["principal_name"]))
	case "team":
		return nd(Team, "org", c.org, "slug", str(e["principal_name"]))
	case "app":
		return nd(App, "app_slug", str(e["principal_name"]))
	case "deploy_key":
		// principal_name is the key title, not its identity; the fingerprint
		// exists only on the deploy-keys record the principal_id names.
		return nd(DeployKey, "fingerprint", fingerprints[str(e["principal_id"])])
	}
	return endpoint{}
}

func emitCanLandCode(c *corpus, _ *nodeSet, s *edgeSet) {
	fingerprints := deployKeyFingerprints(c)
	src := c.chainSource("capability-edges", "edges")
	for _, e := range c.chainArray("capability-edges", "edges") {
		from := capabilityPrincipal(c, fingerprints, e)
		s.add(CanLandCode, from, branchEndpoint(c, str(e["repo"]), str(e["branch"])), map[string]any{
			"circumvents":       list(e["circumvents"]),
			"routes_open":       list(e["routes_open"]),
			"routes_blocked":    list(e["routes_blocked"]),
			"write_via":         str(e["write_via"]),
			"permission":        e["permission"],
			"is_admin":          truthy(e["is_admin"]),
			"is_default_branch": truthy(e["is_default_branch"]),
			"principal_kind":    str(e["principal_kind"]),
			"_source":           []any{src},
		})
	}
}

func emitCanApprove(c *corpus, _ *nodeSet, s *edgeSet) {
	approves := map[string]bool{}
	for _, r := range c.dirs["repos"] {
		approves[str(r.fields["repo"])] = truthy(r.fields["can_approve_pull_request_reviews"])
	}
	for _, r := range c.dirs["jobs"] {
		repo := str(r.fields["repo"])
		if !approves[repo] {
			continue
		}
		s.add(CanApprove, jobEndpoint(c, r.fields), repoEndpoint(c, repo), source(r.rel))
	}
}

func emitUsesAction(c *corpus, _ *nodeSet, s *edgeSet) {
	for _, r := range c.dirs["jobs"] {
		from := jobEndpoint(c, r.fields)
		for _, e := range objects(r.fields["action_refs"]) {
			ref, ok := actionIdentity(c.full(str(r.fields["repo"])), str(e["uses"]))
			if !ok {
				continue
			}
			s.add(UsesAction, from, nd(Action, "ref", ref), map[string]any{
				"ref_kind":     str(e["ref_kind"]),
				"ref_mutable":  truthy(e["ref_mutable"]),
				"resolved_sha": e["resolved_sha"],
				"_source":      []any{r.rel + "#action_refs"},
			})
		}
	}
}

// actionIdentity mirrors emitActions: a ref resolving to a workflow file is a
// CALLS target, and a "./"-relative ref is qualified so {ref} stays unique.
func actionIdentity(repo, uses string) (string, bool) {
	if uses == "" || isWorkflowRef(uses) {
		return "", false
	}
	if rest, local := strings.CutPrefix(uses, "./"); local {
		if repo == "" {
			return "", false
		}
		return repo + "/" + rest, true
	}
	return uses, true
}

// The Secret endpoint comes from the node writer's index: a job cites the raw
// "<repo>__<env>" scope_key, and splitting it back apart is ambiguous.
func emitSecretReads(c *corpus, n *nodeSet, s *edgeSet) {
	for _, r := range c.dirs["jobs"] {
		from := jobEndpoint(c, r.fields)
		for _, e := range objects(r.fields["secrets_referenced"]) {
			id, ok := n.secretID(str(e["scope"]), str(e["scope_key"]), str(e["name"]))
			if !ok {
				s.miss(Reads, 1)
				continue
			}
			steps := []any{}
			if v, present := e["step_index"]; present && v != nil {
				steps = append(steps, v)
			}
			s.add(Reads, from, resolved(Secret, id), map[string]any{
				"step_indexes": steps,
				"_source":      []any{r.rel + "#secrets_referenced"},
			})
		}
	}
}

func emitArtifactIO(c *corpus, _ *nodeSet, s *edgeSet) {
	for _, r := range c.dirs["jobs"] {
		from := jobEndpoint(c, r.fields)
		repo := c.full(str(r.fields["repo"]))
		for _, io := range []struct {
			t     EdgeType
			field string
		}{{Reads, "artifact_reads"}, {Writes, "artifact_writes"}} {
			for _, e := range objects(r.fields[io.field]) {
				s.add(io.t, from, nd(Artifact, "repo", repo, "name", str(e["name"])),
					source(r.rel+"#"+io.field))
			}
		}
	}
}

// cache-keyspace only, matching emitCaches: jobs[].cache_*[].scope embeds a
// prefix that does not round-trip to the chain's key.
func emitCacheIO(c *corpus, _ *nodeSet, s *edgeSet) {
	for _, io := range []struct {
		t     EdgeType
		field string
	}{{Reads, "reads_by_prefix"}, {Writes, "writes_by_prefix"}} {
		m, _ := c.chains["cache-keyspace"][io.field].(map[string]any)
		src := c.chainSource("cache-keyspace", io.field)
		for _, prefix := range slices.Sorted(maps.Keys(m)) {
			for _, e := range objects(m[prefix]) {
				s.add(io.t, jobEndpoint(c, obj(e["job"])), nd(Cache, "key_prefix", prefix), map[string]any{
					"keys":    []any{str(e["key"])},
					"_source": []any{src},
				})
			}
		}
	}
}

// jobs[].needs rather than chains/job-output-flow, whose endpoints carry only an
// _id; the chain contributes the attacker-flow properties, keyed by record _id.
func emitNeeds(c *corpus, _ *nodeSet, s *edgeSet) {
	jobs := map[string]map[string]any{}
	for _, r := range c.dirs["jobs"] {
		jobs[r.id] = r.fields
	}
	flow := map[[2]string]map[string]any{}
	for _, e := range c.chainArray("job-output-flow", "edges") {
		p, okp := jobs[str(obj(e["producer"])["_id"])]
		q, okq := jobs[str(obj(e["consumer"])["_id"])]
		if !okp || !okq {
			continue
		}
		flow[[2]string{jobEndpoint(c, q).id, jobEndpoint(c, p).id}] = map[string]any{
			"attacker_influenced": truthy(e["attacker_influenced"]),
			"attacker_path":       list(e["attacker_path"]),
			"_source":             []any{c.chainSource("job-output-flow", "edges")},
		}
	}

	for _, r := range c.dirs["jobs"] {
		from := jobEndpoint(c, r.fields)
		for _, dep := range list(r.fields["needs"]) {
			to := nd(Job, "repo", from.key["repo"], "workflow", from.key["workflow"], "job_id", str(dep))
			props := source(r.rel + "#needs")
			if extra, ok := flow[[2]string{from.id, to.id}]; ok {
				maps.Copy(props, extra)
				props["_source"] = []any{r.rel + "#needs", c.chainSource("job-output-flow", "edges")}
			}
			s.add(Needs, from, to, props)
		}
	}
}

func emitCalls(c *corpus, _ *nodeSet, s *edgeSet) {
	src := c.chainSource("reusable-callgraph", "edges")
	for _, e := range c.chainArray("reusable-callgraph", "edges") {
		caller, callee := obj(e["caller"]), obj(e["callee"])
		repo := str(callee["repo"])
		if truthy(callee["is_local"]) || repo == "" {
			repo = str(caller["repo"])
		}
		s.add(Calls, jobEndpoint(c, caller), nd(Workflow, "repo", c.full(repo), "path", str(callee["path"])),
			map[string]any{
				"ref":         str(callee["ref"]),
				"ref_kind":    str(callee["ref_kind"]),
				"ref_mutable": truthy(callee["ref_mutable"]),
				"is_local":    truthy(callee["is_local"]),
				"_source":     []any{src},
			})
	}
}

func emitTriggers(c *corpus, _ *nodeSet, s *edgeSet) {
	src := c.chainSource("trigger-channels", "workflow_run_pairs")
	for _, p := range c.chainArray("trigger-channels", "workflow_run_pairs") {
		s.add(Triggers, workflowEndpoint(c, obj(p["upstream"])), workflowEndpoint(c, obj(p["downstream"])),
			map[string]any{"event_types": list(p["event_types"]), "_source": []any{src}})
	}
}

func emitTargets(c *corpus, _ *nodeSet, s *edgeSet) {
	src := c.chainSource("env-deployments", "deploys")
	for _, d := range c.chainArray("env-deployments", "deploys") {
		name := str(d["env_name"])
		if name == "" || strings.Contains(name, "${{") {
			s.miss(Targets, 1)
			continue
		}
		job := obj(d["job"])
		s.add(Targets, jobEndpoint(c, job), envEndpoint(c, str(job["repo"]), name), map[string]any{
			"env_record_present":   truthy(d["env_record_present"]),
			"env_admins_bypass":    truthy(d["env_admins_bypass"]),
			"env_no_branch_policy": truthy(d["env_no_branch_policy"]),
			"env_no_reviewers":     truthy(d["env_no_reviewers"]),
			"_source":              []any{src},
		})
	}
}

func emitDefines(c *corpus, _ *nodeSet, s *edgeSet) {
	repos := map[string]bool{}
	for _, r := range c.dirs["repos"] {
		repos[str(r.fields["repo"])] = true
	}
	for _, r := range c.dirs["jobs"] {
		for _, e := range objects(r.fields["action_refs"]) {
			ref, ok := actionIdentity(c.full(str(r.fields["repo"])), str(e["uses"]))
			if !ok {
				continue
			}
			owner, repo, ok := splitActionOwner(ref)
			if !ok || owner != c.org || !repos[repo] {
				continue
			}
			s.add(Defines, repoEndpoint(c, repo), nd(Action, "ref", ref), source(r.rel+"#action_refs"))
		}
	}
}

func splitActionOwner(ref string) (string, string, bool) {
	parts := strings.SplitN(ref, "/", 3)
	if len(parts) < 2 {
		return "", "", false
	}
	repo, _, _ := strings.Cut(parts[1], "@")
	return parts[0], repo, repo != ""
}

// A glob is not a ref identity, so a pattern only yields an edge when it names a
// Branch node that already exists; "v*" needs tag refs normalize does not emit.
func emitDeployableFrom(c *corpus, n *nodeSet, s *edgeSet) {
	for _, r := range c.dirs["environments"] {
		repo := str(r.fields["repo"])
		for _, p := range list(obj(r.fields["deployment_branch_policy"])["patterns"]) {
			to := branchEndpoint(c, repo, str(p))
			if !to.complete() || !n.has(to.id) {
				s.miss(DeployableFrom, 1)
				continue
			}
			s.add(DeployableFrom, envEndpoint(c, repo, str(r.fields["name"])), to,
				source(r.rel+"#deployment_branch_policy"))
		}
	}
}

// Relations the data asserts but whose target identity was never collected.
// Counted so the gap is auditable rather than invisible: a placeholder Runner
// would make every self-hosted job appear to share one machine, which is the
// exact claim the cat-07 rules exist to test.
func emitUnbuildable(c *corpus, _ *nodeSet, s *edgeSet) {
	runners, groups := map[string]bool{}, map[string]bool{}
	for _, r := range c.dirs["jobs"] {
		id := jobEndpoint(c, r.fields).id
		if truthy(r.fields["self_hosted"]) {
			runners[id] = true
		}
		if str(r.fields["runner_group"]) != "" {
			groups[id] = true
		}
	}
	s.miss(RunsOn, len(runners)+len(groups))
	s.miss(MintsTokenAs, len(c.chainArray("app-mintable", "mints")))
}
