package github

import (
	"context"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/praetorian-inc/trajan/internal/graph"
)

// nd builds an identity tuple, not a node: the edge writer never emits nodes.
// Keys outside IdentityKey are dropped on construction, so a caller may supply
// scope_key unconditionally and let the schema decide whether it identifies.
func nd(l NodeLabel, kv ...string) graph.Endpoint[NodeLabel] {
	want := IdentityKey(l)
	e := graph.Endpoint[NodeLabel]{Label: l, Key: make(map[string]string, len(want))}
	for i := 0; i+1 < len(kv); i += 2 {
		if slices.Contains(want, kv[i]) && identifies(kv[i+1]) {
			e.Key[kv[i]] = kv[i+1]
		}
	}
	if complete(e) {
		e.ID = graph.NodeID[NodeLabel, EdgeType](ghSchema{}, l, e.Key)
	}
	return e
}

func complete(e graph.Endpoint[NodeLabel]) bool {
	want := IdentityKey(e.Label)
	if len(want) == 0 {
		return false
	}
	for _, k := range want {
		if e.Key[k] == "" {
			return false
		}
	}
	return true
}

// resolved names a node the node writer already emitted and whose identity the
// edge writer cannot rebuild: a Secret, whose canonical scope_key is only
// recoverable from the secret record, not from the job reference that cites it.
func resolved(l NodeLabel, id string) graph.Endpoint[NodeLabel] {
	return graph.Endpoint[NodeLabel]{Label: l, ID: id}
}

type edgeIndex = graph.EdgeSet[NodeLabel, EdgeType]

func newEdgeIndex() *edgeIndex { return graph.NewEdgeSet[NodeLabel, EdgeType](ghSchema{}) }

func buildEdges(ctx context.Context, c *ghCorpus, n *nodeIndex) (*edgeIndex, error) {
	s := newEdgeIndex()
	for _, emit := range []func(*ghCorpus, *nodeIndex, *edgeIndex){
		emitContains, emitMemberOf, emitHasAccess, emitInstalledOn, emitGoverns,
		emitProtectedBy, emitCanBypass, emitCanLandCode, emitCanApprove,
		emitUsesAction, emitSecretReads, emitArtifactIO, emitCacheIO, emitNeeds,
		emitCalls, emitTriggers, emitTargets, emitTargetsBranch, emitDefines,
		emitDeployableFrom, emitRequiresReviewBy, emitCanAssume, emitPassesSecret, emitMintsTokenAs,
		emitOrgSecretAccess, emitRunnerGroupAccess, emitRunsOn,
	} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		emit(c, n, s)
	}
	return s, s.Err()
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

func jobEndpoint(c *ghCorpus, f map[string]any) graph.Endpoint[NodeLabel] {
	return nd(Job,
		"repo", c.full(str(f["repo"])),
		"workflow", workflowPath(str(f["workflow_filename"])),
		"job_id", str(f["job_id"]))
}

func workflowEndpoint(c *ghCorpus, f map[string]any) graph.Endpoint[NodeLabel] {
	return nd(Workflow, "repo", c.full(str(f["repo"])), "path", workflowPath(str(f["workflow_filename"])))
}

func repoEndpoint(c *ghCorpus, repo string) graph.Endpoint[NodeLabel] {
	return nd(Repository, "full_name", c.full(repo))
}

func branchEndpoint(c *ghCorpus, repo, name string) graph.Endpoint[NodeLabel] {
	return nd(Branch, "repo", c.full(repo), "name", name)
}

func envEndpoint(c *ghCorpus, repo, name string) graph.Endpoint[NodeLabel] {
	return nd(Environment, "repo", c.full(repo), "name", name)
}

func cacheEndpoint(c *ghCorpus, repo, prefix string) graph.Endpoint[NodeLabel] {
	return nd(Cache, "repo", c.full(repo), "key_prefix", prefix)
}

func tagEndpoint(c *ghCorpus, repo, name string) graph.Endpoint[NodeLabel] {
	return nd(Tag, "repo", c.full(repo), "name", name)
}

func rulesetEndpoint(c *ghCorpus, f map[string]any, repo string) graph.Endpoint[NodeLabel] {
	scope := str(f["scope"])
	return nd(Ruleset, "scope", scope, "scope_key", c.rulesetScopeKey(scope, repo),
		"id", decimal(f["ruleset_id"]))
}

func runnerEndpoint(c *ghCorpus, f map[string]any) graph.Endpoint[NodeLabel] {
	return nd(Runner, "scope", str(f["scope"]), "scope_key", c.runnerScopeKey(f), "id", decimal(f["runner_id"]))
}

// A callee names its role "${{ inputs.role-arn }}" and only the caller knows the
// literal, so the identifier resolves across the call edge the way an artifact name
// does — callers disagreeing on an input leave it unresolvable.
func emitCanAssume(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	inputs := calleeInputs(c)
	for _, r := range c.dirs["jobs"] {
		in := inputs[calleeKey(c, r.fields)]
		for _, cr := range list(r.fields["cloud_roles"]) {
			m := obj(cr)
			to := nd(CloudRole, "identifier", resolveInput(str(m["identifier"]), in))
			if !complete(to) {
				s.Miss(CanAssume, Job, CloudRole, 1)
				continue
			}
			s.Add(CanAssume, jobEndpoint(c, r.fields), to, source(r.rel))
		}
	}
}

// A secret's blast radius is not derivable from the node: "selected" names a list only
// the secret record carries, and an empty list means the secret is reachable by
// nothing — the exact inverse of a fan-out from Secret.visibility.
func emitOrgSecretAccess(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	for _, r := range c.dirs["org"] {
		src := r.rel + "#org_actions_secrets"
		for _, e := range objects(r.fields["org_actions_secrets"]) {
			vis := str(e["visibility"])
			to := nd(Secret, "scope", "org", "scope_key", c.org, "name", str(e["name"]))
			for _, repo := range scopedRepos(c, e) {
				s.Add(CanAccess, repoEndpoint(c, repo), to,
					map[string]any{"visibility": vis, "_source": []any{src}})
			}
		}
	}
}

// app is null where the mint site names an app id the corpus cannot resolve to an
// installation, leaving the token's identity — and so its permissions — unknown.
func emitMintsTokenAs(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	src := c.chainSource("app-mintable", "mints")
	// Job identity omits branch, so one minting job seen on several branches is several
	// chain rows and at most one edge; the miss is counted per job, not per row.
	unresolved := map[string]bool{}
	for _, m := range c.chainArray("app-mintable", "mints") {
		from := jobEndpoint(c, obj(m["minter"]))
		to := nd(App, "app_slug", str(obj(m["app"])["slug"]))
		if !complete(to) {
			unresolved[from.ID] = true
			continue
		}
		s.Add(MintsTokenAs, from, to, map[string]any{
			"action":     str(m["action"]),
			"action_ref": str(m["action_ref"]),
			"_source":    []any{src},
		})
	}
	s.Miss(MintsTokenAs, Job, App, len(unresolved))
}

func emitContains(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	org := nd(Organization, "login", c.org)
	for _, r := range c.dirs["repos"] {
		s.Add(Contains, org, repoEndpoint(c, str(r.fields["repo"])), source(r.rel))
	}
	for _, r := range c.dirs["principals"] {
		if str(r.fields["kind"]) == "team" {
			s.Add(Contains, org, nd(Team, "org", c.org, "slug", str(r.fields["slug"])), source(r.rel))
		}
	}
	for _, r := range c.dirs["apps"] {
		s.Add(Contains, org, nd(App, "app_slug", str(r.fields["app_slug"])), source(r.rel))
	}
	for _, r := range c.dirs["runner-groups"] {
		s.Add(Contains, org, nd(RunnerGroup, "org", str(r.fields["org"]), "id", decimal(r.fields["group_id"])), source(r.rel))
	}
	for _, r := range c.dirs["runners"] {
		run := runnerEndpoint(c, r.fields)
		switch str(r.fields["scope"]) {
		case "org":
			s.Add(Contains, org, run, source(r.rel))
		case "repo":
			s.Add(Contains, repoEndpoint(c, str(r.fields["repo"])), run, source(r.rel))
		}
	}
	// member_runner_ids rather than the runner's own runner_group_id: the org
	// runner listing omits the group on every runner it returns, while the
	// per-group membership call names them.
	for _, r := range c.dirs["runner-groups"] {
		from := nd(RunnerGroup, "org", str(r.fields["org"]), "id", decimal(r.fields["group_id"]))
		for _, id := range list(r.fields["member_runner_ids"]) {
			s.Add(Contains, from, nd(Runner, "scope", "org", "scope_key", c.org, "id", decimal(id)),
				source(r.rel+"#member_runner_ids"))
		}
	}
	for _, r := range c.dirs["rulesets"] {
		if truthy(r.fields["_empty"]) {
			continue
		}
		rs := rulesetEndpoint(c, r.fields, str(r.fields["repo"]))
		if str(r.fields["scope"]) == "org" {
			s.Add(Contains, org, rs, source(r.rel))
		} else {
			s.Add(Contains, repoEndpoint(c, str(r.fields["repo"])), rs, source(r.rel))
		}
	}
	for _, r := range c.dirs["org"] {
		for _, e := range objects(r.fields["org_actions_secrets"]) {
			s.Add(Contains, org, nd(Secret, "scope", "org", "scope_key", c.org, "name", str(e["name"])),
				source(r.rel+"#org_actions_secrets"))
		}
	}
	for _, e := range c.chainArray("effective-ruleset", "effective_per_branch") {
		s.Add(Contains, repoEndpoint(c, str(e["repo"])), branchEndpoint(c, str(e["repo"]), str(e["branch"])),
			source(c.chainSource("effective-ruleset", "effective_per_branch")))
	}
	unslugged := 0
	for _, r := range c.dirs["jobs"] {
		wf := workflowEndpoint(c, r.fields)
		// The job record's branch is filename-slugged, so it reaches Branch identity only
		// through trueBranch; an ambiguous slug leaves containment unrecoverable.
		repo := str(r.fields["repo"])
		if name := c.trueBranch[c.full(repo)+"\x00"+str(r.fields["branch"])]; name != "" {
			s.Add(Contains, branchEndpoint(c, repo, name), wf, source(r.rel))
		} else {
			unslugged++
		}
		s.Add(Contains, wf, jobEndpoint(c, r.fields), source(r.rel))
	}
	s.Miss(Contains, Branch, Workflow, unslugged)
	for _, r := range c.dirs["environments"] {
		s.Add(Contains, repoEndpoint(c, str(r.fields["repo"])), envEndpoint(c, str(r.fields["repo"]), str(r.fields["name"])), source(r.rel))
	}
	for _, r := range c.dirs["tags"] {
		repo := str(r.fields["repo"])
		s.Add(Contains, repoEndpoint(c, repo), tagEndpoint(c, repo, str(r.fields["name"])), source(r.rel))
	}
	for _, r := range c.dirs["secrets"] {
		sec := nd(Secret, "scope", str(r.fields["scope"]), "scope_key", c.secretScopeKey(r.fields), "name", str(r.fields["name"]))
		switch str(r.fields["scope"]) {
		case "org":
			s.Add(Contains, org, sec, source(r.rel))
		case "repo":
			s.Add(Contains, repoEndpoint(c, str(r.fields["repo"])), sec, source(r.rel))
		case "environment":
			s.Add(Contains, envEndpoint(c, str(r.fields["repo"]), str(r.fields["environment"])), sec, source(r.rel))
		}
	}
}

func emitMemberOf(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	org := nd(Organization, "login", c.org)
	for _, r := range c.dirs["principals"] {
		switch str(r.fields["kind"]) {
		case "user":
			if truthy(r.fields["is_org_member"]) {
				s.Add(MemberOf, nd(User, "login", str(r.fields["login"])), org, source(r.rel))
			}
		case "team":
			team := nd(Team, "org", c.org, "slug", str(r.fields["slug"]))
			for _, m := range objects(r.fields["members"]) {
				s.Add(MemberOf, nd(User, "login", str(m["login"])), team, source(r.rel+"#members"))
			}
		}
	}
}

func emitHasAccess(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	for _, r := range c.dirs["principals"] {
		var from graph.Endpoint[NodeLabel]
		switch str(r.fields["kind"]) {
		case "user":
			from = nd(User, "login", str(r.fields["login"]))
		case "team":
			from = nd(Team, "org", c.org, "slug", str(r.fields["slug"]))
		default:
			continue
		}
		for _, g := range objects(r.fields["repo_grants"]) {
			s.Add(HasAccess, from, repoEndpoint(c, str(g["repo"])), map[string]any{
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
func emitInstalledOn(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	for _, r := range c.dirs["deploy-keys"] {
		s.Add(InstalledOn, nd(DeployKey, "fingerprint", str(r.fields["fingerprint"])),
			repoEndpoint(c, str(r.fields["repo"])), map[string]any{
				"key_id":     r.fields["key_id"],
				"title":      str(r.fields["title"]),
				"read_only":  truthy(r.fields["read_only"]),
				"can_push":   truthy(r.fields["can_push"]),
				"added_by":   str(r.fields["added_by"]),
				"created_at": str(r.fields["created_at"]),
				"last_used":  str(r.fields["last_used"]),
				"_source":    []any{r.rel},
			})
	}
}

func emitGoverns(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
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
		from := rulesetEndpoint(c, r.fields, str(r.fields["repo"]))
		if str(r.fields["scope"]) == "org" {
			s.Add(Governs, from, nd(Organization, "login", c.org), props)
		} else {
			s.Add(Governs, from, repoEndpoint(c, str(r.fields["repo"])), props)
		}
	}
}

// branch-coverage rather than effective-ruleset.active_ruleset_ids: the latter
// omits the enforcement:"disabled" ruleset that fr-11-15 exists to test.
func emitProtectedBy(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	src := c.chainSource("branch-coverage", "repo_branch_coverage")
	for _, b := range c.chainArray("branch-coverage", "repo_branch_coverage") {
		repo := str(b["repo"])
		from := branchEndpoint(c, repo, str(b["branch"]))
		for _, a := range objects(b["applicable_rulesets"]) {
			s.Add(ProtectedBy, from, rulesetEndpoint(c, a, repo), protectedByProps(a, src))
		}
	}
	for _, r := range c.dirs["tags"] {
		repo := str(r.fields["repo"])
		from := tagEndpoint(c, repo, str(r.fields["name"]))
		for _, a := range objects(r.fields["applicable_rulesets"]) {
			s.Add(ProtectedBy, from, rulesetEndpoint(c, a, repo), protectedByProps(a, r.rel+"#applicable_rulesets"))
		}
	}
}

func protectedByProps(a map[string]any, src string) map[string]any {
	return map[string]any{
		"enforcement":           str(a["enforcement"]),
		"ruleset_name":          str(a["name"]),
		"any_bypass_present":    truthy(a["any_bypass_present"]),
		"requires_pull_request": truthy(a["requires_pull_request"]),
		"_source":               []any{src},
	}
}

// rulesets/ rather than chains/capability-edges: the chain's bypass_actors_matched
// names an actor but never the ruleset it bypasses.
func emitCanBypass(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
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
		to := rulesetEndpoint(c, r.fields, str(r.fields["repo"]))
		bypass := obj(r.fields["bypass"])
		for _, field := range []string{"bypass_always", "bypass_pull_request_only"} {
			for _, a := range objects(bypass[field]) {
				id := decimal(a["actor_id"])
				var from graph.Endpoint[NodeLabel]
				switch {
				case str(a["actor_type"]) == "User" && users[id] != "":
					from = nd(User, "login", users[id])
				case str(a["actor_type"]) == "Team" && teams[id] != "":
					from = nd(Team, "org", c.org, "slug", teams[id])
				case str(a["actor_type"]) == "Integration" && apps[id] != "":
					from = nd(App, "app_slug", apps[id])
				default:
					// The unresolvable side is the actor itself — a null actor_id,
					// or an actor_type with no NodeLabel — so it gets no label.
					s.Miss(CanBypass, "", Ruleset, 1)
					continue
				}
				s.Add(CanBypass, from, to, map[string]any{
					"bypass_mode": str(a["bypass_mode"]),
					"actor_type":  str(a["actor_type"]),
					"_source":     []any{r.rel + "#bypass." + field},
				})
			}
		}
	}
}

func deployKeyFingerprints(c *ghCorpus) map[string]string {
	out := map[string]string{}
	for _, r := range c.dirs["deploy-keys"] {
		out[r.id] = str(r.fields["fingerprint"])
	}
	return out
}

func capabilityPrincipal(c *ghCorpus, fingerprints map[string]string, e map[string]any) graph.Endpoint[NodeLabel] {
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
	return graph.Endpoint[NodeLabel]{}
}

func emitCanLandCode(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	fingerprints := deployKeyFingerprints(c)
	src := c.chainSource("capability-edges", "edges")
	for _, e := range c.chainArray("capability-edges", "edges") {
		from := capabilityPrincipal(c, fingerprints, e)
		s.Add(CanLandCode, from, branchEndpoint(c, str(e["repo"]), str(e["branch"])), map[string]any{
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

func emitCanApprove(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	approves := map[string]bool{}
	for _, r := range c.dirs["repos"] {
		approves[str(r.fields["repo"])] = truthy(r.fields["can_approve_pull_request_reviews"])
	}
	for _, r := range c.dirs["jobs"] {
		repo := str(r.fields["repo"])
		// Both halves of the capability: the repo setting alone is already a Repository
		// property, so an edge restating it would assert nothing about the job.
		if !approves[repo] || str(obj(r.fields["permissions"])["pull-requests"]) != "write" {
			continue
		}
		s.Add(CanApprove, jobEndpoint(c, r.fields), repoEndpoint(c, repo), source(r.rel))
	}
}

func emitUsesAction(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	for _, r := range c.dirs["jobs"] {
		from := jobEndpoint(c, r.fields)
		for _, e := range objects(r.fields["action_refs"]) {
			ref, ok := actionIdentity(c.full(str(r.fields["repo"])), str(e["uses"]))
			if !ok {
				continue
			}
			s.Add(UsesAction, from, nd(Action, "ref", ref), map[string]any{
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
func emitSecretReads(c *ghCorpus, n *nodeIndex, s *edgeIndex) {
	for _, r := range c.dirs["jobs"] {
		from := jobEndpoint(c, r.fields)
		for _, e := range objects(r.fields["secrets_referenced"]) {
			id, ok := n.secretID(str(e["scope"]), str(e["scope_key"]), str(e["name"]))
			if !ok {
				s.Miss(Reads, Job, Secret, 1)
				continue
			}
			steps := []any{}
			if v, present := e["step_index"]; present && v != nil {
				steps = append(steps, v)
			}
			s.Add(Reads, from, resolved(Secret, id), map[string]any{
				"step_indexes": steps,
				"_source":      []any{r.rel + "#secrets_referenced"},
			})
		}
	}
}

func emitArtifactIO(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	inputs := calleeInputs(c)
	for _, r := range c.dirs["jobs"] {
		from := jobEndpoint(c, r.fields)
		repo := c.full(str(r.fields["repo"]))
		in := inputs[calleeKey(c, r.fields)]
		for _, io := range []struct {
			t     EdgeType
			field string
		}{{Reads, "artifact_reads"}, {Writes, "artifact_writes"}} {
			for _, e := range objects(r.fields[io.field]) {
				s.Add(io.t, from, nd(Artifact, "repo", repo, "name", resolveInput(str(e["name"]), in)),
					source(r.rel+"#"+io.field))
			}
		}
	}
}

func emitCacheIO(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	for _, io := range []struct {
		t     EdgeType
		field string
	}{{Reads, "reads_by_prefix"}, {Writes, "writes_by_prefix"}} {
		m, _ := c.chains["cache-keyspace"][io.field].(map[string]any)
		src := c.chainSource("cache-keyspace", io.field)
		for _, prefix := range slices.Sorted(maps.Keys(m)) {
			for _, e := range objects(m[prefix]) {
				job := obj(e["job"])
				s.Add(io.t, jobEndpoint(c, job), cacheEndpoint(c, str(job["repo"]), prefix), map[string]any{
					"keys":    []any{str(e["key"])},
					"_source": []any{src},
				})
			}
		}
	}
}

// jobs[].needs rather than chains/job-output-flow, whose endpoints carry only an
// _id; the chain contributes the attacker-flow properties, keyed by record _id.
func emitNeeds(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
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
		flow[[2]string{jobEndpoint(c, q).ID, jobEndpoint(c, p).ID}] = map[string]any{
			"attacker_influenced": truthy(e["attacker_influenced"]),
			"attacker_path":       list(e["attacker_path"]),
			"_source":             []any{c.chainSource("job-output-flow", "edges")},
		}
	}

	for _, r := range c.dirs["jobs"] {
		from := jobEndpoint(c, r.fields)
		for _, dep := range list(r.fields["needs"]) {
			to := nd(Job, "repo", from.Key["repo"], "workflow", from.Key["workflow"], "job_id", str(dep))
			props := source(r.rel + "#needs")
			if extra, ok := flow[[2]string{from.ID, to.ID}]; ok {
				maps.Copy(props, extra)
				props["_source"] = []any{r.rel + "#needs", c.chainSource("job-output-flow", "edges")}
			}
			s.Add(Needs, from, to, props)
		}
	}
}

func emitCalls(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	src := c.chainSource("reusable-callgraph", "edges")
	for _, e := range c.chainArray("reusable-callgraph", "edges") {
		caller, callee := obj(e["caller"]), obj(e["callee"])
		repo := str(callee["repo"])
		if truthy(callee["is_local"]) || repo == "" {
			repo = str(caller["repo"])
		}
		s.Add(Calls, jobEndpoint(c, caller), nd(Workflow, "repo", c.full(repo), "path", str(callee["path"])),
			map[string]any{
				"ref":             str(callee["ref"]),
				"ref_kind":        str(callee["ref_kind"]),
				"ref_mutable":     truthy(callee["ref_mutable"]),
				"is_local":        truthy(callee["is_local"]),
				"secrets_inherit": truthy(callee["secrets_inherit"]),
				"_source":         []any{src},
			})
	}
}

func emitTriggers(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	src := c.chainSource("trigger-channels", "workflow_run_pairs")
	for _, p := range c.chainArray("trigger-channels", "workflow_run_pairs") {
		s.Add(Triggers, workflowEndpoint(c, obj(p["upstream"])), workflowEndpoint(c, obj(p["downstream"])),
			map[string]any{"event_types": list(p["event_types"]), "_source": []any{src}})
	}
}

func emitTargets(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	src := c.chainSource("env-deployments", "deploys")
	for _, d := range c.chainArray("env-deployments", "deploys") {
		job := obj(d["job"])
		env := envEndpoint(c, str(job["repo"]), str(d["env_name"]))
		s.Add(Targets, jobEndpoint(c, job), env, map[string]any{
			"env_record_present":   truthy(d["env_record_present"]),
			"env_admins_bypass":    truthy(d["env_admins_bypass"]),
			"env_no_branch_policy": truthy(d["env_no_branch_policy"]),
			"env_no_reviewers":     truthy(d["env_no_reviewers"]),
			"_source":              []any{src},
		})
		// emitContains derives the parent from environments/ alone, so an
		// environment only a deployment names would otherwise have none. Guarded
		// because an unidentifiable env_name is already counted against TARGETS.
		if complete(env) {
			s.Add(Contains, repoEndpoint(c, str(job["repo"])), env, source(src))
		}
	}
}

// trigger_filters is a workflow-level fact replicated onto every job record of that
// workflow, so a filter is emitted and counted once however many jobs it has. A glob
// is not a ref identity: it only yields an edge against a Branch node that exists.
func emitTargetsBranch(c *ghCorpus, n *nodeIndex, s *edgeIndex) {
	seen := map[[3]string]bool{}
	for _, r := range c.dirs["jobs"] {
		from := workflowEndpoint(c, r.fields)
		repo := str(r.fields["repo"])
		filters := obj(r.fields["trigger_filters"])
		for _, event := range slices.Sorted(maps.Keys(filters)) {
			for _, b := range list(obj(filters[event])["branches"]) {
				filter := str(b)
				key := [3]string{from.ID, event, filter}
				if seen[key] {
					continue
				}
				seen[key] = true
				rel := r.rel + "#trigger_filters." + event + ".branches"
				props := func() map[string]any {
					p := source(rel)
					p["branch_filter"] = filter
					return p
				}
				if !isBranchPattern(filter) {
					to := branchEndpoint(c, repo, filter)
					if !complete(to) || !n.Has(to.ID) {
						s.Miss(Targets, Workflow, Branch, 1)
						continue
					}
					s.Add(Targets, from, to, props())
					continue
				}
				re, ok := branchPattern(filter)
				if !ok {
					s.Miss(Targets, Workflow, Branch, 1)
					continue
				}
				matched := 0
				for _, name := range n.branchesIn(c.full(repo)) {
					if !re.MatchString(name) {
						continue
					}
					to := branchEndpoint(c, repo, name)
					if !complete(to) || !n.Has(to.ID) {
						continue
					}
					s.Add(Targets, from, to, props())
					matched++
				}
				if matched == 0 {
					s.Miss(Targets, Workflow, Branch, 1)
				}
			}
		}
	}
}

func isBranchPattern(f string) bool { return strings.ContainsAny(f, `*?+[]!`) }

// GitHub's filter syntax: * stops at a path separator, ** does not. The rest of
// it (?, +, ranges, leading-! negation) needs the whole filter list to resolve,
// so a pattern using any of it stays an unbuilt edge rather than a guess.
func branchPattern(f string) (*regexp.Regexp, bool) {
	if strings.ContainsAny(f, `?+[]!`) {
		return nil, false
	}
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(f); {
		switch {
		case strings.HasPrefix(f[i:], "**"):
			b.WriteString(".*")
			i += 2
		case f[i] == '*':
			b.WriteString("[^/]*")
			i++
		default:
			b.WriteString(regexp.QuoteMeta(f[i : i+1]))
			i++
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	return re, err == nil
}

// action_refs carries no step index and secrets_referenced carries no action, so the
// step a reference sits on is the only join between a credential and the third-party
// code that receives it. step_index -1 is job-env-level and belongs to no step.
func emitPassesSecret(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	for _, r := range c.dirs["jobs"] {
		steps := list(r.fields["steps"])
		from := jobEndpoint(c, r.fields)
		repo := c.full(str(r.fields["repo"]))
		for _, e := range objects(r.fields["secrets_referenced"]) {
			i, err := strconv.Atoi(decimal(e["step_index"]))
			if err != nil || i < 0 || i >= len(steps) {
				continue
			}
			ref, ok := actionIdentity(repo, str(obj(steps[i])["uses"]))
			if !ok {
				continue
			}
			s.Add(PassesSecret, from, nd(Action, "ref", ref), map[string]any{
				"secret_names": []any{str(e["name"])},
				"_source":      []any{r.rel + "#secrets_referenced"},
			})
		}
	}
}

func emitDefines(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
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
			s.Add(Defines, repoEndpoint(c, repo), nd(Action, "ref", ref), source(r.rel+"#action_refs"))
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
// Branch or Tag node that already exists.
func emitDeployableFrom(c *ghCorpus, n *nodeIndex, s *edgeIndex) {
	for _, r := range c.dirs["environments"] {
		repo := str(r.fields["repo"])
		for _, p := range list(obj(r.fields["deployment_branch_policy"])["patterns"]) {
			to := branchEndpoint(c, repo, str(p))
			if !complete(to) || !n.Has(to.ID) {
				to = tagEndpoint(c, repo, str(p))
			}
			if !complete(to) || !n.Has(to.ID) {
				s.Miss(DeployableFrom, Environment, Branch, 1)
				continue
			}
			s.Add(DeployableFrom, envEndpoint(c, repo, str(r.fields["name"])), to,
				source(r.rel+"#deployment_branch_policy"))
		}
	}
}

func emitRequiresReviewBy(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	for _, r := range c.dirs["environments"] {
		from := envEndpoint(c, str(r.fields["repo"]), str(r.fields["name"]))
		src := source(r.rel + "#reviewers_required")
		for _, rv := range objects(r.fields["reviewers_required"]) {
			// type is the reviewer's account type for a user and the team's ownership type for a team; "Team" never appears.
			switch str(rv["type"]) {
			case "User", "Bot":
				s.Add(RequiresReviewBy, from, nd(User, "login", str(rv["login"])), src)
			case "organization", "enterprise":
				s.Add(RequiresReviewBy, from, nd(Team, "org", c.org, "slug", str(rv["login"])), src)
			default:
				s.Miss(RequiresReviewBy, Environment, "", 1)
			}
		}
	}
}

// Org secrets and runner groups spell visibility the same way. An empty "selected"
// list reaches nothing, which is the point of the setting. An archived repository runs
// no workflow, so it consumes no secret and takes no job however the scope is written.
func scopedRepos(c *ghCorpus, f map[string]any) []string {
	live := func(g map[string]any) bool { return !truthy(g["archived"]) }
	switch str(f["visibility"]) {
	case "all":
		return c.repoNames(live)
	case "private":
		return c.repoNames(func(g map[string]any) bool { return live(g) && str(g["visibility"]) != "public" })
	case "selected":
		named := make(map[string]bool, len(list(f["selected_repositories"])))
		for _, v := range list(f["selected_repositories"]) {
			named[str(v)] = true
		}
		return c.repoNames(func(g map[string]any) bool { return live(g) && named[str(g["repo"])] })
	}
	return nil
}

func emitRunnerGroupAccess(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	for _, r := range c.dirs["runner-groups"] {
		to := nd(RunnerGroup, "org", str(r.fields["org"]), "id", decimal(r.fields["group_id"]))
		for _, repo := range scopedRepos(c, r.fields) {
			s.Add(CanAccess, repoEndpoint(c, repo), to, map[string]any{
				"visibility": str(r.fields["visibility"]),
				"_source":    []any{r.rel},
			})
		}
	}
}

// Neither a runner label nor a group NAME is an identity: the join is a runner whose
// labels cover the job's, and a group whose name is unique in the org. An unresolved
// job is counted but gets no placeholder: one stand-in Runner would fake a shared machine.
func emitRunsOn(c *ghCorpus, _ *nodeIndex, s *edgeIndex) {
	reach := map[string][]string{}
	byName := map[string][]map[string]any{}
	groupOf := map[string]string{}
	for _, r := range c.dirs["runner-groups"] {
		name := str(r.fields["name"])
		gid := decimal(r.fields["group_id"])
		byName[name] = append(byName[name], r.fields)
		reach[gid] = scopedRepos(c, r.fields)
		for _, id := range list(r.fields["member_runner_ids"]) {
			groupOf[decimal(id)] = gid
		}
	}

	for _, r := range c.dirs["jobs"] {
		from := jobEndpoint(c, r.fields)
		repo := str(r.fields["repo"])

		pinned, wantGroup := str(r.fields["runner_group"]), ""
		if pinned != "" {
			// Group names are not unique in an org, so an ambiguous name resolves
			// to no group rather than to an arbitrary one.
			if g := byName[pinned]; len(g) == 1 {
				wantGroup = decimal(g[0]["group_id"])
				s.Add(RunsOn, from, nd(RunnerGroup, "org", str(g[0]["org"]), "id", wantGroup),
					map[string]any{"runner_group": pinned, "_source": []any{r.rel}})
			} else {
				s.Miss(RunsOn, Job, RunnerGroup, 1)
			}
		}

		if !truthy(r.fields["self_hosted"]) {
			continue
		}
		want, resolvable := runnerLabelSet(r.fields["runner_labels"])
		matched := 0
		if resolvable && !(pinned != "" && wantGroup == "") {
			for _, run := range c.dirs["runners"] {
				if wantGroup != "" && groupOf[decimal(run.fields["runner_id"])] != wantGroup {
					continue
				}
				if !runnerServes(c, run.fields, repo, reach, groupOf) || !runnerHasLabels(run.fields, want) {
					continue
				}
				s.Add(RunsOn, from, runnerEndpoint(c, run.fields),
					map[string]any{"runner_labels": stringArray(want), "_source": []any{r.rel}})
				matched++
			}
		}
		if matched == 0 {
			s.Miss(RunsOn, Job, Runner, 1)
		}
	}
}

// An unevaluated label names whatever the caller passed, so the job's runner is
// chosen at run time and no collected runner can be claimed to serve it.
func runnerLabelSet(v any) ([]string, bool) {
	out := make([]string, 0, len(list(v)))
	for _, l := range list(v) {
		name := str(l)
		if !identifies(name) {
			return nil, false
		}
		out = append(out, strings.ToLower(name))
	}
	return out, len(out) > 0
}

func runnerHasLabels(f map[string]any, want []string) bool {
	have := make(map[string]bool, len(list(f["labels"])))
	for _, l := range list(f["labels"]) {
		have[strings.ToLower(str(l))] = true
	}
	for _, w := range want {
		if !have[w] {
			return false
		}
	}
	return true
}

// A repo runner serves only its own repository; an org runner serves whatever its
// group reaches. The listing omits runner_group_id, so membership comes off the groups'
// member_runner_ids; a runner no group claims is left ungated, not excluded.
func runnerServes(c *ghCorpus, f map[string]any, repo string, reach map[string][]string, groupOf map[string]string) bool {
	switch str(f["scope"]) {
	case "repo":
		return c.runnerScopeKey(f) == c.full(repo)
	case "org":
		gid := groupOf[decimal(f["runner_id"])]
		return gid == "" || slices.Contains(reach[gid], repo)
	}
	return false
}
