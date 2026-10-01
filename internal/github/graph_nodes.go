package github

import (
	"context"
	"encoding/json"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/praetorian-inc/trajan/internal/graph"
)

var mergeNotes = map[NodeLabel]string{
	Job:    "identityKeys[Job] omits branch by design; merged branches are on properties.branches",
	Secret: "identityKeys[Secret] does not discriminate the scope a secret lives in",
}

// Labels sourced one-record-per-entity. A merge here collapsed two distinct
// records onto one identity and is reported; the reference-derived labels
// (Workflow, Action, Artifact, Cache, Branch) fan in by design.
var recordLabels = map[NodeLabel]bool{
	Organization: true, Repository: true, User: true, Team: true, App: true,
	DeployKey: true, Runner: true, RunnerGroup: true, Ruleset: true, Environment: true,
	Secret: true, Job: true, Tag: true,
}

var orTrueProps = map[string]bool{"is_default_branch_any": true, "branches_slugged": true}

type secretKey struct {
	scope, rawScopeKey, name string
}

type nodeIndex struct {
	*graph.NodeSet[NodeLabel, EdgeType]
	secrets map[secretKey]string
}

func newNodeIndex() *nodeIndex {
	return &nodeIndex{
		NodeSet: graph.NewNodeSet[NodeLabel, EdgeType](ghSchema{}, graph.SetOptions[NodeLabel]{
			OrTrue:      orTrueProps,
			MergeLabels: recordLabels,
			MergeNotes:  mergeNotes,
		}),
		secrets: map[secretKey]string{},
	}
}

// indexSecret keys on the raw scope_key because jobs[].secrets_referenced[]
// carries that form; resolving it by splitting the slug would be ambiguous.
func (s *nodeIndex) indexSecret(scope, rawScopeKey, name string, n *graph.Node[NodeLabel]) {
	if n == nil {
		return
	}
	k := secretKey{scope, rawScopeKey, name}
	if _, dup := s.secrets[k]; !dup {
		s.secrets[k] = n.ID
	}
}

func (s *nodeIndex) secretID(scope, rawScopeKey, name string) (string, bool) {
	id, ok := s.secrets[secretKey{scope, rawScopeKey, name}]
	return id, ok
}

func (s *nodeIndex) branchesIn(repo string) []string {
	var out []string
	s.Each(func(n *graph.Node[NodeLabel]) {
		if n.Labels[0] == Branch && n.Key["repo"] == repo {
			out = append(out, n.Key["name"])
		}
	})
	slices.Sort(out)
	return out
}

// "${{ inputs.artifact-name }}" names whatever the caller passed, so minting a node
// for it splits one artifact in two and leaves no path between the job that writes
// it and the job that reads it.
func identifies(v string) bool { return v != "" && !strings.Contains(v, "${{") }

func buildNodes(ctx context.Context, c *ghCorpus) (*nodeIndex, error) {
	s := newNodeIndex()
	for _, emit := range []func(*ghCorpus, *nodeIndex){
		emitOrganizations, emitRepositories, emitUsers, emitTeams, emitApps,
		emitDeployKeys, emitRunners, emitRunnerGroups, emitRulesets, emitEnvironments,
		emitSecrets, emitBranches, emitTags, emitWorkflows, emitJobs, emitArtifacts,
		emitCaches, emitActions, emitCloudRoles,
	} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		emit(c, s)
	}
	s.SweepIllegal()
	return s, nil
}

func emitOrganizations(c *ghCorpus, s *nodeIndex) {
	for _, r := range c.dirs["org"] {
		n := s.Upsert(Organization, map[string]string{"login": str(r.fields["org"])},
			s.RecordProps(Organization, r.fields), r.rel)
		s.Index("org", r.id, n)
	}
}

func emitRepositories(c *ghCorpus, s *nodeIndex) {
	for _, r := range c.dirs["repos"] {
		n := s.Upsert(Repository, map[string]string{"full_name": c.full(str(r.fields["repo"]))},
			qualifyRepo(c, s.RecordProps(Repository, r.fields)), r.rel)
		s.Index("repo", r.id, n)
	}
}

func emitUsers(c *ghCorpus, s *nodeIndex) {
	for _, r := range c.dirs["principals"] {
		if str(r.fields["kind"]) != "user" {
			continue
		}
		n := s.Upsert(User, map[string]string{"login": str(r.fields["login"])},
			s.RecordProps(User, r.fields), r.rel)
		s.Index("principal", r.id, n)
	}
}

func emitTeams(c *ghCorpus, s *nodeIndex) {
	for _, r := range c.dirs["principals"] {
		if str(r.fields["kind"]) != "team" {
			continue
		}
		n := s.Upsert(Team, map[string]string{"org": c.org, "slug": str(r.fields["slug"])},
			s.RecordProps(Team, r.fields), r.rel)
		s.Index("principal", r.id, n)
	}
}

func emitApps(c *ghCorpus, s *nodeIndex) {
	for _, r := range c.dirs["apps"] {
		n := s.Upsert(App, map[string]string{"app_slug": str(r.fields["app_slug"])},
			s.RecordProps(App, r.fields), r.rel)
		s.Index("app", r.id, n)
	}
}

// The identity is the fingerprint, which every installation of a reused key shares,
// so a per-installation value would be first-writer-wins on the node. Those fields
// are dropped here and carried on INSTALLED_ON instead.
func emitDeployKeys(c *ghCorpus, s *nodeIndex) {
	for _, r := range c.dirs["deploy-keys"] {
		props := qualifyRepo(c, s.RecordProps(DeployKey, r.fields))
		for _, k := range []string{"key_id", "title", "read_only", "can_push", "repo", "added_by", "created_at", "last_used"} {
			delete(props, k)
		}
		n := s.Upsert(DeployKey, map[string]string{"fingerprint": str(r.fields["fingerprint"])}, props, r.rel)
		s.Index("deploy_key", r.id, n)
	}
}

func emitRunners(c *ghCorpus, s *nodeIndex) {
	for _, r := range c.dirs["runners"] {
		n := s.Upsert(Runner, map[string]string{
			"scope":     str(r.fields["scope"]),
			"scope_key": c.runnerScopeKey(r.fields),
			"id":        decimal(r.fields["runner_id"]),
		}, qualifyRepo(c, s.RecordProps(Runner, r.fields)), r.rel)
		s.Index("runner", r.id, n)
	}
}

func emitRunnerGroups(c *ghCorpus, s *nodeIndex) {
	for _, r := range c.dirs["runner-groups"] {
		n := s.Upsert(RunnerGroup, map[string]string{
			"org": str(r.fields["org"]),
			"id":  decimal(r.fields["group_id"]),
		}, s.RecordProps(RunnerGroup, r.fields), r.rel)
		s.Index("runner_group", r.id, n)
	}
}

func emitRulesets(c *ghCorpus, s *nodeIndex) {
	for _, r := range c.dirs["rulesets"] {
		if truthy(r.fields["_empty"]) {
			continue
		}
		props := qualifyRepo(c, s.RecordProps(Ruleset, r.fields))
		props["required_status_check_contexts"] = pluck(objects(r.fields["required_status_checks"]), "context")
		n := s.Upsert(Ruleset, map[string]string{
			"scope":     str(r.fields["scope"]),
			"scope_key": c.rulesetScopeKey(str(r.fields["scope"]), str(r.fields["repo"])),
			"id":        decimal(r.fields["ruleset_id"]),
		}, props, r.rel)
		s.Index("ruleset", r.id, n)
	}
}

func emitEnvironments(c *ghCorpus, s *nodeIndex) {
	for _, r := range c.dirs["environments"] {
		props := s.RecordProps(Environment, r.fields)
		props["protection_rule_types"] = pluck(objects(r.fields["protection_rules_raw"]), "type")
		n := s.Upsert(Environment, map[string]string{
			"repo": c.full(str(r.fields["repo"])),
			"name": str(r.fields["name"]),
		}, props, r.rel)
		s.Index("environment", r.id, n)
	}
}

func emitSecrets(c *ghCorpus, s *nodeIndex) {
	for _, r := range c.dirs["secrets"] {
		scope, name := str(r.fields["scope"]), str(r.fields["name"])
		n := s.Upsert(Secret, map[string]string{
			"scope":     scope,
			"scope_key": c.secretScopeKey(r.fields),
			"name":      name,
		}, qualifyRepo(c, s.RecordProps(Secret, r.fields)), r.rel)
		s.Index("secret", r.id, n)
		s.indexSecret(scope, str(r.fields["scope_key"]), name, n)
	}
	for _, r := range c.dirs["org"] {
		src := r.rel + "#org_actions_secrets"
		for _, e := range objects(r.fields["org_actions_secrets"]) {
			name := str(e["name"])
			n := s.Upsert(Secret, map[string]string{
				"scope": "org", "scope_key": c.org, "name": name,
			}, s.RecordProps(Secret, e), src)
			s.indexSecret("org", c.org, name, n)
		}
	}
}

// Both chain arrays are read: they agree on repo/branch, but is_default_branch and
// has_active_ruleset exist only on branch-coverage while the effective-* controls
// exist only on effective-ruleset.
func emitBranches(c *ghCorpus, s *nodeIndex) {
	for _, src := range [][2]string{
		{"effective-ruleset", "effective_per_branch"},
		{"branch-coverage", "repo_branch_coverage"},
	} {
		for _, e := range c.chainArray(src[0], src[1]) {
			s.Upsert(Branch, map[string]string{
				"repo": c.full(str(e["repo"])),
				"name": str(e["branch"]),
			}, s.RecordProps(Branch, e), c.chainSource(src[0], src[1]))
		}
	}
}

func emitTags(c *ghCorpus, s *nodeIndex) {
	for _, r := range c.dirs["tags"] {
		s.Upsert(Tag, map[string]string{
			"repo": c.full(str(r.fields["repo"])),
			"name": str(r.fields["name"]),
		}, s.RecordProps(Tag, r.fields), r.rel)
	}
}

func emitCloudRoles(c *ghCorpus, s *nodeIndex) {
	inputs := calleeInputs(c)
	for _, r := range c.dirs["jobs"] {
		in := inputs[calleeKey(c, r.fields)]
		for _, cr := range list(r.fields["cloud_roles"]) {
			m := obj(cr)
			id := resolveInput(str(m["identifier"]), in)
			if id == "" {
				continue
			}
			s.Upsert(CloudRole, map[string]string{"identifier": id},
				map[string]any{"provider": m["provider"]}, r.rel)
		}
	}
}

func emitWorkflows(c *ghCorpus, s *nodeIndex) {
	for _, r := range c.dirs["jobs"] {
		props := map[string]any{}
		if v := str(r.fields["workflow_name"]); v != "" {
			props["workflow_name"] = v
		}
		s.Upsert(Workflow, map[string]string{
			"repo": c.full(str(r.fields["repo"])),
			"path": workflowPath(str(r.fields["workflow_filename"])),
		}, props, r.rel)
	}
}

func emitJobs(c *ghCorpus, s *nodeIndex) {
	for _, r := range c.dirs["jobs"] {
		repo := c.full(str(r.fields["repo"]))
		props := s.RecordProps(Job, r.fields)
		if slug := str(r.fields["branch"]); slug != "" {
			name := c.trueBranch[repo+"\x00"+slug]
			if name == "" {
				name = slug
				props["branches_slugged"] = true
			}
			props["branches"] = []any{name}
		}
		props["is_default_branch_any"] = truthy(r.fields["is_default_branch"])
		// Both are per-branch and a job merges its branch-scoped records, so the
		// surviving scalar would be whichever record sorted first; branches and
		// is_default_branch_any carry the same facts across the merge.
		delete(props, "branch")
		delete(props, "is_default_branch")

		perms := obj(r.fields["permissions"])
		scopes := []string{}
		for k, v := range perms {
			if !strings.HasPrefix(k, "_") && str(v) == "write" {
				scopes = append(scopes, k)
			}
		}
		props["token_write_scopes"] = stringArray(scopes)
		props["token_source"] = perms["_source"]

		n := s.Upsert(Job, map[string]string{
			"repo":     repo,
			"workflow": workflowPath(str(r.fields["workflow_filename"])),
			"job_id":   str(r.fields["job_id"]),
		}, props, r.rel)
		s.Index("job", r.id, n)
	}
}

func emitArtifacts(c *ghCorpus, s *nodeIndex) {
	inputs := calleeInputs(c)
	for _, r := range c.dirs["jobs"] {
		repo := c.full(str(r.fields["repo"]))
		in := inputs[calleeKey(c, r.fields)]
		for _, field := range []string{"artifact_reads", "artifact_writes"} {
			for _, e := range objects(r.fields[field]) {
				s.Upsert(Artifact, map[string]string{"repo": repo, "name": resolveInput(str(e["name"]), in)}, nil, r.rel)
			}
		}
	}
}

// A callee names its artifacts "${{ inputs.X }}" and only the call site knows X, so
// without this the caller's writer and the callee's reader land on two Artifact nodes.
// Call sites disagreeing on an input leave it unresolvable rather than guessed.
func calleeInputs(c *ghCorpus) map[[2]string]map[string]any {
	out := map[[2]string]map[string]any{}
	disputed := map[[2]string]map[string]bool{}
	for _, e := range c.chainArray("reusable-callgraph", "edges") {
		callee := obj(e["callee"])
		repo := str(callee["repo"])
		if truthy(callee["is_local"]) || repo == "" {
			repo = str(obj(e["caller"])["repo"])
		}
		k := calleeIdent(c, repo, str(callee["path"]))
		if out[k] == nil {
			out[k] = map[string]any{}
			disputed[k] = map[string]bool{}
		}
		for name, v := range obj(callee["inputs"]) {
			if prev, seen := out[k][name]; seen && str(prev) != str(v) {
				disputed[k][name] = true
			}
			out[k][name] = v
		}
	}
	for k, names := range disputed {
		for name := range names {
			delete(out[k], name)
		}
	}
	return out
}

// A reusable workflow always lives in .github/workflows, so the basename is the
// identity the caller's path and the callee's workflow_filename agree on.
func calleeIdent(c *ghCorpus, repo, workflow string) [2]string {
	return [2]string{c.full(repo), path.Base(workflow)}
}

func calleeKey(c *ghCorpus, f map[string]any) [2]string {
	return calleeIdent(c, str(f["repo"]), str(f["workflow_filename"]))
}

func resolveInput(name string, inputs map[string]any) string {
	ref, ok := strings.CutPrefix(name, "${{")
	if !ok {
		return name
	}
	ref, ok = strings.CutSuffix(ref, "}}")
	if !ok {
		return name
	}
	ref, ok = strings.CutPrefix(strings.TrimSpace(ref), "inputs.")
	if !ok {
		return name
	}
	if v := str(inputs[ref]); identifies(v) {
		return v
	}
	return name
}

func emitCaches(c *ghCorpus, s *nodeIndex) {
	for _, field := range []string{"reads_by_prefix", "writes_by_prefix"} {
		m, _ := c.chains["cache-keyspace"][field].(map[string]any)
		src := c.chainSource("cache-keyspace", field)
		for _, prefix := range slices.Sorted(maps.Keys(m)) {
			for _, e := range objects(m[prefix]) {
				repo := c.full(str(obj(e["job"])["repo"]))
				s.Upsert(Cache, map[string]string{"repo": repo, "key_prefix": prefix}, nil, src)
			}
		}
	}
	for _, e := range c.chainArray("cache-keyspace", "prefix_overlaps") {
		s.Upsert(Cache, map[string]string{"repo": c.full(str(e["repo"])), "key_prefix": str(e["key_prefix"])},
			s.RecordProps(Cache, e), c.chainSource("cache-keyspace", "prefix_overlaps"))
	}
}

func emitActions(c *ghCorpus, s *nodeIndex) {
	for _, r := range c.dirs["jobs"] {
		repo := c.full(str(r.fields["repo"]))
		for _, e := range objects(r.fields["action_refs"]) {
			ref := str(e["uses"])
			if ref == "" || isWorkflowRef(ref) {
				continue
			}
			if rest, local := strings.CutPrefix(ref, "./"); local {
				if repo == "" {
					continue
				}
				ref = repo + "/" + rest
			}
			s.Upsert(Action, map[string]string{"ref": ref}, s.RecordProps(Action, e), r.rel)
		}
	}
}

// Job.workflow and Workflow.path have to join on string equality.
func workflowPath(filename string) string {
	if filename == "" {
		return ""
	}
	return ".github/workflows/" + filename
}

func isWorkflowRef(uses string) bool {
	p := uses
	if i := strings.LastIndex(p, "@"); i >= 0 {
		p = p[:i]
	}
	return strings.Contains(p, ".github/workflows/") &&
		(strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml"))
}

// repo is an identity key on Artifact, Branch, Environment, Job and Workflow, always
// qualified there; a label carrying it as a plain property would otherwise put two
// conventions in one property name once the importer folds key into properties.
func qualifyRepo(c *ghCorpus, props map[string]any) map[string]any {
	if r := str(props["repo"]); r != "" {
		props["repo"] = c.full(r)
	}
	return props
}

func pluck(entries []map[string]any, key string) []any {
	vals := make([]string, 0, len(entries))
	for _, e := range entries {
		vals = append(vals, str(e[key]))
	}
	return stringArray(vals)
}

func stringArray(vals []string) []any {
	slices.Sort(vals)
	out := []any{}
	for _, v := range slices.Compact(vals) {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func decimal(v any) string {
	n, ok := v.(json.Number)
	if !ok {
		return str(v)
	}
	i, err := n.Int64()
	if err != nil {
		return n.String()
	}
	return strconv.FormatInt(i, 10)
}
