package graph

import (
	"cmp"
	"context"
	"encoding/json"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
)

type findingRef struct {
	RuleID      string `json:"rule_id"`
	Fingerprint string `json:"fingerprint"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Target      string `json:"target"`
	SubjectKind string `json:"subject_kind"`
	SubjectID   string `json:"subject_id"`
	Title       string `json:"title"`
}

// findings is a sibling of properties, not a member: Neo4j property values
// cannot be arrays of maps, so nesting it would make nodes.json un-importable.
type node struct {
	ID         string            `json:"id"`
	Labels     []NodeLabel       `json:"labels"`
	Key        map[string]string `json:"key"`
	Properties map[string]any    `json:"properties"`
	Findings   []findingRef      `json:"findings"`
}

type identityMerge struct {
	Label         NodeLabel `json:"label"`
	SourceRecords int       `json:"source_records"`
	Nodes         int       `json:"nodes"`
	MergedRecords int       `json:"merged_records"`
	Note          string    `json:"note"`
}

type propertyConflict struct {
	Label     NodeLabel `json:"label"`
	Property  string    `json:"property"`
	Discarded int       `json:"discarded"`
}

var mergeNotes = map[NodeLabel]string{
	Job:    "identityKeys[Job] omits branch by design; merged branches are on properties.branches",
	Secret: "identityKeys[Secret] does not discriminate the scope a secret lives in",
}

// Labels sourced one-record-per-entity. A merge here collapsed two distinct
// records onto one identity and is reported; the reference-derived labels
// (Workflow, Action, Artifact, Cache, Branch) fan in by design.
var recordLabels = map[NodeLabel]bool{
	Organization: true, Repository: true, User: true, Team: true, App: true,
	DeployKey: true, RunnerGroup: true, Ruleset: true, Environment: true,
	Secret: true, Job: true,
}

// Cleared the moment any real source backs the node.
var falseWinsProps = map[string]bool{"observed_only": true, "synthetic": true}

var orTrueProps = map[string]bool{"is_default_branch_any": true, "branches_slugged": true}

func esc(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "|", `\|`)
}

func nodeID(l NodeLabel, key map[string]string) string {
	parts := []string{string(l)}
	for _, k := range IdentityKey(l) {
		parts = append(parts, esc(key[k]))
	}
	return strings.Join(parts, "|")
}

type conflictKey struct {
	label    NodeLabel
	property string
}

type secretKey struct {
	scope, rawScopeKey, name string
}

type nodeSet struct {
	byID map[string]*node

	// subjects indexes a finding's (subject.kind, subject.id) onto the node the
	// record produced. subject.id is a record _id and is never parsed.
	subjects   map[string]map[string]string
	secrets    map[secretKey]string
	sourceRecs map[NodeLabel]int
	incomplete map[NodeLabel]int
	conflicts  map[conflictKey]int
}

func newNodeSet() *nodeSet {
	return &nodeSet{
		byID:       map[string]*node{},
		subjects:   map[string]map[string]string{},
		secrets:    map[secretKey]string{},
		sourceRecs: map[NodeLabel]int{},
		incomplete: map[NodeLabel]int{},
		conflicts:  map[conflictKey]int{},
	}
}

// upsert merges a source record into the node its identity tuple names, and
// returns nil when any identity value is empty — a placeholder would have to
// invent identity, and every consumer asks reachability questions.
func (s *nodeSet) upsert(l NodeLabel, key map[string]string, props map[string]any, source string) *node {
	k := make(map[string]string, len(IdentityKey(l)))
	for _, name := range IdentityKey(l) {
		v := key[name]
		if v == "" {
			s.incomplete[l]++
			return nil
		}
		k[name] = v
	}
	id := nodeID(l, k)
	s.sourceRecs[l]++

	n := s.byID[id]
	if n == nil {
		n = &node{ID: id, Labels: []NodeLabel{l}, Key: k, Properties: map[string]any{}, Findings: []findingRef{}}
		s.byID[id] = n
	}
	s.merge(n, props)
	if source != "" {
		s.merge(n, map[string]any{"_source": []any{source}})
	}
	n.Properties["graph_id"] = id
	return n
}

func (s *nodeSet) merge(n *node, props map[string]any) {
	for k, v := range props {
		old, seen := n.Properties[k]
		if !seen {
			n.Properties[k] = v
			continue
		}
		switch {
		case falseWinsProps[k]:
			n.Properties[k] = truthy(old) && truthy(v)
		case orTrueProps[k]:
			n.Properties[k] = truthy(old) || truthy(v)
		default:
			ao, aok := old.([]any)
			an, nok := v.([]any)
			if aok && nok {
				n.Properties[k] = unionArray(ao, an)
				continue
			}
			if scalarKey(old) != scalarKey(v) {
				s.conflicts[conflictKey{n.Labels[0], k}]++
			}
		}
	}
}

func (s *nodeSet) index(kind, recordID string, n *node) {
	if n == nil || recordID == "" {
		return
	}
	if s.subjects[kind] == nil {
		s.subjects[kind] = map[string]string{}
	}
	if _, dup := s.subjects[kind][recordID]; !dup {
		s.subjects[kind][recordID] = n.ID
	}
}

// indexSecret keys on the raw scope_key because jobs[].secrets_referenced[]
// carries that form; resolving it by splitting the slug would be ambiguous.
func (s *nodeSet) indexSecret(scope, rawScopeKey, name string, n *node) {
	if n == nil {
		return
	}
	k := secretKey{scope, rawScopeKey, name}
	if _, dup := s.secrets[k]; !dup {
		s.secrets[k] = n.ID
	}
}

func (s *nodeSet) get(id string) *node { return s.byID[id] }

func (s *nodeSet) has(id string) bool { _, ok := s.byID[id]; return ok }

func (s *nodeSet) subject(kind, recordID string) (string, bool) {
	id, ok := s.subjects[kind][recordID]
	return id, ok
}

func (s *nodeSet) secretID(scope, rawScopeKey, name string) (string, bool) {
	id, ok := s.secrets[secretKey{scope, rawScopeKey, name}]
	return id, ok
}

func (s *nodeSet) all() []node {
	out := make([]node, 0, len(s.byID))
	for _, n := range s.byID {
		out = append(out, *n)
	}
	slices.SortFunc(out, func(a, b node) int {
		return cmp.Or(cmp.Compare(a.Labels[0], b.Labels[0]), cmp.Compare(a.ID, b.ID))
	})
	return out
}

func (s *nodeSet) byLabel() map[NodeLabel]int {
	out := make(map[NodeLabel]int, len(identityKeys))
	for _, l := range NodeLabels() {
		out[l] = 0
	}
	for _, n := range s.byID {
		out[n.Labels[0]]++
	}
	return out
}

func (s *nodeSet) merges() []identityMerge {
	counts := s.byLabel()
	out := []identityMerge{}
	for _, l := range NodeLabels() {
		src := s.sourceRecs[l]
		if !recordLabels[l] || src == 0 || src == counts[l] {
			continue
		}
		out = append(out, identityMerge{l, src, counts[l], src - counts[l], mergeNotes[l]})
	}
	return out
}

func (s *nodeSet) propertyConflicts() []propertyConflict {
	out := make([]propertyConflict, 0, len(s.conflicts))
	for k, n := range s.conflicts {
		out = append(out, propertyConflict{k.label, k.property, n})
	}
	slices.SortFunc(out, func(a, b propertyConflict) int {
		return cmp.Or(cmp.Compare(b.Discarded, a.Discarded),
			cmp.Compare(a.Label, b.Label), cmp.Compare(a.Property, b.Property))
	})
	return out
}

// incompleteIdentities counts candidates dropped by upsert, per label, so an
// unbacked endpoint is visible in the summary rather than silently absent.
func (s *nodeSet) incompleteIdentities() map[NodeLabel]int {
	return maps.Clone(s.incomplete)
}

func buildNodes(ctx context.Context, c *corpus) (*nodeSet, error) {
	s := newNodeSet()
	for _, emit := range []func(*corpus, *nodeSet){
		emitOrganizations, emitRepositories, emitUsers, emitTeams, emitApps,
		emitDeployKeys, emitRunnerGroups, emitRulesets, emitEnvironments,
		emitSecrets, emitBranches, emitWorkflows, emitJobs, emitArtifacts,
		emitCaches, emitActions, emitCloudRoles,
	} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		emit(c, s)
	}
	return s, nil
}

func emitOrganizations(c *corpus, s *nodeSet) {
	for _, r := range c.dirs["org"] {
		n := s.upsert(Organization, map[string]string{"login": str(r.fields["org"])},
			recordProps(Organization, r.fields), r.rel)
		s.index("org", r.id, n)
	}
}

func emitRepositories(c *corpus, s *nodeSet) {
	for _, r := range c.dirs["repos"] {
		n := s.upsert(Repository, map[string]string{"full_name": c.full(str(r.fields["repo"]))},
			recordProps(Repository, r.fields), r.rel)
		s.index("repo", r.id, n)
	}
}

func emitUsers(c *corpus, s *nodeSet) {
	for _, r := range c.dirs["principals"] {
		if str(r.fields["kind"]) != "user" {
			continue
		}
		n := s.upsert(User, map[string]string{"login": str(r.fields["login"])},
			recordProps(User, r.fields), r.rel)
		s.index("principal", r.id, n)
	}
}

func emitTeams(c *corpus, s *nodeSet) {
	for _, r := range c.dirs["principals"] {
		if str(r.fields["kind"]) != "team" {
			continue
		}
		n := s.upsert(Team, map[string]string{"org": c.org, "slug": str(r.fields["slug"])},
			recordProps(Team, r.fields), r.rel)
		s.index("principal", r.id, n)
	}
}

func emitApps(c *corpus, s *nodeSet) {
	for _, r := range c.dirs["apps"] {
		n := s.upsert(App, map[string]string{"app_slug": str(r.fields["app_slug"])},
			recordProps(App, r.fields), r.rel)
		s.index("app", r.id, n)
	}
}

func emitDeployKeys(c *corpus, s *nodeSet) {
	for _, r := range c.dirs["deploy-keys"] {
		n := s.upsert(DeployKey, map[string]string{"fingerprint": str(r.fields["fingerprint"])},
			recordProps(DeployKey, r.fields), r.rel)
		s.index("deploy_key", r.id, n)
	}
}

func emitRunnerGroups(c *corpus, s *nodeSet) {
	for _, r := range c.dirs["runner-groups"] {
		n := s.upsert(RunnerGroup, map[string]string{
			"org": str(r.fields["org"]),
			"id":  decimal(r.fields["group_id"]),
		}, recordProps(RunnerGroup, r.fields), r.rel)
		s.index("runner_group", r.id, n)
	}
}

func emitRulesets(c *corpus, s *nodeSet) {
	for _, r := range c.dirs["rulesets"] {
		if truthy(r.fields["_empty"]) {
			continue
		}
		n := s.upsert(Ruleset, map[string]string{
			"scope": str(r.fields["scope"]),
			"id":    decimal(r.fields["ruleset_id"]),
		}, recordProps(Ruleset, r.fields), r.rel)
		s.index("ruleset", r.id, n)
	}
}

func emitEnvironments(c *corpus, s *nodeSet) {
	for _, r := range c.dirs["environments"] {
		n := s.upsert(Environment, map[string]string{
			"repo": c.full(str(r.fields["repo"])),
			"name": str(r.fields["name"]),
		}, recordProps(Environment, r.fields), r.rel)
		s.index("environment", r.id, n)
	}
}

func emitSecrets(c *corpus, s *nodeSet) {
	for _, r := range c.dirs["secrets"] {
		scope, name := str(r.fields["scope"]), str(r.fields["name"])
		n := s.upsert(Secret, map[string]string{
			"scope":     scope,
			"scope_key": c.secretScopeKey(r.fields),
			"name":      name,
		}, recordProps(Secret, r.fields), r.rel)
		s.index("secret", r.id, n)
		s.indexSecret(scope, str(r.fields["scope_key"]), name, n)
	}
	for _, r := range c.dirs["org"] {
		src := r.rel + "#org_actions_secrets"
		for _, e := range objects(r.fields["org_actions_secrets"]) {
			name := str(e["name"])
			n := s.upsert(Secret, map[string]string{
				"scope": "org", "scope_key": c.org, "name": name,
			}, recordProps(Secret, e), src)
			s.indexSecret("org", c.org, name, n)
		}
	}
}

// Branch takes both chain arrays: they share all 162 _ids and agree on
// repo/branch, but is_default_branch and has_active_ruleset exist only on
// branch-coverage while the effective-* controls exist only on effective-ruleset.
func emitBranches(c *corpus, s *nodeSet) {
	for _, src := range [][2]string{
		{"effective-ruleset", "effective_per_branch"},
		{"branch-coverage", "repo_branch_coverage"},
	} {
		for _, e := range c.chainArray(src[0], src[1]) {
			s.upsert(Branch, map[string]string{
				"repo": c.full(str(e["repo"])),
				"name": str(e["branch"]),
			}, recordProps(Branch, e), c.chainSource(src[0], src[1]))
		}
	}
}

func emitCloudRoles(c *corpus, s *nodeSet) {
	for _, r := range c.dirs["jobs"] {
		for _, cr := range list(r.fields["cloud_roles"]) {
			m := obj(cr)
			id := str(m["identifier"])
			if id == "" {
				continue
			}
			s.upsert(CloudRole, map[string]string{"identifier": id},
				map[string]any{"provider": m["provider"]}, r.rel)
		}
	}
}

func emitWorkflows(c *corpus, s *nodeSet) {
	for _, r := range c.dirs["jobs"] {
		props := map[string]any{}
		if v, ok := r.fields["workflow_name"]; ok {
			props["workflow_name"] = v
		}
		s.upsert(Workflow, map[string]string{
			"repo": c.full(str(r.fields["repo"])),
			"path": workflowPath(str(r.fields["workflow_filename"])),
		}, props, r.rel)
	}
}

func emitJobs(c *corpus, s *nodeSet) {
	for _, r := range c.dirs["jobs"] {
		repo := c.full(str(r.fields["repo"]))
		props := recordProps(Job, r.fields)
		if slug := str(r.fields["branch"]); slug != "" {
			name, ok := c.trueBranch[repo+"\x00"+slug]
			if !ok {
				name = slug
				props["branches_slugged"] = true
			}
			props["branches"] = []any{name}
		}
		props["is_default_branch_any"] = truthy(r.fields["is_default_branch"])
		n := s.upsert(Job, map[string]string{
			"repo":     repo,
			"workflow": workflowPath(str(r.fields["workflow_filename"])),
			"job_id":   str(r.fields["job_id"]),
		}, props, r.rel)
		s.index("job", r.id, n)
	}
}

func emitArtifacts(c *corpus, s *nodeSet) {
	for _, r := range c.dirs["jobs"] {
		repo := c.full(str(r.fields["repo"]))
		for _, field := range []string{"artifact_reads", "artifact_writes"} {
			for _, e := range objects(r.fields[field]) {
				s.upsert(Artifact, map[string]string{"repo": repo, "name": str(e["name"])}, nil, r.rel)
			}
		}
	}
}

// Cache comes from cache-keyspace only: jobs[].cache_*[].scope embeds a
// differently-derived prefix ("scope-prefix:build-tools-v3-pinned-2026-05")
// that does not round-trip to the chain's key ("build/tools").
func emitCaches(c *corpus, s *nodeSet) {
	for _, field := range []string{"reads_by_prefix", "writes_by_prefix"} {
		m, _ := c.chains["cache-keyspace"][field].(map[string]any)
		for _, prefix := range slices.Sorted(maps.Keys(m)) {
			s.upsert(Cache, map[string]string{"key_prefix": prefix}, nil,
				c.chainSource("cache-keyspace", field))
		}
	}
	for _, e := range c.chainArray("cache-keyspace", "prefix_overlaps") {
		s.upsert(Cache, map[string]string{"key_prefix": str(e["key_prefix"])},
			recordProps(Cache, e), c.chainSource("cache-keyspace", "prefix_overlaps"))
	}
}

func emitActions(c *corpus, s *nodeSet) {
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
			s.upsert(Action, map[string]string{"ref": ref}, recordProps(Action, e), r.rel)
		}
	}
}

// workflowPath returns the path Workflow is keyed on so Job.workflow and
// Workflow.path join on string equality.
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

// recordProps copies the Neo4j-legal top-level fields of a source record.
// Nested structure is dropped: Neo4j cannot store it as a property and the
// detail already lives in 10-normalize.
func recordProps(l NodeLabel, fields map[string]any) map[string]any {
	ident := IdentityKey(l)
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		if k == "_id" || k == "_provenance" || slices.Contains(ident, k) || !legalProp(v) {
			continue
		}
		out[k] = v
	}
	return out
}

func legalProp(v any) bool {
	switch t := v.(type) {
	case nil, bool, string, json.Number, float64:
		return true
	case []any:
		return primitiveArray(t)
	}
	return false
}

// Neo4j array properties must be homogeneous and cannot contain null.
func primitiveArray(a []any) bool {
	kind := ""
	for _, e := range a {
		k := primKind(e)
		if k == "" || (kind != "" && k != kind) {
			return false
		}
		kind = k
	}
	return true
}

func primKind(v any) string {
	switch v.(type) {
	case string:
		return "s"
	case bool:
		return "b"
	case json.Number, float64:
		return "n"
	}
	return ""
}

func unionArray(a, b []any) []any {
	out := make([]any, 0, len(a)+len(b))
	seen := make(map[string]bool, len(a)+len(b))
	for _, e := range slices.Concat(a, b) {
		k := scalarKey(e)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return lessPrimitive(out[i], out[j]) })
	return out
}

func lessPrimitive(a, b any) bool {
	na, aok := a.(json.Number)
	nb, bok := b.(json.Number)
	if aok && bok {
		fa, ea := na.Float64()
		fb, eb := nb.Float64()
		if ea == nil && eb == nil && fa != fb {
			return fa < fb
		}
	}
	return scalarKey(a) < scalarKey(b)
}

func scalarKey(v any) string {
	switch t := v.(type) {
	case nil:
		return "\x00null"
	case string:
		return "s" + t
	case bool:
		return "b" + strconv.FormatBool(t)
	case json.Number:
		return "n" + t.String()
	case float64:
		return "n" + strconv.FormatFloat(t, 'g', -1, 64)
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, scalarKey(e))
		}
		return "a[" + strings.Join(parts, ",") + "]"
	}
	return "?"
}
