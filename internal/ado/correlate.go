package ado

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// hashKey produces a bounded, collision-safe filename stem for edges whose
// natural key (ACL token + identity descriptor) can exceed the 255-byte path
// limit. The readable components stay as fields on the record.
func hashKey(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:16])
}

// correlate reads the normalized corpus back as generic maps and derives the
// structural edges plus the three settings-resolution joins. Derived/attack
// (taint) edges are a later pass.
func correlate(ctx context.Context, prior engine.PriorPhase, cp engine.CurrentPhase, org string, timer *engine.PhaseTimer) error {
	pipelines, err := loadRecords(prior, "10-normalize/pipelines")
	if err != nil {
		return fmt.Errorf("correlate: load pipelines: %w", err)
	}
	repos, err := loadRecords(prior, "10-normalize/repos")
	if err != nil {
		return fmt.Errorf("correlate: load repos: %w", err)
	}
	projectsRec, err := loadRecords(prior, "10-normalize/projects")
	if err != nil {
		return fmt.Errorf("correlate: load projects: %w", err)
	}
	policies, err := loadRecords(prior, "10-normalize/policies")
	if err != nil {
		return fmt.Errorf("correlate: load policies: %w", err)
	}
	jobs, err := loadRecords(prior, "10-normalize/jobs")
	if err != nil {
		return fmt.Errorf("correlate: load jobs: %w", err)
	}

	for _, step := range []func() error{
		func() error { return deriveRunsAs(cp, timer, pipelines, projectsRec) },
		func() error { return derivePolicyAttribution(cp, timer, policies, repos) },
		func() error { return deriveBranches(cp, timer, pipelines, policies, repos) },
		func() error { return deriveEffectiveRoles(ctx, prior, cp, timer, org) },
		func() error { return deriveMemberOf(prior, cp, timer, org) },
		func() error { return deriveJobResourceEdges(prior, cp, timer, jobs) },
	} {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

// clampScope resolves the job-auth scope: effective = "project" when the project
// enforces (or enforcement is unobserved — fail closed), else the requested scope.
// Shared by the :Pipeline node (identity_scope) and the RUNS_AS edge.
func clampScope(requested string, enforced, observed bool) (effective, identityScope, provenance string) {
	effective = requested
	if enforced || !observed {
		effective = "project"
	}
	identityScope = "project"
	if effective == "projectCollection" {
		identityScope = "collection"
	}
	provenance = "observed"
	if !observed {
		provenance = "unknown"
	}
	return
}

// deriveRunsAs — JOIN #1: 3-level job-auth clamp. effective = "project" if the
// project (or org, unknown) enforces enforceJobAuthScope, else the pipeline's
// requested scope. Emits a runs-as edge per pipeline.
func deriveRunsAs(cp engine.CurrentPhase, timer *engine.PhaseTimer, pipelines, projectsRec []map[string]any) error {
	type enf struct{ enforced, observed bool }
	enforceByProject := map[string]enf{}
	for _, p := range projectsRec {
		enforceByProject[mStr(p, "project")] = enf{mBool(p, "limit_job_auth_scope_to_current_project"), mBool(p, "settings_observed")}
	}
	for _, pl := range pipelines {
		project := mStr(pl, "project")
		requested := mStr(pl, "job_authorization_scope") // "project" | "projectCollection"
		e := enforceByProject[project]
		effective, scope, provenance := clampScope(requested, e.enforced, e.observed)
		rec := map[string]any{
			"kind":                "RUNS_AS",
			"pipeline_id":         mInt64(pl, "id"),
			"project":             project,
			"requested_scope":     requested,
			"effective_scope":     effective,
			"identity_scope":      scope,
			"enforced_by_project": e.enforced,
			"enforce_provenance":  provenance,
			"org_provenance":      "unknown",
		}
		key := fmt.Sprintf("%s__%d", project, mInt64(pl, "id"))
		if err := emit(cp, timer, engine.NormalizeADOEdges("runs-as", key), rec); err != nil {
			return err
		}
	}
	return nil
}

// derivePolicyAttribution — JOIN #2: attach each BranchPolicy to repos by scope
// (repositoryId, null=all in project); materialize the branch from refName; emit
// BUILD_VALIDATES for build-validation policies.
func derivePolicyAttribution(cp engine.CurrentPhase, timer *engine.PhaseTimer, policies, repos []map[string]any) error {
	reposByProject := map[string][]map[string]any{}
	for _, r := range repos {
		proj := mStr(r, "project")
		reposByProject[proj] = append(reposByProject[proj], r)
	}
	for _, pol := range policies {
		project := mStr(pol, "project")
		for _, sc := range mList(pol, "scope") {
			scope := entMap(sc)
			repoID := entStr(scope["repositoryId"]) // "" => project-wide
			refName := entStr(scope["refName"])
			targets := reposByProject[project]
			if repoID != "" {
				targets = filterReposByID(targets, repoID)
			}
			for _, r := range targets {
				matchKind := entStr(scope["matchKind"])
				branch := stripRef(refName)
				branchID := project + "/" + mStr(r, "name") + "@" + branch
				rec := map[string]any{
					"kind":    "HAS_POLICY",
					"project": project,
					"repo":    mStr(r, "name"),
					// stripped to match the :Branch node/DEFINED_BY join key.
					"branch":    branch,
					"branch_id": branchID,
					// Prefix => refName is a subtree prefix (protects the whole
					// subtree), not a concrete branch — load-bearing for attribution.
					"match_kind":   matchKind,
					"is_prefix":    matchKind == "Prefix",
					"policy_type":  mStr(pol, "policy_type"),
					"config_id":    mInt64(pol, "config_id"),
					"is_blocking":  mBool(pol, "is_blocking"),
					"is_enabled":   mBool(pol, "is_enabled"),
					"project_wide": repoID == "",
				}
				// A single config can carry multiple scope[] entries on the same
				// repo+ref differing only by matchKind, or a project-wide (null repo)
				// scope alongside a repo-specific one — key on both so neither is lost.
				scopeDisc := repoID
				if scopeDisc == "" {
					scopeDisc = "all"
				}
				key := fmt.Sprintf("%s__%s__%d__%s__%s__%s", adoSafe(project), adoSafe(mStr(r, "name")), mInt64(pol, "config_id"), adoSafe(refName), adoSafe(matchKind), adoSafe(scopeDisc))
				if err := emit(cp, timer, engine.NormalizeADOEdges("has-policy", key), rec); err != nil {
					return err
				}
				if bdID := mInt64(mMap(pol, "settings"), "buildDefinitionId"); bdID != 0 {
					bv := map[string]any{
						"kind":                "BUILD_VALIDATES",
						"project":             project,
						"repo":                mStr(r, "name"),
						"branch":              branch,
						"branch_id":           branchID,
						"config_id":           mInt64(pol, "config_id"),
						"build_definition_id": bdID,
						"is_blocking":         mBool(pol, "is_blocking"),
					}
					if err := emit(cp, timer, engine.NormalizeADOEdges("build-validates", key), bv); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func filterReposByID(repos []map[string]any, id string) []map[string]any {
	var out []map[string]any
	for _, r := range repos {
		if mStr(r, "id") == id {
			out = append(out, r)
		}
	}
	return out
}

// deriveEffectiveRoles — JOIN #3: decode each ACL's effectiveAllow bitmask into
// action names (per its security namespace) and expand group descriptors to
// leaf members via graph memberships. Emits a HAS_ROLE edge per ACE.
func deriveEffectiveRoles(ctx context.Context, prior engine.PriorPhase, cp engine.CurrentPhase, timer *engine.PhaseTimer, org string) error {
	nsActions := loadNamespaceActions(prior, org)
	memberships := loadMemberships(prior, org)
	idIndex := aceIdentityIndex(prior, org)
	repoIdx, scIdx, projIdx, err := roleTokenIndexes(prior)
	if err != nil {
		return err
	}

	sources := []struct {
		dir string
		ns  string
	}{
		{"00-collect/acl-repo", gitNS},
		{"00-collect/acl-build", buildNS},
		{"00-collect/acl-endpoint", endpointNS},
	}
	for _, src := range sources {
		if err := ctx.Err(); err != nil {
			return err
		}
		files, err := prior.IterJSON(src.dir)
		if err != nil {
			return fmt.Errorf("correlate: load %s: %w", src.dir, err)
		}
		actions := nsActions[src.ns]
		for _, f := range files {
			data := entDataOf(f.Data)
			for _, raw := range entListOrEmpty(data["value"]) {
				acl := entMap(raw)
				token := entStr(acl["token"])
				for desc, aceRaw := range entObj(acl, "acesDictionary") {
					ace := entMap(aceRaw)
					eff := effectiveAllowMask(ace)
					// ACL descriptors are legacy identity descriptors; bridge to the
					// graph subject descriptor so the principal node + members resolve.
					graphDesc := aceGraphDescriptor(desc, idIndex)
					resKind, resID := resolveRoleToken(token, repoIdx, scIdx, projIdx)
					rec := map[string]any{
						"kind":              "HAS_ROLE",
						"descriptor":        desc,
						"graph_descriptor":  graphDesc,
						"token":             token,
						"namespace":         src.ns,
						"resource_kind":     resKind,
						"resource_id":       resID,
						"resource_resolved": resID != "",
						"allowed_actions":   decodeActions(eff, actions),
						"effective_allow":   eff,
						"expanded_members":  expandMembers(graphDesc, memberships),
					}
					key := hashKey(src.ns, token, desc)
					if err := emit(cp, timer, engine.NormalizeADOEdges("has-role", key), rec); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// roleTokenIndexes builds the lookups that resolve a HAS_ROLE ACL token to the
// node it grants on: repos by GUID, service connections by id, projects by GUID.
func roleTokenIndexes(prior engine.PriorPhase) (repoIdx, scIdx, projIdx map[string]string, err error) {
	repoIdx, scIdx, projIdx = map[string]string{}, map[string]string{}, map[string]string{}
	repos, err := loadRecords(prior, "10-normalize/repos")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("correlate: load repos: %w", err)
	}
	for _, r := range repos {
		repoIdx[mStr(r, "id")] = mStr(r, "_id")
	}
	scs, err := loadRecords(prior, "10-normalize/service-connections")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("correlate: load service-connections: %w", err)
	}
	for _, s := range scs {
		scIdx[mStr(s, "id")] = mStr(s, "_id")
	}
	projs, err := loadRecords(prior, "10-normalize/projects")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("correlate: load projects: %w", err)
	}
	for _, p := range projs {
		projIdx[mStr(p, "id")] = mStr(p, "_id")
	}
	return repoIdx, scIdx, projIdx, nil
}

// resolveRoleToken maps a security-namespace ACL token to the emitted node _id it
// scopes: "repoV2/<projGuid>/<repoGuid>" -> Repository, "endpoints/<projGuid>/<id>"
// -> ServiceConnection, a bare "<projGuid>" -> Project. Unresolvable (collection
// root, deleted resource) returns "".
func resolveRoleToken(token string, repoIdx, scIdx, projIdx map[string]string) (kind, nodeID string) {
	parts := strings.Split(token, "/")
	switch {
	case len(parts) >= 3 && parts[0] == "repoV2":
		return "Repository", repoIdx[parts[2]]
	case len(parts) >= 3 && parts[0] == "endpoints":
		return "ServiceConnection", scIdx[parts[2]]
	case len(parts) == 1 && parts[0] != "":
		if id := projIdx[parts[0]]; id != "" {
			return "Project", id
		}
	}
	return "", ""
}

// effectiveAllowMask selects an ACE's effective permission bits. Only fall back
// to the local allow when effectiveAllow is ABSENT — a present effectiveAllow of
// 0 is a real deny, not an unknown.
func effectiveAllowMask(ace map[string]any) int64 {
	if e := entGetIn(ace, "extendedInfo", "effectiveAllow"); e != nil {
		return entInt64(e)
	}
	return entInt64(ace["allow"])
}

// aceIdentityIndex maps an ACL ACE identity (the token after ";") to the graph
// subject descriptor that carries it, for both forms that resolve to an emitted
// principal node:
//   - group SIDs (S-1-…), base64-encoded in the vssgp./aadgp. group descriptor;
//   - service identities (<org>:Build:<guid>), base64-encoded in the svc. user
//     descriptor a Microsoft.TeamFoundation.ServiceIdentity ACE references.
//
// Built-in server SIDs the Graph API does not enumerate resolve to "" and stay
// unexpanded (the raw descriptor is still kept on the HAS_ROLE record).
func aceIdentityIndex(prior engine.PriorPhase, org string) map[string]string {
	graph := entLoadData(prior, engine.CollectADOGraph(org))
	idx := map[string]string{}
	for _, raw := range entListOrEmpty(graph["groups"]) {
		desc := entStr(entMap(raw)["descriptor"])
		if sid := decodeGraphSID(desc); sid != "" {
			idx[sid] = desc
		}
	}
	for _, raw := range entListOrEmpty(graph["users"]) {
		u := entMap(raw)
		desc := entStr(u["descriptor"])
		if desc == "" {
			continue
		}
		if inner := decodeSubjectDescriptor(desc); inner != "" {
			idx[inner] = desc
		}
		// A direct AAD-user ACE is a ClaimsIdentity keyed by UPN/mail, not a SID —
		// index those (lowercased) so the user's HAS_ROLE resolves to its node.
		for _, k := range []string{entStr(u["principalName"]), entStr(u["mailAddress"]), entStr(u["domain"]) + "\\" + entStr(u["principalName"])} {
			if k != "" && k != "\\" {
				idx[strings.ToLower(k)] = desc
			}
		}
	}
	return idx
}

func decodeGraphSID(desc string) string {
	for _, p := range []string{"vssgp.", "aadgp."} {
		if !strings.HasPrefix(desc, p) {
			continue
		}
		b := desc[len(p):]
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
			if dec, err := enc.DecodeString(b); err == nil {
				if s := string(dec); strings.HasPrefix(s, "S-1-") {
					return s
				}
			}
		}
	}
	return ""
}

// decodeSubjectDescriptor returns the identity string a graph user descriptor
// (<prefix>.<base64>) encodes — a svc. build-service descriptor decodes to
// "<org>:Build:<guid>", exactly the id a ServiceIdentity ACE references.
func decodeSubjectDescriptor(desc string) string {
	i := strings.IndexByte(desc, '.')
	if i < 0 {
		return ""
	}
	b := desc[i+1:]
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding} {
		if dec, err := enc.DecodeString(b); err == nil {
			return string(dec)
		}
	}
	return ""
}

// aceGraphDescriptor translates an ACL ACE identity descriptor to the graph
// descriptor of the principal it names (group SID or service identity), or ""
// when the identity is not present in the collected graph.
func aceGraphDescriptor(aceDesc string, idIndex map[string]string) string {
	i := strings.Index(aceDesc, ";")
	if i < 0 {
		return ""
	}
	id := aceDesc[i+1:]
	if d, ok := idIndex[id]; ok { // exact: SID or <org>:Build:<guid>
		return d
	}
	return idIndex[strings.ToLower(id)] // case-insensitive: ClaimsIdentity UPN/mail
}

func loadNamespaceActions(prior engine.PriorPhase, org string) map[string]map[int64]string {
	out := map[string]map[int64]string{}
	for _, raw := range entLoadList(prior, engine.CollectADOSecurityNS(org)) {
		ns := entMap(raw)
		id := entStr(ns["namespaceId"])
		if id == "" {
			continue
		}
		bits := map[int64]string{}
		for _, a := range entListOrEmpty(ns["actions"]) {
			am := entMap(a)
			bits[entInt64(am["bit"])] = entStr(am["name"])
		}
		out[id] = bits
	}
	return out
}

func decodeActions(mask int64, actions map[int64]string) []any {
	var names []string
	for bit, name := range actions {
		if mask&bit != 0 {
			names = append(names, name)
		}
	}
	slices.Sort(names) // deterministic output (map iteration is randomized)
	out := make([]any, len(names))
	for i, n := range names {
		out[i] = n
	}
	return out
}

func loadMemberships(prior engine.PriorPhase, org string) map[string][]string {
	graph := entLoadData(prior, engine.CollectADOGraph(org))
	out := map[string][]string{}
	for container, raw := range entObj(graph, "memberships") {
		for _, m := range entListOrEmpty(raw) {
			if md := entStr(entMap(m)["memberDescriptor"]); md != "" {
				out[container] = append(out[container], md)
			}
		}
	}
	return out
}

// expandMembers walks memberships (direction=down) to the leaf descriptors under
// a group, with cycle detection. A non-group (leaf) descriptor returns itself.
func expandMembers(desc string, memberships map[string][]string) []any {
	seen := map[string]bool{}
	var leaves []string
	var walk func(d string)
	walk = func(d string) {
		if seen[d] {
			return
		}
		seen[d] = true
		children, ok := memberships[d]
		if !ok || len(children) == 0 {
			if d != desc {
				leaves = append(leaves, d)
			}
			return
		}
		for _, c := range children {
			walk(c)
		}
	}
	walk(desc)
	slices.Sort(leaves) // deterministic output
	out := make([]any, len(leaves))
	for i, l := range leaves {
		out[i] = l
	}
	return out
}

// deriveJobResourceEdges resolves the job-level YAML references (variable-group
// names, service-connection names) to their concrete resource ids.
func deriveJobResourceEdges(prior engine.PriorPhase, cp engine.CurrentPhase, timer *engine.PhaseTimer, jobs []map[string]any) error {
	type vgRef struct {
		id    int64
		owner string
	}
	type scRef struct{ id, owner string }
	vgByProjectName := map[string]map[string]vgRef{}
	scByProjectName := map[string]map[string]scRef{}
	vgs, err := loadRecords(prior, "10-normalize/variable-groups")
	if err != nil {
		return fmt.Errorf("correlate: load variable-groups: %w", err)
	}
	// A shared resource is visible (and referable by name) in every project it is
	// shared into, so register its name under all of them, resolving to the single
	// canonical (owner-keyed) node — carrying owner_project so the edge binds to
	// the node _id "owner/id" rather than the consuming project.
	for _, g := range vgs {
		for _, proj := range visibleProjects(g) {
			if vgByProjectName[proj] == nil {
				vgByProjectName[proj] = map[string]vgRef{}
			}
			vgByProjectName[proj][mStr(g, "name")] = vgRef{mInt64(g, "id"), mStr(g, "owner_project")}
		}
	}
	scs, err := loadRecords(prior, "10-normalize/service-connections")
	if err != nil {
		return fmt.Errorf("correlate: load service-connections: %w", err)
	}
	for _, s := range scs {
		for _, proj := range visibleProjects(s) {
			if scByProjectName[proj] == nil {
				scByProjectName[proj] = map[string]scRef{}
			}
			scByProjectName[proj][mStr(s, "name")] = scRef{mStr(s, "id"), mStr(s, "owner_project")}
		}
	}
	envByProjectName := map[string]map[string]int64{}
	envs, err := loadRecords(prior, "10-normalize/environments")
	if err != nil {
		return fmt.Errorf("correlate: load environments: %w", err)
	}
	for _, e := range envs {
		proj := mStr(e, "project")
		if envByProjectName[proj] == nil {
			envByProjectName[proj] = map[string]int64{}
		}
		envByProjectName[proj][mStr(e, "name")] = mInt64(e, "id")
	}
	poolByProjectName := map[string]map[string]int64{}
	pools, err := loadRecords(prior, "10-normalize/project-agent-pools")
	if err != nil {
		return fmt.Errorf("correlate: load project-agent-pools: %w", err)
	}
	for _, p := range pools {
		proj := mStr(p, "project")
		if poolByProjectName[proj] == nil {
			poolByProjectName[proj] = map[string]int64{}
		}
		poolByProjectName[proj][mStr(p, "name")] = mInt64(p, "id")
	}

	// CONSUMES_GROUP is emitted at the level a group is DECLARED (schema: a
	// pipeline-level group reaches every job; a stage-level group every job in the
	// stage). The Pipeline/Stage/Job nodes each carry only their own declarations.
	emitConsumesGroup := func(level, project string, pipelineID int64, stage, job, name string) error {
		ref := vgByProjectName[project][name]
		rec := map[string]any{
			"kind": "CONSUMES_GROUP", "project": project, "pipeline_id": pipelineID,
			"level": level, "stage": stage, "job": job, "group_name": name,
			"variable_group_id": ref.id, "owner_project": ref.owner, "resolved": ref.id != 0,
		}
		key := fmt.Sprintf("%s__%d__%s__%s__%s__%s", adoSafe(project), pipelineID, level, adoSafe(stage), adoSafe(job), adoSafe(name))
		return emit(cp, timer, engine.NormalizeADOEdges("consumes-group", key), rec)
	}
	pipelineRecs, err := loadRecords(prior, "10-normalize/pipelines")
	if err != nil {
		return fmt.Errorf("correlate: load pipelines: %w", err)
	}
	for _, pl := range pipelineRecs {
		for _, g := range mList(pl, "variable_groups") {
			if name, _ := g.(string); name != "" {
				if err := emitConsumesGroup("pipeline", mStr(pl, "project"), mInt64(pl, "id"), "", "", name); err != nil {
					return err
				}
			}
		}
	}
	stageRecs, err := loadRecords(prior, "10-normalize/stages")
	if err != nil {
		return fmt.Errorf("correlate: load stages: %w", err)
	}
	for _, st := range stageRecs {
		for _, g := range mList(st, "variable_groups") {
			if name, _ := g.(string); name != "" {
				if err := emitConsumesGroup("stage", mStr(st, "project"), mInt64(st, "pipeline_id"), mStr(st, "stage"), "", name); err != nil {
					return err
				}
			}
		}
	}

	for _, j := range jobs {
		project := mStr(j, "project")
		jobKey := fmt.Sprintf("%s__%d__%s__%s", adoSafe(project), mInt64(j, "pipeline_id"), adoSafe(mStr(j, "stage")), adoSafe(mStr(j, "job")))
		for _, g := range mList(j, "variable_groups") {
			if name, _ := g.(string); name != "" {
				if err := emitConsumesGroup("job", project, mInt64(j, "pipeline_id"), mStr(j, "stage"), mStr(j, "job"), name); err != nil {
					return err
				}
			}
		}
		for _, u := range mList(j, "service_connection_usages") {
			um := entMap(u)
			name := entStr(um["connection_name"])
			ref := scByProjectName[project][name]
			rec := map[string]any{
				"kind":                  "USES_CONNECTION",
				"project":               project,
				"pipeline_id":           mInt64(j, "pipeline_id"),
				"job":                   mStr(j, "job"),
				"connection_name":       name,
				"service_connection_id": ref.id,
				"owner_project":         ref.owner,
				"task":                  entStr(um["task"]),
				"input_name":            entStr(um["input_name"]),
				"resolved":              ref.id != "",
			}
			if err := emit(cp, timer, engine.NormalizeADOEdges("uses-connection", jobKey+"__"+adoSafe(name)), rec); err != nil {
				return err
			}
		}
		if env := mStr(j, "targets_environment"); env != "" {
			// A deployment target may be resource-scoped ("env.resource"): prefer an
			// exact environment match, else split on the first "." and resolve the
			// environment prefix, keeping the resource separately.
			envName, resource := env, ""
			envID := envByProjectName[project][env]
			if envID == 0 {
				if n, r, ok := strings.Cut(env, "."); ok {
					if id := envByProjectName[project][n]; id != 0 {
						envName, resource, envID = n, r, id
					}
				}
			}
			rec := map[string]any{
				"kind": "TARGETS", "project": project, "pipeline_id": mInt64(j, "pipeline_id"),
				"job": mStr(j, "job"), "environment": envName, "resource": strOrNull(resource),
				"environment_ref": env, "environment_id": envID, "resolved": envID != 0,
			}
			if err := emit(cp, timer, engine.NormalizeADOEdges("targets", jobKey+"__"+adoSafe(env)), rec); err != nil {
				return err
			}
		}
		if pool := mMap(j, "pool"); poolRef(pool) != "" {
			name := mStr(pool, "name")
			vmImage := mStr(pool, "vm_image")
			poolID := poolByProjectName[project][name]
			rec := map[string]any{
				"kind": "RUNS_ON", "project": project, "pipeline_id": mInt64(j, "pipeline_id"),
				"job": mStr(j, "job"), "pool_name": name, "vm_image": vmImage,
				"demands": listOrEmpty(pool, "demands"),
				// vmImage with no named pool is a Microsoft-hosted image (no node).
				"is_hosted":             name == "" && vmImage != "",
				"project_agent_pool_id": poolID,
				"resolved":              poolID != 0,
			}
			if err := emit(cp, timer, engine.NormalizeADOEdges("runs-on", jobKey), rec); err != nil {
				return err
			}
		}
	}
	return nil
}

// deriveBranches materializes :Branch nodes and DEFINED_BY edges. A branch is
// referenced two ways: as a YAML pipeline's entry point (Pipeline -> Branch,
// carrying the yaml_path) and as a branch-policy scope's protected ref. Nodes are
// deduped by id; the pipeline pass runs first so a branch that is a repo default
// keeps is_default=true.
func deriveBranches(cp engine.CurrentPhase, timer *engine.PhaseTimer, pipelines, policies, repos []map[string]any) error {
	branches := map[string]map[string]any{}
	add := func(project, repo, repoID, branch string, isDefault, isPrefix bool) {
		id := project + "/" + repo + "@" + branch
		if _, ok := branches[id]; ok {
			return
		}
		branches[id] = map[string]any{
			"_id": id, "kind": "Branch", "project": project, "repo": repo,
			"repo_id": repoID, "name": branch, "is_default": isDefault, "is_prefix": isPrefix,
		}
	}

	for _, pl := range pipelines {
		if mStr(pl, "settings_source_type") != "yaml" {
			continue
		}
		repo := mMap(pl, "repository")
		if !strings.EqualFold(mStr(repo, "type"), "TfsGit") {
			continue
		}
		repoName := mStr(repo, "name")
		if repoName == "" {
			continue
		}
		project := mStr(pl, "project")
		branch := stripRef(mStr(repo, "default_branch"))
		if branch == "" {
			branch = "main"
		}
		add(project, repoName, mStr(repo, "id"), branch, true, false)
		edge := map[string]any{
			"kind": "DEFINED_BY", "project": project, "pipeline_id": mInt64(pl, "id"),
			"repo": repoName, "branch": branch, "yaml_path": mStr(pl, "yaml_path"),
			"branch_id": project + "/" + repoName + "@" + branch,
		}
		if err := emit(cp, timer, engine.NormalizeADOEdges("defined-by", fmt.Sprintf("%s__%d", adoSafe(project), mInt64(pl, "id"))), edge); err != nil {
			return err
		}
	}

	reposByProject := map[string][]map[string]any{}
	for _, r := range repos {
		reposByProject[mStr(r, "project")] = append(reposByProject[mStr(r, "project")], r)
	}
	for _, pol := range policies {
		project := mStr(pol, "project")
		for _, sc := range mList(pol, "scope") {
			scope := entMap(sc)
			ref := stripRef(entStr(scope["refName"]))
			if ref == "" {
				continue
			}
			repoID := entStr(scope["repositoryId"])
			isPrefix := entStr(scope["matchKind"]) == "Prefix"
			targets := reposByProject[project]
			if repoID != "" {
				targets = filterReposByID(targets, repoID)
			}
			for _, r := range targets {
				add(project, mStr(r, "name"), mStr(r, "id"), ref, ref == stripRef(mStr(r, "default_branch")), isPrefix)
			}
		}
	}

	ids := make([]string, 0, len(branches))
	for id := range branches {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		b := branches[id]
		if err := emit(cp, timer, engine.NormalizeADOBranch(mStr(b, "project"), mStr(b, "repo"), mStr(b, "name")), b); err != nil {
			return err
		}
	}
	return nil
}

// visibleProjects lists every project a (possibly shared) resource can be
// referenced from: its owner plus everyone it is shared into.
func visibleProjects(rec map[string]any) []string {
	set := map[string]bool{}
	if o := mStr(rec, "owner_project"); o != "" {
		set[o] = true
	}
	for _, p := range mList(rec, "shared_into") {
		if s, ok := p.(string); ok {
			set[s] = true
		}
	}
	for _, p := range mList(rec, "visible_in_projects") {
		if s, ok := p.(string); ok {
			set[s] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}

func poolRef(pool map[string]any) string {
	if n := mStr(pool, "name"); n != "" {
		return n
	}
	return mStr(pool, "vm_image")
}

func listOrEmpty(m map[string]any, key string) []any {
	if v, ok := mGet(m, key).([]any); ok {
		return v
	}
	return []any{}
}

// deriveMemberOf emits a MEMBER_OF edge per direct group membership (graph
// memberships, direction=down), so nested-group traversal has explicit edges.
func deriveMemberOf(prior engine.PriorPhase, cp engine.CurrentPhase, timer *engine.PhaseTimer, org string) error {
	for group, members := range loadMemberships(prior, org) {
		for _, member := range members {
			rec := map[string]any{"kind": "MEMBER_OF", "member": member, "group": group, "is_direct": true}
			if err := emit(cp, timer, engine.NormalizeADOEdges("member-of", hashKey(member, group)), rec); err != nil {
				return err
			}
		}
	}
	return nil
}
