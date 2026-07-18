package ado

import (
	"context"
	"fmt"
	"sort"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// normalizeEntities emits one structural record per node from the API-JSON
// surfaces. Resource-scoped properties (checks, pipeline authorization, secrets)
// fold onto their owning node. Per-item failures are recorded and skipped.
func normalizeEntities(ctx context.Context, prior engine.PriorPhase, cp engine.CurrentPhase, org string, timer *engine.PhaseTimer) error {
	projs := projects(prior, org)

	if err := normalizeOrg(prior, cp, org, projs, timer); err != nil {
		return err
	}
	if err := normalizePrincipals(prior, cp, org, timer); err != nil {
		return err
	}
	if err := normalizeAgentPools(prior, cp, timer); err != nil {
		return err
	}
	if err := normalizeFeeds(prior, cp, org, timer); err != nil {
		return err
	}
	if err := normalizeExtensions(prior, cp, org, timer); err != nil {
		return err
	}
	if err := normalizeServiceHooks(prior, cp, org, timer); err != nil {
		return err
	}
	// Service connections and variable groups are deduped across projects (a
	// shared resource appears in every project it is shared into), so they run
	// org-level, not per-project.
	if err := normalizeServiceConnectionsShared(prior, cp, org, projs, timer); err != nil {
		return err
	}
	if err := normalizeVariableGroupsShared(prior, cp, org, projs, timer); err != nil {
		return err
	}
	for _, p := range projs {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, fn := range []func(engine.PriorPhase, engine.CurrentPhase, string, projectMeta, *engine.PhaseTimer) error{
			normalizeProject, normalizeRepos, normalizeEnvironments, normalizePolicies, normalizeAgentQueues, normalizeSecureFiles,
		} {
			if err := fn(prior, cp, org, p, timer); err != nil {
				return err
			}
		}
	}
	return nil
}

// generalSettings returns a project's effective build/pipeline settings object.
func generalSettings(prior engine.PriorPhase, project string) map[string]any {
	return entLoadData(prior, engine.CollectADOGeneralSettings(project))
}

// orgInheritedSettings are the general-settings keys (schema names) that resolve
// down from the org. Only these gate org_settings_uniform; the remaining
// settingsView keys are project-scoped posture.
var orgInheritedSettings = []string{
	"limit_job_auth_scope_to_current_project", "limit_job_auth_scope_for_releases",
	"limit_job_auth_scope_to_referenced_repos", "enforce_settable_var",
	"disable_classic_pipeline_creation", "disable_classic_build_pipeline_creation",
	"disable_classic_release_creation", "disable_implied_yaml_ci_trigger",
}

// settingsView projects the load-bearing general-settings booleans under the
// schema_reference property names (the values are effective/server-clamped). These
// are spread FLAT onto :Organization and :Project per the schema. settings_observed
// is false when the surface soft-failed, so an absent flag is not read as false.
func settingsView(gs map[string]any) map[string]any {
	observed := gs != nil
	if _, un := gs["_unobserved"]; un {
		observed = false
	}
	return map[string]any{
		"limit_job_auth_scope_to_current_project":  entBool(gs["enforceJobAuthScope"]),
		"limit_job_auth_scope_for_releases":        entBool(gs["enforceJobAuthScopeForReleases"]),
		"limit_job_auth_scope_to_referenced_repos": entBool(gs["enforceReferencedRepoScopedToken"]),
		"enforce_settable_var":                     entBool(gs["enforceSettableVar"]),
		"disable_classic_pipeline_creation":        entBool(gs["disableClassicPipelineCreation"]),
		"disable_classic_build_pipeline_creation":  entBool(gs["disableClassicBuildPipelineCreation"]),
		"disable_classic_release_creation":         entBool(gs["disableClassicReleasePipelineCreation"]),
		"disable_implied_yaml_ci_trigger":          entBool(gs["disableImpliedYAMLCiTrigger"]),
		"enable_shell_tasks_args_sanitizing":       entBool(gs["enableShellTasksArgsSanitizing"]),
		"fork_protection_enabled":                  entBool(gs["forkProtectionEnabled"]),
		"builds_enabled_for_forks":                 entBool(gs["buildsEnabledForForks"]),
		"settings_observed":                        observed,
	}
}

// mergeFlat spreads src's keys onto dst (dst wins on conflict is not expected;
// settings keys are disjoint from the node's own keys).
func mergeFlat(dst, src map[string]any) {
	for k, v := range src {
		dst[k] = v
	}
}

func normalizeOrg(prior engine.PriorPhase, cp engine.CurrentPhase, org string, projs []projectMeta, timer *engine.PhaseTimer) error {
	// No org-level generalsettings endpoint exists (404): the org enforce flags
	// are only observable as the per-project effective values. Present a sample
	// project's view, but only assert it as the org baseline when ALL projects
	// agree — an override on any project would otherwise be reported as the org's.
	var sample map[string]any
	var sampleProject string
	uniform := true
	if len(projs) > 0 {
		sample = settingsView(generalSettings(prior, projs[0].Name))
		sampleProject = projs[0].Name
		for _, p := range projs[1:] {
			v := settingsView(generalSettings(prior, p.Name))
			for _, k := range orgInheritedSettings {
				if v[k] != sample[k] {
					uniform = false
					break
				}
			}
			if !uniform {
				break
			}
		}
	}
	conn := entLoadData(prior, engine.CollectADOConnectionData(org))
	rec := map[string]any{
		"_id":                  org,
		"kind":                 "Organization",
		"org":                  org,
		"sample_project":       sampleProject,
		"org_settings_uniform": uniform, // if true, the flat settings are the org baseline
		"org_provenance":       "unknown",
		"projects_count":       len(projs),
		"authenticated_user":   entObj(conn, "authenticatedUser"),
		"_provenance":          prov(engine.CollectADOProjects(org), engine.CollectADOConnectionData(org)),
	}
	// The org has no generalsettings endpoint; attach the enforce/disable booleans
	// flat from the (uniform) per-project effective values per schema §2.
	mergeFlat(rec, orDefaultMap(sample))
	return emit(cp, timer, engine.NormalizeADOOrg(org), rec)
}

func normalizeProject(prior engine.PriorPhase, cp engine.CurrentPhase, org string, p projectMeta, timer *engine.PhaseTimer) error {
	detail := entLoadData(prior, engine.CollectADOProject(p.Name))
	gs := generalSettings(prior, p.Name)
	rec := map[string]any{
		"_id":              org + "/" + p.Name,
		"kind":             "Project",
		"org":              org,
		"project":          p.Name,
		"id":               p.ID,
		"visibility":       entStr(detail["visibility"]),
		"process_template": entStr(entGetIn(detail, "capabilities", "processTemplate", "templateName")),
		"_provenance":      prov(engine.CollectADOProject(p.Name), engine.CollectADOGeneralSettings(p.Name)),
	}
	// Schema §2: the job-auth/classic/fork settings sit flat on :Project (they
	// override the org). deriveRunsAs reads limit_job_auth_scope_to_current_project.
	mergeFlat(rec, settingsView(gs))
	return emit(cp, timer, engine.NormalizeADOProject(p.Name), rec)
}

func normalizeRepos(prior engine.PriorPhase, cp engine.CurrentPhase, org string, p projectMeta, timer *engine.PhaseTimer) error {
	for _, raw := range entLoadList(prior, engine.CollectADORepos(p.Name)) {
		r := entMap(raw)
		name := entStr(r["name"])
		if name == "" {
			continue
		}
		rec := map[string]any{
			"_id":            org + "/" + p.Name + "/" + name,
			"kind":           "Repository",
			"project":        p.Name,
			"id":             entStr(r["id"]),
			"name":           name,
			"default_branch": entStr(r["defaultBranch"]),
			"is_disabled":    entBool(r["isDisabled"]),
			"size":           entInt64(r["size"]),
			// attributed by the policy-by-scope join (correlate)
			"build_validation_policies": []any{},
			"_provenance":               prov(engine.CollectADORepos(p.Name)),
		}
		if err := emit(cp, timer, engine.NormalizeADORepo(p.Name, name), rec); err != nil {
			return err
		}
	}
	return nil
}

// foldChecks projects the collected check configs onto a resource node.
func foldChecks(prior engine.PriorPhase, project, rtype, id string) []any {
	out := []any{}
	for _, raw := range entLoadList(prior, engine.CollectADOChecks(project, rtype, id)) {
		c := entMap(raw)
		out = append(out, map[string]any{
			"type_id":     entStr(entGetIn(c, "type", "id")),
			"type_name":   entStr(entGetIn(c, "type", "name")),
			"settings":    c["settings"],
			"is_disabled": entBool(c["isDisabled"]),
		})
	}
	return out
}

// foldAuthorization projects the pipeline-permissions object. A soft-failed
// surface (collector wrote {_unobserved:status}) must NOT collapse to
// all_pipelines:false — "unknown" is not "not granted". A present-but-absent
// allPipelines key genuinely means no blanket grant.
func foldAuthorization(prior engine.PriorPhase, project, rtype, id string) map[string]any {
	d := entLoadData(prior, engine.CollectADOPipelinePerms(project, rtype, id))
	if st, ok := d["_unobserved"]; ok {
		return map[string]any{"observed": false, "unobserved_status": st, "all_pipelines": nil, "pipelines": []any{}, "authorized_pipelines": []any{}}
	}
	pipelines := entListOrEmpty(d["pipelines"])
	authorized := []any{}
	for _, raw := range pipelines {
		p := entMap(raw)
		if entBool(p["authorized"]) {
			authorized = append(authorized, entInt64(p["id"]))
		}
	}
	return map[string]any{
		"observed":             true,
		"all_pipelines":        entBool(entObj(d, "allPipelines")["authorized"]),
		"pipelines":            pipelines,
		"authorized_pipelines": authorized,
	}
}

// resAgg accumulates one shared resource (service connection or variable group)
// across every project it is visible in, so it collapses to a single owner-keyed
// node with per-project authorization (which legitimately differs per consuming
// project) retained. The static record is built from the owner's copy, not
// whichever project happened to iterate first.
type resAgg struct {
	owner   string
	seen    map[string]bool
	perProj map[string]any
	copies  map[string]map[string]any
	order   []string // project collection order, for a deterministic owner-absent fallback
}

func newResAgg(owner string) *resAgg {
	return &resAgg{owner: owner, seen: map[string]bool{}, perProj: map[string]any{}, copies: map[string]map[string]any{}}
}

// sourceCopy returns the owner's raw copy (the authoritative one) and the project
// it came from, falling back deterministically to the first-collected copy when
// the owner project was not itself collected.
func (a *resAgg) sourceCopy() (map[string]any, string) {
	if c := a.copies[a.owner]; c != nil {
		return c, a.owner
	}
	for _, p := range a.order {
		if c := a.copies[p]; c != nil {
			return c, p
		}
	}
	return map[string]any{}, a.owner
}

func normalizeServiceConnectionsShared(prior engine.PriorPhase, cp engine.CurrentPhase, org string, projs []projectMeta, timer *engine.PhaseTimer) error {
	byID := map[string]*resAgg{}
	var order []string
	for _, p := range projs {
		for _, raw := range entLoadList(prior, engine.CollectADOServiceConnections(p.Name)) {
			e := entMap(raw)
			id := entStr(e["id"])
			if id == "" {
				continue
			}
			a := byID[id]
			if a == nil {
				a = newResAgg(ownerFromRefs(e["serviceEndpointProjectReferences"], p.Name))
				byID[id] = a
				order = append(order, id)
			}
			a.seen[p.Name] = true
			a.order = append(a.order, p.Name)
			a.copies[p.Name] = e
			a.perProj[p.Name] = map[string]any{
				"checks":               foldChecks(prior, p.Name, "endpoint", id),
				"pipeline_permissions": foldAuthorization(prior, p.Name, "endpoint", id),
			}
		}
	}
	for _, id := range order {
		a := byID[id]
		src, srcProj := a.sourceCopy()
		rec := serviceConnectionRec(src)
		rec["_id"] = a.owner + "/" + id
		rec["project"] = a.owner
		rec["owner_project"] = a.owner
		rec["owner_collected"] = a.copies[a.owner] != nil
		rec["visible_in_projects"] = sortedStrSet(a.seen)
		rec["shared_into"] = sharedInto(rec["project_references"], a.owner)
		rec["per_project_authorization"] = a.perProj
		auth := ownerAuth(a.perProj, a.owner, a.seen)
		rec["checks"] = auth["checks"]
		rec["pipeline_permissions"] = auth["pipeline_permissions"]
		rec["_provenance"] = prov(engine.CollectADOServiceConnections(srcProj))
		if err := emitWIFCredential(cp, timer, src, id, a.owner); err != nil {
			return err
		}
		if err := emit(cp, timer, engine.NormalizeADOServiceConnection(a.owner, id), rec); err != nil {
			return err
		}
	}
	return nil
}

func serviceConnectionRec(e map[string]any) map[string]any {
	auth := entObj(e, "authorization")
	params := entObj(auth, "parameters")
	data := entObj(e, "data")
	scheme := entStr(auth["scheme"])
	return map[string]any{
		"kind":                 "ServiceConnection",
		"id":                   entStr(e["id"]),
		"name":                 entStr(e["name"]),
		"type":                 entStr(e["type"]),
		"auth_scheme":          scheme,
		"url":                  entStr(e["url"]),
		"is_shared":            entBool(e["isShared"]),
		"is_ready":             entBool(e["isReady"]),
		"owner":                entStr(e["owner"]),
		"scope":                entStr(data["scopeLevel"]),
		"scope_level":          entStr(data["scopeLevel"]),
		"creation_mode":        entStr(data["creationMode"]),
		"subscription_id":      entStr(data["subscriptionId"]),
		"subscription_name":    entStr(data["subscriptionName"]),
		"tenant_id":            entStr(params["tenantid"]),
		"service_principal_id": entStr(params["serviceprincipalid"]),
		"project_references":   entListOrEmpty(e["serviceEndpointProjectReferences"]),
		"is_wif":               scheme == "WorkloadIdentityFederation",
	}
}

// emitWIFCredential emits a bare :WIFCredential + FEDERATES_TO once per WIF
// connection (subject/issuer are server-generated, absent for manual).
func emitWIFCredential(cp engine.CurrentPhase, timer *engine.PhaseTimer, e map[string]any, id, owner string) error {
	params := entObj(entObj(e, "authorization"), "parameters")
	if entStr(entObj(e, "authorization")["scheme"]) != "WorkloadIdentityFederation" {
		return nil
	}
	spn := entStr(params["serviceprincipalid"])
	subject := entStr(params["workloadIdentityFederationSubject"])
	key := spn
	if key == "" {
		key = subject
	}
	wif := map[string]any{
		"_id": id + "/" + key, "kind": "WIFCredential", "connection_id": id, "project": owner,
		"app_registration_id": spn, "subject": strOrNull(subject),
		"issuer":      strOrNull(entStr(params["workloadIdentityFederationIssuer"])),
		"issuer_type": entStr(params["workloadIdentityFederationIssuerType"]),
		"tenant_id":   entStr(params["tenantid"]),
	}
	if err := emit(cp, timer, engine.NormalizeADOWIFCredential(id, key), wif); err != nil {
		return err
	}
	fed := map[string]any{"kind": "FEDERATES_TO", "project": owner, "connection_id": id,
		"wif_credential_id": id + "/" + key, "app_registration_id": spn,
		"subject": strOrNull(subject),
		"issuer":  strOrNull(entStr(params["workloadIdentityFederationIssuer"]))}
	return emit(cp, timer, engine.NormalizeADOEdges("federates-to", adoSafe(id)), fed)
}

func normalizeVariableGroupsShared(prior engine.PriorPhase, cp engine.CurrentPhase, org string, projs []projectMeta, timer *engine.PhaseTimer) error {
	byID := map[int64]*resAgg{}
	var order []int64
	for _, p := range projs {
		for _, raw := range entLoadList(prior, engine.CollectADOVariableGroups(p.Name)) {
			g := entMap(raw)
			gid := entInt64(g["id"])
			if gid == 0 {
				continue
			}
			a := byID[gid]
			if a == nil {
				a = newResAgg(ownerFromRefs(g["variableGroupProjectReferences"], p.Name))
				byID[gid] = a
				order = append(order, gid)
			}
			a.seen[p.Name] = true
			a.order = append(a.order, p.Name)
			a.copies[p.Name] = g
			idStr := fmt.Sprintf("%d", gid)
			a.perProj[p.Name] = map[string]any{
				"checks":               foldChecks(prior, p.Name, "variablegroup", idStr),
				"pipeline_permissions": foldAuthorization(prior, p.Name, "variablegroup", idStr),
			}
		}
	}
	for _, gid := range order {
		a := byID[gid]
		src, srcProj := a.sourceCopy()
		rec := variableGroupRec(src)
		rec["_id"] = a.owner + "/" + fmt.Sprintf("%d", gid)
		rec["project"] = a.owner
		rec["owner_project"] = a.owner
		rec["owner_collected"] = a.copies[a.owner] != nil
		rec["visible_in_projects"] = sortedStrSet(a.seen)
		rec["shared_into"] = sharedInto(rec["project_references"], a.owner)
		rec["per_project_authorization"] = a.perProj
		auth := ownerAuth(a.perProj, a.owner, a.seen)
		rec["checks"] = auth["checks"]
		rec["pipeline_permissions"] = auth["pipeline_permissions"]
		rec["_provenance"] = prov(engine.CollectADOVariableGroups(srcProj))
		if err := emitSecretVariables(cp, timer, src, gid, a.owner); err != nil {
			return err
		}
		if err := emit(cp, timer, engine.NormalizeADOVariableGroup(a.owner, gid), rec); err != nil {
			return err
		}
		if err := emitKeyVaultLink(cp, timer, rec, a.owner, gid); err != nil {
			return err
		}
	}
	return nil
}

// emitKeyVaultLink materializes a :KeyVault node + LINKS_TO edge for an
// AzureKeyVault-backed variable group (schema §; empty in estates with no KV VG).
func emitKeyVaultLink(cp engine.CurrentPhase, timer *engine.PhaseTimer, rec map[string]any, owner string, gid int64) error {
	if !mBool(rec, "is_linked_to_keyvault") {
		return nil
	}
	vault := mStr(rec, "keyvault_name")
	if vault == "" {
		return nil
	}
	kv := map[string]any{
		"_id": owner + "/" + vault, "kind": "KeyVault", "project": owner, "name": vault,
		"service_connection_id": mStr(rec, "keyvault_service_connection_id"),
	}
	if err := emit(cp, timer, engine.NormalizeADOKeyVault(owner, vault), kv); err != nil {
		return err
	}
	link := map[string]any{
		"kind": "LINKS_TO", "project": owner, "variable_group_id": gid,
		"keyvault_name": vault, "keyvault_id": owner + "/" + vault,
		"service_connection_id": mStr(rec, "keyvault_service_connection_id"),
	}
	return emit(cp, timer, engine.NormalizeADOEdges("links-to", fmt.Sprintf("%s__%d", adoSafe(owner), gid)), link)
}

func variableGroupRec(g map[string]any) map[string]any {
	vars := entObj(g, "variables")
	secretNames := []any{}
	varList := []any{}
	for _, name := range sortedKeys(vars) {
		isSecret := entBool(entObj(vars, name)["isSecret"])
		varList = append(varList, map[string]any{"name": name, "is_secret": isSecret})
		if isSecret {
			secretNames = append(secretNames, name)
		}
	}
	pd := entObj(g, "providerData")
	return map[string]any{
		"kind":                           "VariableGroup",
		"id":                             entInt64(g["id"]),
		"name":                           entStr(g["name"]),
		"type":                           entStr(g["type"]),
		"is_linked_to_keyvault":          entStr(g["type"]) == "AzureKeyVault",
		"keyvault_name":                  entStr(pd["vault"]),
		"keyvault_service_connection_id": entStr(pd["serviceEndpointId"]),
		"variables":                      varList,
		"secret_variable_names":          secretNames,
		"project_references":             entListOrEmpty(g["variableGroupProjectReferences"]),
	}
}

func emitSecretVariables(cp engine.CurrentPhase, timer *engine.PhaseTimer, g map[string]any, gid int64, owner string) error {
	vars := entObj(g, "variables")
	for _, name := range sortedKeys(vars) {
		if !entBool(entObj(vars, name)["isSecret"]) {
			continue
		}
		sv := map[string]any{
			"_id": fmt.Sprintf("%d/%s", gid, name), "kind": "SecretVariable",
			"group_id": gid, "project": owner, "name": name, "is_secret": true,
		}
		if err := emit(cp, timer, engine.NormalizeADOSecretVariable(gid, name), sv); err != nil {
			return err
		}
		def := map[string]any{"kind": "DEFINES", "group_id": gid, "secret_name": name, "project": owner}
		if err := emit(cp, timer, engine.NormalizeADOEdges("defines", fmt.Sprintf("%d__%s", gid, adoSafe(name))), def); err != nil {
			return err
		}
	}
	return nil
}

// ownerFromRefs picks the owning project of a (possibly shared) resource: the
// first project reference (ADO lists the owner first), else the collecting one.
func ownerFromRefs(refs any, fallback string) string {
	list, _ := refs.([]any)
	if len(list) > 0 {
		if n := entStr(entGetIn(entMap(list[0]), "projectReference", "name")); n != "" {
			return n
		}
	}
	return fallback
}

func sharedInto(refs any, owner string) []any {
	out := []any{}
	seen := map[string]bool{owner: true}
	list, _ := refs.([]any)
	for _, r := range list {
		if n := entStr(entGetIn(entMap(r), "projectReference", "name")); n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

func sortedStrSet(m map[string]bool) []any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]any, len(keys))
	for i, k := range keys {
		out[i] = k
	}
	return out
}

// ownerAuth returns the owner project's authorization/checks (the primary), or
// any collected project's deterministically if the owner wasn't collected.
func ownerAuth(perProj map[string]any, owner string, seen map[string]bool) map[string]any {
	if a, ok := perProj[owner].(map[string]any); ok {
		return a
	}
	for _, p := range sortedStrSet(seen) {
		if a, ok := perProj[p.(string)].(map[string]any); ok {
			return a
		}
	}
	return map[string]any{"checks": []any{}, "pipeline_permissions": map[string]any{}}
}

// normalizeAgentQueues emits a :ProjectAgentPool per agent queue, folding its
// checks + pipeline-authorization (queue resource type) and a REFERENCES_POOL
// edge to the org-level pool.
func normalizeAgentQueues(prior engine.PriorPhase, cp engine.CurrentPhase, org string, p projectMeta, timer *engine.PhaseTimer) error {
	for _, raw := range entLoadList(prior, engine.CollectADOAgentQueues(p.Name)) {
		q := entMap(raw)
		qid := entInt64(q["id"])
		if qid == 0 {
			continue
		}
		idStr := fmt.Sprintf("%d", qid)
		pool := entObj(q, "pool")
		orgPool := entInt64(pool["id"])
		rec := map[string]any{
			"_id":                  fmt.Sprintf("%s/%d", p.Name, qid),
			"kind":                 "ProjectAgentPool",
			"project":              p.Name,
			"id":                   qid,
			"name":                 entStr(q["name"]),
			"pool_id":              orgPool,
			"is_hosted":            entBool(pool["isHosted"]),
			"pool_type":            entStr(pool["poolType"]),
			"checks":               foldChecks(prior, p.Name, "queue", idStr),
			"pipeline_permissions": foldAuthorization(prior, p.Name, "queue", idStr),
			"_provenance":          prov(engine.CollectADOAgentQueues(p.Name)),
		}
		if err := emit(cp, timer, engine.NormalizeADOProjectAgentPool(p.Name, qid), rec); err != nil {
			return err
		}
		if orgPool != 0 {
			ref := map[string]any{"kind": "REFERENCES_POOL", "project": p.Name, "queue_id": qid, "org_pool_id": orgPool}
			if err := emit(cp, timer, engine.NormalizeADOEdges("references-pool", fmt.Sprintf("%s__%d", adoSafe(p.Name), qid)), ref); err != nil {
				return err
			}
		}
	}
	return nil
}

func normalizeEnvironments(prior engine.PriorPhase, cp engine.CurrentPhase, org string, p projectMeta, timer *engine.PhaseTimer) error {
	for _, raw := range entLoadList(prior, engine.CollectADOEnvironments(p.Name)) {
		e := entMap(raw)
		envID := entInt64(e["id"])
		name := entStr(e["name"])
		if name == "" {
			continue
		}
		idStr := fmt.Sprintf("%d", envID)
		detail := entLoadData(prior, engine.CollectADOEnvironmentDetail(p.Name, envID))
		rec := map[string]any{
			"_id":                  p.Name + "/" + name,
			"kind":                 "Environment",
			"project":              p.Name,
			"id":                   envID,
			"name":                 name,
			"description":          entStr(e["description"]),
			"resources":            entListOrEmpty(detail["resources"]),
			"created_on":           entStr(detail["createdOn"]),
			"created_by":           entStr(entGetIn(detail, "createdBy", "displayName")),
			"last_modified_on":     entStr(detail["lastModifiedOn"]),
			"checks":               foldChecks(prior, p.Name, "environment", idStr),
			"pipeline_permissions": foldAuthorization(prior, p.Name, "environment", idStr),
			"_provenance":          prov(engine.CollectADOEnvironments(p.Name)),
		}
		if err := emit(cp, timer, engine.NormalizeADOEnvironment(p.Name, name), rec); err != nil {
			return err
		}
	}
	return nil
}

// policySettings maps raw REST camelCase branch-policy settings to the schema's
// snake_case property names (reviewer + build-validation fields as a union; absent
// keys serialize as zero-values, harmless to the rule that reads the other subtype).
func policySettings(s map[string]any) map[string]any {
	return map[string]any{
		"minimum_approver_count":          entInt64(s["minimumApproverCount"]),
		"creator_vote_counts":             entBool(s["creatorVoteCounts"]),
		"allow_downvotes":                 entBool(s["allowDownvotes"]),
		"reset_on_source_push":            entBool(s["resetOnSourcePush"]),
		"reset_rejections_on_source_push": entBool(s["resetRejectionsOnSourcePush"]),
		"block_last_pusher_vote":          entBool(s["blockLastPusherVote"]),
		"require_vote_on_last_iteration":  entBool(s["requireVoteOnLastIteration"]),
		"build_definition_id":             entInt64(s["buildDefinitionId"]),
		"display_name":                    entStr(s["displayName"]),
		"manual_queue_only":               entBool(s["manualQueueOnly"]),
		"queue_on_source_update_only":     entBool(s["queueOnSourceUpdateOnly"]),
		"valid_duration":                  entInt64(s["validDuration"]),
		"filename_patterns":               entListOrEmpty(s["filenamePatterns"]),
		"scope":                           entListOrEmpty(s["scope"]),
	}
}

// policyTypeNames resolves policy type GUID -> display name from policy-types.
func policyTypeNames(prior engine.PriorPhase, project string) map[string]string {
	out := map[string]string{}
	for _, raw := range entLoadList(prior, engine.CollectADOPolicyTypes(project)) {
		t := entMap(raw)
		if id, name := entStr(t["id"]), entStr(t["displayName"]); id != "" {
			out[id] = name
		}
	}
	return out
}

// normalizePolicies emits one BranchPolicy record per policy configuration
// (scope[] preserved); repo/branch attribution is the policy-by-scope join.
func normalizePolicies(prior engine.PriorPhase, cp engine.CurrentPhase, org string, p projectMeta, timer *engine.PhaseTimer) error {
	types := policyTypeNames(prior, p.Name)
	for _, raw := range entLoadList(prior, engine.CollectADOPolicies(p.Name)) {
		c := entMap(raw)
		cfgID := entInt64(c["id"])
		typeID := entStr(entGetIn(c, "type", "id"))
		typeName := types[typeID]
		if typeName == "" {
			typeName = entStr(entGetIn(c, "type", "displayName"))
		}
		rec := map[string]any{
			"_id":         fmt.Sprintf("%s/%d", p.Name, cfgID),
			"kind":        "BranchPolicy",
			"project":     p.Name,
			"config_id":   cfgID,
			"policy_type": typeName,
			"type_id":     typeID,
			"is_enabled":  entBool(c["isEnabled"]),
			"is_blocking": entBool(c["isBlocking"]),
			"is_deleted":  entBool(c["isDeleted"]),
			"scope":       entListOrEmpty(entGetIn(entObj(c, "settings"), "scope")),
			"settings":    policySettings(entObj(c, "settings")),
			"_provenance": prov(engine.CollectADOPolicies(p.Name)),
		}
		if err := emit(cp, timer, engine.NormalizeADOPolicy(p.Name, fmt.Sprintf("cfg-%d", cfgID), typeName), rec); err != nil {
			return err
		}
	}
	return nil
}

func normalizeAgentPools(prior engine.PriorPhase, cp engine.CurrentPhase, timer *engine.PhaseTimer) error {
	files, err := prior.IterJSON("00-collect/pools")
	if err != nil {
		return err
	}
	for _, f := range files {
		pool := entDataOf(f.Data)
		id := entInt64(pool["id"])
		if id == 0 {
			continue
		}
		agents := []any{}
		for _, raw := range entLoadList(prior, engine.CollectADOPoolAgents(id)) {
			a := entMap(raw)
			agents = append(agents, map[string]any{
				"id":                  entInt64(a["id"]),
				"name":                entStr(a["name"]),
				"enabled":             entBool(a["enabled"]),
				"status":              entStr(a["status"]),
				"os_description":      entStr(a["osDescription"]),
				"version":             entStr(a["version"]),
				"system_capabilities": entObj(a, "systemCapabilities"),
			})
		}
		elastic := entLoadData(prior, engine.CollectADOElasticPool(id))
		rec := map[string]any{
			"_id":            fmt.Sprintf("%d", id),
			"kind":           "OrgAgentPool",
			"id":             id,
			"name":           entStr(pool["name"]),
			"is_hosted":      entBool(pool["isHosted"]),
			"pool_type":      entStr(pool["poolType"]),
			"auto_provision": entBool(pool["autoProvision"]),
			"auto_update":    entBool(pool["autoUpdate"]),
			"size":           entInt64(pool["size"]),
			"agents":         agents,
			"elastic":        orDefaultMap(elastic),
			"is_elastic":     elastic != nil,
			"_provenance":    prov(engine.CollectADOPool(id)),
		}
		if err := emit(cp, timer, engine.NormalizeADOAgentPool(id), rec); err != nil {
			return err
		}
	}
	return nil
}

func normalizeFeeds(prior engine.PriorPhase, cp engine.CurrentPhase, org string, timer *engine.PhaseTimer) error {
	for _, raw := range entLoadList(prior, engine.CollectADOFeeds(org)) {
		bundle := entMap(raw)
		feed := entObj(bundle, "feed")
		fid := entStr(feed["id"])
		if fid == "" {
			continue
		}
		rec := map[string]any{
			"_id":              "org/" + fid,
			"kind":             "ArtifactsFeed",
			"scope":            "org",
			"id":               fid,
			"name":             entStr(feed["name"]),
			"upstream_enabled": entBool(feed["upstreamEnabled"]),
			"upstream_sources": entListOrEmpty(feed["upstreamSources"]),
			"views":            entListOrEmpty(bundle["views"]),
			"permissions":      entListOrEmpty(bundle["permissions"]),
			"_provenance":      prov(engine.CollectADOFeeds(org)),
		}
		if err := emit(cp, timer, engine.NormalizeADOFeed("org", fid), rec); err != nil {
			return err
		}
	}
	return nil
}

// normalizePrincipals emits User / SecurityGroup / BuildServiceIdentity records
// from the graph bundle. Build Service identities are users with domain "Build".
func normalizePrincipals(prior engine.PriorPhase, cp engine.CurrentPhase, org string, timer *engine.PhaseTimer) error {
	graph := entLoadData(prior, engine.CollectADOGraph(org))
	if graph == nil {
		return nil
	}
	for _, raw := range entListOrEmpty(graph["users"]) {
		u := entMap(raw)
		desc := entStr(u["descriptor"])
		if desc == "" {
			continue
		}
		if entStr(u["domain"]) == "Build" {
			rec := principalRecord("BuildServiceIdentity", org, u)
			if err := emit(cp, timer, engine.NormalizeADOPrincipal("build-service", desc), rec); err != nil {
				return err
			}
			continue
		}
		rec := principalRecord("User", org, u)
		if err := emit(cp, timer, engine.NormalizeADOPrincipal("users", desc), rec); err != nil {
			return err
		}
	}
	for _, raw := range entListOrEmpty(graph["groups"]) {
		g := entMap(raw)
		desc := entStr(g["descriptor"])
		if desc == "" {
			continue
		}
		rec := principalRecord("SecurityGroup", org, g)
		if err := emit(cp, timer, engine.NormalizeADOPrincipal("groups", desc), rec); err != nil {
			return err
		}
	}
	return nil
}

func principalRecord(kind, org string, m map[string]any) map[string]any {
	return map[string]any{
		"_id":            entStr(m["descriptor"]),
		"kind":           kind,
		"org":            org,
		"descriptor":     entStr(m["descriptor"]),
		"principal_name": entStr(m["principalName"]),
		"display_name":   entStr(m["displayName"]),
		"mail_address":   entStr(m["mailAddress"]),
		"origin":         entStr(m["origin"]),
		"origin_id":      entStr(m["originId"]),
		"domain":         entStr(m["domain"]),
		"subject_kind":   entStr(m["subjectKind"]),
	}
}

func orDefaultMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}
