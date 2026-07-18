package ado

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// Security namespace GUIDs (verified against the live org, see api-exploration).
const (
	gitNS      = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"
	buildNS    = "33344d9c-fc72-4d6f-aba5-fa317101a7e9"
	endpointNS = "49b48001-ca20-4adc-8111-5b60c903a50c"
)

const (
	collectorVer = "@0.1"
	sourceAPI    = "azure_devops_rest"
)

var timeNow = time.Now

func nowISO() string { return engine.IsoformatUTC(timeNow()) }

type collectMeta struct {
	CollectedAt string         `json:"collected_at"`
	Collector   string         `json:"collector"`
	Source      collectMetaSrc `json:"source"`
}

type collectMetaSrc struct {
	API  string `json:"api"`
	Path string `json:"path"`
}

func envelope(cp engine.CurrentPhase, rel, collector, sourcePath string, data any) error {
	return cp.Write(rel, map[string]any{
		"_meta": collectMeta{
			CollectedAt: nowISO(),
			Collector:   collector + collectorVer,
			Source:      collectMetaSrc{API: sourceAPI, Path: sourcePath},
		},
		"data": data,
	})
}

// writeOrMark writes the collected data, or a {"_unobserved":<status>} marker
// when the surface soft-failed (401/403/404) — so downstream can tell "no access"
// from "never collected" (CLAUDE.md: 403/404 → skip AND mark).
func writeOrMark(cp engine.CurrentPhase, rel, collector, sourcePath string, raw json.RawMessage, status int) error {
	if status != 0 {
		return envelope(cp, rel, collector, sourcePath, map[string]any{"_unobserved": status})
	}
	return envelope(cp, rel, collector, sourcePath, raw)
}

// listOrMark returns the list (never nil) on success, or a {"_unobserved":<status>}
// marker when it soft-failed (401/403/404) — so downstream can tell "no access"
// from "genuinely empty" (CLAUDE.md: 403/404 → skip AND mark). Used for both
// top-level list surfaces and embedded sub-lists (feed views/permissions).
func listOrMark(items []json.RawMessage, status int) any {
	if status != 0 {
		return map[string]any{"_unobserved": status}
	}
	return rawArray(items)
}

// writeListOrMark envelopes a list surface via listOrMark. The list analog of
// writeOrMark; a forbidden list must not read to the scanner as "none exist".
func writeListOrMark(cp engine.CurrentPhase, rel, collector, sourcePath string, items []json.RawMessage, status int) error {
	return envelope(cp, rel, collector, sourcePath, listOrMark(items, status))
}

// softGet returns (raw, status): status is 0 on success, or the soft HTTP code
// (401/403/404) when the resource was unobservable (raw nil). A non-soft error
// propagates.
func softGet(ctx context.Context, cl ADO, host, api, p string, params url.Values) (json.RawMessage, int, error) {
	raw, _, err := cl.Get(ctx, host, api, p, params, true)
	if err != nil {
		if isSoft(err) {
			return nil, softStatus(err), nil
		}
		return nil, 0, err
	}
	if raw == nil {
		return nil, 404, nil
	}
	return raw, 0, nil
}

func softList(ctx context.Context, cl ADO, host, api, p string, params url.Values) ([]json.RawMessage, int, error) {
	items, err := cl.Paginate(ctx, host, api, p, params)
	if err != nil {
		if isSoft(err) {
			return nil, softStatus(err), nil
		}
		return nil, 0, err
	}
	return items, 0, nil
}

// rawArray ensures a nil slice marshals as [] (rules key on it).
func rawArray(items []json.RawMessage) []json.RawMessage {
	if items == nil {
		return []json.RawMessage{}
	}
	return items
}

func numField(raw json.RawMessage, key string) int64 {
	v := objField(raw, key)
	if len(v) == 0 {
		return 0
	}
	var n int64
	if json.Unmarshal(v, &n) != nil {
		return 0
	}
	return n
}

// collectIDs extracts numeric "id" fields from a list of raw items.
func collectIDs(items []json.RawMessage) []int64 {
	var out []int64
	for _, raw := range items {
		if id := numField(raw, "id"); id != 0 {
			out = append(out, id)
		}
	}
	return out
}

// addPipelineIDs merges numeric ids (first name wins) into a shared id->name map,
// used to union /build/definitions and /pipelines.
func addPipelineIDs(dst map[int64]string, items []json.RawMessage) {
	for _, raw := range items {
		if id := numField(raw, "id"); id != 0 {
			if _, ok := dst[id]; !ok {
				dst[id] = strField(raw, "name")
			}
		}
	}
}

func sortedIDs(m map[int64]string) []int64 {
	out := make([]int64, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

type projectRef struct {
	ID   string
	Name string
}

type repoRef struct {
	ID   string
	Name string
}

type resourceRef struct {
	Type string
	ID   string
	Name string
}

// ================= ORG =================

func collectProjects(ctx context.Context, cl ADO, cp engine.CurrentPhase, org string) ([]projectRef, error) {
	items, status, err := softList(ctx, cl, "core", APIVersion, "/_apis/projects", nil)
	if err != nil {
		return nil, err
	}
	if err := writeListOrMark(cp, engine.CollectADOProjects(org), "projects", "/_apis/projects", items, status); err != nil {
		return nil, err
	}
	out := make([]projectRef, 0, len(items))
	for _, raw := range items {
		id, name := strField(raw, "id"), strField(raw, "name")
		if id != "" && name != "" {
			out = append(out, projectRef{ID: id, Name: name})
		}
	}
	return out, nil
}

func collectAgentPools(ctx context.Context, cl ADO, cp engine.CurrentPhase) error {
	pools, status, err := softList(ctx, cl, "core", APIVersion, "/_apis/distributedtask/pools", nil)
	if err != nil {
		return err
	}
	if status != 0 {
		return nil
	}
	for _, raw := range pools {
		id := numField(raw, "id")
		if id == 0 {
			continue
		}
		if err := envelope(cp, engine.CollectADOPool(id), "agent-pool",
			fmt.Sprintf("/_apis/distributedtask/pools/%d", id), raw); err != nil {
			return err
		}
		if boolField(raw, "isHosted") {
			continue // Microsoft-hosted pools have no self-hosted agents or elastic config
		}
		// Agents (with capabilities). A failed sub-call marks that pool's agents and
		// continues — one flaky pool must not sink the whole surface.
		agentsPath := fmt.Sprintf("/_apis/distributedtask/pools/%d/agents", id)
		agents, astatus, aerr := softList(ctx, cl, "core", APIVersion, agentsPath,
			url.Values{"includeCapabilities": []string{"true"}})
		var agentData any = rawArray(agents)
		if aerr != nil {
			agentData = map[string]any{"_error": aerr.Error()}
		} else if astatus != 0 {
			agentData = map[string]any{"_unobserved": astatus}
		}
		if err := envelope(cp, engine.CollectADOPoolAgents(id), "pool-agents", agentsPath, agentData); err != nil {
			return err
		}
		// Elastic/VMSS pool config (singleUseAgents/recycle) lives on a separate
		// endpoint; a 404 just means the pool is static self-hosted (expected, no mark).
		ep, estatus, eerr := softGet(ctx, cl, "core", APIVersionPreview,
			fmt.Sprintf("/_apis/distributedtask/elasticpools/%d", id), nil)
		if eerr != nil {
			return eerr
		}
		if estatus == 0 {
			if err := envelope(cp, engine.CollectADOElasticPool(id), "elastic-pool",
				fmt.Sprintf("/_apis/distributedtask/elasticpools/%d", id), ep); err != nil {
				return err
			}
		}
	}
	return nil
}

func collectConnectionData(ctx context.Context, cl ADO, cp engine.CurrentPhase, org string) error {
	raw, status, err := softGet(ctx, cl, "core", APIVersionPreview, "/_apis/connectionData", nil)
	if err != nil {
		return err
	}
	return writeOrMark(cp, engine.CollectADOConnectionData(org), "connection-data", "/_apis/connectionData", raw, status)
}

// collectEndpointACL pulls the ServiceEndpoints-namespace ACL for one connection
// (Administer bit). Soft — needs vso.security_manage.
func collectEndpointACL(ctx context.Context, cl ADO, cp engine.CurrentPhase, project, projectID, connID string) error {
	token := fmt.Sprintf("endpoints/%s/%s", projectID, connID)
	raw, status, err := softGet(ctx, cl, "core", APIVersion, "/_apis/accesscontrollists/"+endpointNS,
		url.Values{"token": []string{token}, "includeExtendedInfo": []string{"true"}})
	if err != nil {
		return err
	}
	return writeOrMark(cp, engine.CollectADOEndpointACL(project, connID), "endpoint-acl",
		"/_apis/accesscontrollists/"+endpointNS, raw, status)
}

func boolField(raw json.RawMessage, key string) bool {
	v := objField(raw, key)
	if len(v) == 0 {
		return false
	}
	var b bool
	if json.Unmarshal(v, &b) != nil {
		return false
	}
	return b
}

func collectSecurityNamespaces(ctx context.Context, cl ADO, cp engine.CurrentPhase, org string) error {
	items, status, err := softList(ctx, cl, "core", APIVersion, "/_apis/securitynamespaces", nil)
	if err != nil {
		return err
	}
	return writeListOrMark(cp, engine.CollectADOSecurityNS(org), "security-namespaces", "/_apis/securitynamespaces", items, status)
}

func collectGraph(ctx context.Context, cl ADO, cp engine.CurrentPhase, org string) error {
	groups, gstatus, err := softList(ctx, cl, "vssps", APIVersionGraph, "/_apis/graph/groups", nil)
	if err != nil {
		return err
	}
	users, ustatus, err := softList(ctx, cl, "vssps", APIVersionGraph, "/_apis/graph/users", nil)
	if err != nil {
		return err
	}
	// direction=down memberships per group give the nested-group edges normalize
	// needs to resolve effectiveAllow ACL descriptors to users (transitive closure
	// is normalize's job; collect provides one hop per group). Every group is
	// already listed, so no recursion is required here.
	memberships := map[string][]json.RawMessage{}
	for _, g := range groups {
		desc := strField(g, "descriptor")
		if desc == "" {
			continue
		}
		mem, mstatus, merr := softList(ctx, cl, "vssps", APIVersionGraph,
			"/_apis/graph/memberships/"+url.PathEscape(desc), url.Values{"direction": []string{"down"}})
		if merr != nil {
			return merr
		}
		if mstatus == 0 {
			memberships[desc] = rawArray(mem)
		}
	}
	data := map[string]any{"groups": rawArray(groups), "users": rawArray(users), "memberships": memberships}
	// Mark the bundle if either principal list was unobservable (groups and users
	// need the same graph-read scope, but a partial failure must still signal).
	if gstatus != 0 {
		data["_unobserved"] = gstatus
	} else if ustatus != 0 {
		data["_unobserved"] = ustatus
	}
	return envelope(cp, engine.CollectADOGraph(org), "graph", "/_apis/graph/{groups,users,memberships}", data)
}

func collectExtensions(ctx context.Context, cl ADO, cp engine.CurrentPhase, org string) error {
	raw, status, err := softGet(ctx, cl, "extmgmt", APIVersionPreview, "/_apis/extensionmanagement/installedextensions", nil)
	if err != nil {
		return err
	}
	if status != 0 {
		raw = json.RawMessage("null")
	}
	return envelope(cp, engine.CollectADOExtensions(org), "extensions",
		"/_apis/extensionmanagement/installedextensions", raw)
}

func collectServiceHooks(ctx context.Context, cl ADO, cp engine.CurrentPhase, org string) error {
	items, status, err := softList(ctx, cl, "core", APIVersionPreview, "/_apis/hooks/subscriptions", nil)
	if err != nil {
		return err
	}
	return writeListOrMark(cp, engine.CollectADOServiceHooks(org), "service-hooks", "/_apis/hooks/subscriptions", items, status)
}

// collectFeeds pulls org-scoped feeds (feeds are org-scoped in practice) plus
// each feed's views and permissions.
func collectFeeds(ctx context.Context, cl ADO, cp engine.CurrentPhase, org string) error {
	feeds, status, err := softList(ctx, cl, "feeds", APIVersionPreview, "/_apis/packaging/feeds", nil)
	if err != nil {
		return err
	}
	if status != 0 {
		return envelope(cp, engine.CollectADOFeeds(org), "feeds", "/_apis/packaging/feeds", map[string]any{"_unobserved": status})
	}
	type feedBundle struct {
		Feed        json.RawMessage `json:"feed"`
		Views       any             `json:"views"`       // list, or {_unobserved} on soft-fail
		Permissions any             `json:"permissions"` // list, or {_unobserved} on soft-fail
	}
	bundles := make([]feedBundle, 0, len(feeds))
	for _, f := range feeds {
		fid := strField(f, "id")
		if fid == "" {
			bundles = append(bundles, feedBundle{Feed: f, Views: []json.RawMessage{}, Permissions: []json.RawMessage{}})
			continue
		}
		views, vstatus, _ := softList(ctx, cl, "feeds", APIVersionPreview, "/_apis/packaging/feeds/"+fid+"/views", nil)
		perms, pstatus, _ := softList(ctx, cl, "feeds", APIVersionPreview, "/_apis/packaging/feeds/"+fid+"/permissions", nil)
		bundles = append(bundles, feedBundle{Feed: f, Views: listOrMark(views, vstatus), Permissions: listOrMark(perms, pstatus)})
	}
	return envelope(cp, engine.CollectADOFeeds(org), "feeds", "/_apis/packaging/feeds", bundles)
}

// ================= PROJECT list surfaces =================

func collectProjectDetail(ctx context.Context, cl ADO, cp engine.CurrentPhase, project string) error {
	raw, status, err := softGet(ctx, cl, "core", APIVersion,
		"/_apis/projects/"+url.PathEscape(project), url.Values{"includeCapabilities": []string{"true"}})
	if err != nil {
		return err
	}
	return writeOrMark(cp, engine.CollectADOProject(project), "project", "/_apis/projects/"+project, raw, status)
}

func collectGeneralSettings(ctx context.Context, cl ADO, cp engine.CurrentPhase, project string) error {
	raw, status, err := softGet(ctx, cl, "core", APIVersion, "/"+url.PathEscape(project)+"/_apis/build/generalsettings", nil)
	if err != nil {
		return err
	}
	return writeOrMark(cp, engine.CollectADOGeneralSettings(project), "general-settings",
		"/"+project+"/_apis/build/generalsettings", raw, status)
}

func collectProjectProperties(ctx context.Context, cl ADO, cp engine.CurrentPhase, projectID, project string) error {
	raw, status, err := softGet(ctx, cl, "core", APIVersionPreview, "/_apis/projects/"+projectID+"/properties", nil)
	if err != nil {
		return err
	}
	return writeOrMark(cp, engine.CollectADOProjectProps(project), "project-properties",
		"/_apis/projects/"+projectID+"/properties", raw, status)
}

func collectRepos(ctx context.Context, cl ADO, cp engine.CurrentPhase, project string) ([]repoRef, error) {
	items, status, err := softList(ctx, cl, "core", APIVersion, "/"+url.PathEscape(project)+"/_apis/git/repositories", nil)
	if err != nil {
		return nil, err
	}
	if err := writeListOrMark(cp, engine.CollectADORepos(project), "repositories",
		"/"+project+"/_apis/git/repositories", items, status); err != nil {
		return nil, err
	}
	out := make([]repoRef, 0, len(items))
	for _, raw := range items {
		if id, name := strField(raw, "id"), strField(raw, "name"); id != "" {
			out = append(out, repoRef{ID: id, Name: name})
		}
	}
	return out, nil
}

// listSurface fetches a project list, stores it, and returns resourceRefs of the
// given type for downstream pipeline-permissions / checks fan-out.
func listSurface(ctx context.Context, cl ADO, cp engine.CurrentPhase, project, host, api, apiPath, rel, collector, rtype string) ([]resourceRef, error) {
	items, status, err := softList(ctx, cl, host, api, apiPath, nil)
	if err != nil {
		return nil, err
	}
	if err := writeListOrMark(cp, rel, collector, apiPath, items, status); err != nil {
		return nil, err
	}
	if rtype == "" || status != 0 {
		return nil, nil
	}
	out := make([]resourceRef, 0, len(items))
	for _, raw := range items {
		id := strField(raw, "id")
		if id == "" {
			if n := numField(raw, "id"); n != 0 {
				id = fmt.Sprintf("%d", n)
			}
		}
		if id != "" {
			out = append(out, resourceRef{Type: rtype, ID: id, Name: strField(raw, "name")})
		}
	}
	return out, nil
}

func collectPolicies(ctx context.Context, cl ADO, cp engine.CurrentPhase, project string) error {
	pe := url.PathEscape(project)
	_, err := listSurface(ctx, cl, cp, project, "core", APIVersion,
		"/"+pe+"/_apis/policy/configurations", engine.CollectADOPolicies(project), "policy-configurations", "")
	if err != nil {
		return err
	}
	_, err = listSurface(ctx, cl, cp, project, "core", APIVersion,
		"/"+pe+"/_apis/policy/types", engine.CollectADOPolicyTypes(project), "policy-types", "")
	return err
}

func collectBuildACL(ctx context.Context, cl ADO, cp engine.CurrentPhase, project, projectID string) error {
	raw, status, err := softGet(ctx, cl, "core", APIVersion, "/_apis/accesscontrollists/"+buildNS,
		url.Values{"token": []string{projectID}, "includeExtendedInfo": []string{"true"}})
	if err != nil {
		return err
	}
	return writeOrMark(cp, engine.CollectADOBuildACL(project), "build-acl",
		"/_apis/accesscontrollists/"+buildNS, raw, status)
}

func collectRepoACL(ctx context.Context, cl ADO, cp engine.CurrentPhase, project, projectID string, repo repoRef) error {
	token := fmt.Sprintf("repoV2/%s/%s", projectID, repo.ID)
	raw, status, err := softGet(ctx, cl, "core", APIVersion, "/_apis/accesscontrollists/"+gitNS,
		url.Values{"token": []string{token}, "includeExtendedInfo": []string{"true"}, "recurse": []string{"true"}})
	if err != nil {
		return err
	}
	return writeOrMark(cp, engine.CollectADORepoACL(project, repo.Name), "repo-acl",
		"/_apis/accesscontrollists/"+gitNS, raw, status)
}

// ================= PER-RESOURCE (checks + pipeline permissions) =================

func collectPipelinePermissions(ctx context.Context, cl ADO, cp engine.CurrentPhase, project string, r resourceRef) error {
	p := fmt.Sprintf("/%s/_apis/pipelines/pipelinepermissions/%s/%s", url.PathEscape(project), r.Type, url.PathEscape(r.ID))
	raw, status, err := softGet(ctx, cl, "core", APIVersionPreview, p, nil)
	if err != nil {
		return err
	}
	return writeOrMark(cp, engine.CollectADOPipelinePerms(project, r.Type, r.ID), "pipeline-permissions", p, raw, status)
}

func collectChecks(ctx context.Context, cl ADO, cp engine.CurrentPhase, project string, r resourceRef) error {
	p := fmt.Sprintf("/%s/_apis/pipelines/checks/configurations", url.PathEscape(project))
	params := url.Values{
		"resourceType": []string{r.Type},
		"resourceId":   []string{r.ID},
		"$expand":      []string{"settings"},
	}
	items, status, err := softList(ctx, cl, "core", APIVersionPreview, p, params)
	if err != nil || status != 0 {
		return err
	}
	return envelope(cp, engine.CollectADOChecks(project, r.Type, r.ID), "checks", p, rawArray(items))
}

// ================= PER-ENV =================

func collectEnvironmentDetail(ctx context.Context, cl ADO, cp engine.CurrentPhase, project string, envID int64) error {
	p := fmt.Sprintf("/%s/_apis/distributedtask/environments/%d", url.PathEscape(project), envID)
	raw, status, err := softGet(ctx, cl, "core", APIVersion, p, url.Values{"expands": []string{"resourceReferences"}})
	if err != nil {
		return err
	}
	return writeOrMark(cp, engine.CollectADOEnvironmentDetail(project, envID), "environment-detail", p, raw, status)
}

// ================= PER-PIPELINE (build def full + preview) =================

// collectBuildDefFull returns the full definition so the caller can drive YAML +
// template-closure collection.
func collectBuildDefFull(ctx context.Context, cl ADO, cp engine.CurrentPhase, project string, id int64) (json.RawMessage, error) {
	p := fmt.Sprintf("/%s/_apis/build/definitions/%d", url.PathEscape(project), id)
	raw, status, err := softGet(ctx, cl, "core", APIVersion, p, nil)
	if err != nil {
		return nil, err
	}
	if status != 0 {
		// unobservable: mark and skip downstream YAML/preview (caller checks nil)
		return nil, writeOrMark(cp, engine.CollectADOBuildDefFull(project, id), "build-definition", p, nil, status)
	}
	if err := envelope(cp, engine.CollectADOBuildDefFull(project, id), "build-definition", p, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// collectReleaseFull fetches one classic release definition's full detail
// (environments, pre/post-deploy approvals, gates, artifacts, triggers) — the
// list endpoint returns only summaries. cat-14.
func collectReleaseFull(ctx context.Context, cl ADO, cp engine.CurrentPhase, project string, id int64) error {
	p := fmt.Sprintf("/%s/_apis/release/definitions/%d", url.PathEscape(project), id)
	raw, status, err := softGet(ctx, cl, "vsrm", APIVersion, p, nil)
	if err != nil {
		return err
	}
	return writeOrMark(cp, engine.CollectADOReleaseFull(project, id), "release-definition", p, raw, status)
}

// collectPipelinePreview soft-fails per pipeline (a template-consumer whose
// resource-repo alias can't resolve returns HTTP 400).
func collectPipelinePreview(ctx context.Context, cl ADO, cp engine.CurrentPhase, project string, id int64) error {
	p := fmt.Sprintf("/%s/_apis/pipelines/%d/preview", url.PathEscape(project), id)
	raw, err := cl.Post(ctx, "core", APIVersionPreview, p, nil, map[string]any{"previewRun": true})
	if err != nil {
		// preview validation errors (400) and permission (403) are non-fatal here
		if isSoft(err) || softStatus(err) == 400 {
			return envelope(cp, engine.CollectADOPipelinePreview(project, id), "pipeline-preview", p,
				map[string]any{"_error": err.Error()})
		}
		return err
	}
	return envelope(cp, engine.CollectADOPipelinePreview(project, id), "pipeline-preview", p, raw)
}
