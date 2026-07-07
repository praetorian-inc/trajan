package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// Each per-repo collector (rulesets/secrets/variables/runners) also serves the
// org scope when called with repo=="". Optional surfaces soft-fail (403/404 ->
// skip + mark) rather than aborting.
//
// The secrets collector captures metadata only (names/scope/visibility/
// updated_at) — never secret values.

const collectorVer = "@0.1"

func nowISO() string { return engine.IsoformatUTC(time.Now()) }

type collectMeta struct {
	CollectedAt string         `json:"collected_at"`
	Collector   string         `json:"collector"`
	Source      collectMetaSrc `json:"source"`
}

type collectMetaSrc struct {
	API  string `json:"api"`
	Path string `json:"path"`
}

// envelope stamps source.api=github_rest; surfaces whose primary call is
// offloaded call envelopeAPI to stamp github_graphql/github_git instead.
func envelope(cp engine.CurrentPhase, rel, collector, sourcePath string, data any) error {
	return envelopeAPI(cp, rel, collector, "github_rest", sourcePath, data)
}

func envelopeAPI(cp engine.CurrentPhase, rel, collector, api, sourcePath string, data any) error {
	return cp.Write(rel, map[string]any{
		"_meta": collectMeta{
			CollectedAt: nowISO(),
			Collector:   collector + collectorVer,
			Source:      collectMetaSrc{API: api, Path: sourcePath},
		},
		"data": data,
	})
}

func softStatus(err error) int {
	var ghErr *GhError
	if asGhError(err, &ghErr) {
		return ghErr.Status
	}
	return 0
}

func isSoft(err error) bool {
	s := softStatus(err)
	return s == 403 || s == 404
}

// A 404 yields (nil, nil); any other error (including 403) propagates.
func allow404Get(ctx context.Context, gh GitHub, p string) (json.RawMessage, error) {
	raw, _, err := gh.Get(ctx, p, nil, true)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// Returns (raw, status): status is 0 on success, or 403/404 when the resource
// was unobservable (raw nil). A non-soft error propagates.
func softGet(ctx context.Context, gh GitHub, p string) (json.RawMessage, int, error) {
	raw, _, err := gh.Get(ctx, p, nil, true)
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

func softPaginate(ctx context.Context, gh GitHub, p string, params url.Values, perPage int) ([]json.RawMessage, int, error) {
	items, err := gh.Paginate(ctx, p, params, perPage)
	if err != nil {
		if isSoft(err) {
			return nil, softStatus(err), nil
		}
		return nil, 0, err
	}
	return items, 0, nil
}

// Swallows ANY GhError (not just 403/404) to an empty list; non-GhError propagates.
func paginateSwallow(ctx context.Context, gh GitHub, p string, params url.Values) ([]json.RawMessage, error) {
	items, err := gh.Paginate(ctx, p, params, 0)
	if err != nil {
		var ghErr *GhError
		if asGhError(err, &ghErr) {
			return []json.RawMessage{}, nil
		}
		return nil, err
	}
	return items, nil
}

// Ensures a nil slice marshals as [] rather than null, since rules key on it.
func rawArray(items []json.RawMessage) []json.RawMessage {
	if items == nil {
		return []json.RawMessage{}
	}
	return items
}

func objField(raw json.RawMessage, key string) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m[key]
}

// Returns [] when the key is absent, null, or not an array.
func rawArrayField(raw json.RawMessage, key string) []json.RawMessage {
	v := objField(raw, key)
	if len(v) == 0 {
		return []json.RawMessage{}
	}
	var arr []json.RawMessage
	if json.Unmarshal(v, &arr) != nil {
		return []json.RawMessage{}
	}
	return arr
}

func strField(raw json.RawMessage, key string) string {
	return decodeString(objField(raw, key))
}

func collectOrg(ctx context.Context, gh GitHub, cp engine.CurrentPhase, org string) error {
	orgInfo, _, err := gh.Get(ctx, fmt.Sprintf("/orgs/%s", org), nil, false)
	if err != nil {
		return err
	}
	actionsPerms, err := allow404Get(ctx, gh, fmt.Sprintf("/orgs/%s/actions/permissions", org))
	if err != nil {
		return err
	}
	workflowPerms, err := allow404Get(ctx, gh, fmt.Sprintf("/orgs/%s/actions/permissions/workflow", org))
	if err != nil {
		if softStatus(err) != 403 {
			return err
		}
		workflowPerms = nil
	}
	var selectedActions json.RawMessage
	if len(actionsPerms) > 0 && strField(actionsPerms, "allowed_actions") == "selected" {
		selectedActions, err = allow404Get(ctx, gh, fmt.Sprintf("/orgs/%s/actions/permissions/selected-actions", org))
		if err != nil {
			return err
		}
	}
	hooks, hooksStatus, err := softPaginate(ctx, gh, fmt.Sprintf("/orgs/%s/hooks", org), nil, 0)
	if err != nil {
		return err
	}
	if hooksStatus != 0 {
		hooks = nil
	}
	secManagers, err := allow404Get(ctx, gh, fmt.Sprintf("/orgs/%s/security-managers", org))
	if err != nil {
		return err
	}
	data := map[string]any{
		"org":                          rawOrNull(orgInfo),
		"actions_permissions":          rawOrNull(actionsPerms),
		"actions_workflow_permissions": rawOrNull(workflowPerms),
		"selected_actions":             rawOrNull(selectedActions),
		"hooks":                        rawArray(hooks),
		"security_managers":            rawOrNull(secManagers),
	}
	return envelope(cp, engine.CollectOrg(org), "00_collect_org.py",
		fmt.Sprintf("/orgs/%s (bundle)", org), data)
}

func collectRepo(ctx context.Context, gh GitHub, cp engine.CurrentPhase, org, repo string) error {
	data, err := fetchRepoBundle(ctx, gh, org, repo)
	if err != nil {
		// A GhError still writes a per-repo {_error} payload; a transport error aborts.
		var ghErr *GhError
		if !asGhError(err, &ghErr) {
			return err
		}
		data = map[string]any{"_error": err.Error()}
	}
	// The repo object (primary call) is graphql-offloaded; stamp accordingly.
	return envelopeAPI(cp, engine.CollectRepo(repo), "00_collect_repos.py",
		sourceAPI(gh, surfaceRepoMeta), fmt.Sprintf("/repos/%s/%s (bundle)", org, repo), data)
}

func fetchRepoBundle(ctx context.Context, gh GitHub, org, repo string) (map[string]any, error) {
	full, _, err := gh.Get(ctx, fmt.Sprintf("/repos/%s/%s", org, repo), nil, false)
	if err != nil {
		return nil, err
	}
	branch := strField(full, "default_branch")
	if branch == "" {
		branch = "main"
	}
	legacyBP, err := allow404Get(ctx, gh, fmt.Sprintf("/repos/%s/%s/branches/%s/protection", org, repo, branch))
	if err != nil {
		return nil, err
	}
	topics, err := allow404Get(ctx, gh, fmt.Sprintf("/repos/%s/%s/topics", org, repo))
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"repo":                      rawOrNull(full),
		"default_branch_protection": rawOrNull(legacyBP),
		"topics":                    rawOrNull(topics),
	}, nil
}

func collectActionsSettings(ctx context.Context, gh GitHub, cp engine.CurrentPhase, org, repo string) error {
	perms, err := allow404Get(ctx, gh, fmt.Sprintf("/repos/%s/%s/actions/permissions", org, repo))
	if err != nil {
		return err
	}
	workflowPerms, err := allow404Get(ctx, gh, fmt.Sprintf("/repos/%s/%s/actions/permissions/workflow", org, repo))
	if err != nil {
		return err
	}
	access, err := allow404Get(ctx, gh, fmt.Sprintf("/repos/%s/%s/actions/permissions/access", org, repo))
	if err != nil {
		return err
	}
	data := map[string]any{
		"permissions":          rawOrNull(perms),
		"workflow_permissions": rawOrNull(workflowPerms),
		"access":               rawOrNull(access),
	}
	return envelope(cp, engine.CollectActionsSettings(repo), "00_collect_actions_settings.py",
		fmt.Sprintf("/repos/%s/%s/actions/permissions[*]", org, repo), data)
}

// The list endpoints return summaries only, so per-id detail is fetched for the
// rules[]/bypass_actors[] that branch selection and scans need.
func collectRulesets(ctx context.Context, gh GitHub, cp engine.CurrentPhase, org, repo string) error {
	if repo == "" {
		return collectRulesetsOrg(ctx, gh, cp, org)
	}
	return collectRulesetsRepo(ctx, gh, cp, org, repo)
}

func collectRulesetsOrg(ctx context.Context, gh GitHub, cp engine.CurrentPhase, org string) error {
	summaries, status, err := softPaginate(ctx, gh, fmt.Sprintf("/orgs/%s/rulesets", org), nil, 0)
	if err != nil {
		return err
	}
	if status != 0 {
		return nil
	}
	detailed, err := rulesetDetails(ctx, gh, summaries, func(id string) string {
		return fmt.Sprintf("/orgs/%s/rulesets/%s", org, id)
	})
	if err != nil {
		return err
	}
	data := map[string]any{"scope": "org", "owner": org, "rulesets": rawArray(detailed)}
	return envelope(cp, engine.CollectRulesetsOrg(org), "00_collect_rulesets.py",
		fmt.Sprintf("/orgs/%s/rulesets", org), data)
}

func collectRulesetsRepo(ctx context.Context, gh GitHub, cp engine.CurrentPhase, org, repo string) error {
	params := url.Values{"includes_parents": []string{"false"}}
	summaries, status, err := softPaginate(ctx, gh, fmt.Sprintf("/repos/%s/%s/rulesets", org, repo), params, 0)
	if err != nil {
		return err
	}
	var data map[string]any
	if status != 0 {
		data = map[string]any{"scope": "repo", "owner": org, "repo": repo,
			"rulesets": []json.RawMessage{}, "_unavailable": true}
	} else {
		detailed, derr := rulesetDetails(ctx, gh, summaries, func(id string) string {
			return fmt.Sprintf("/repos/%s/%s/rulesets/%s", org, repo, id)
		})
		if derr != nil {
			return derr
		}
		data = map[string]any{"scope": "repo", "owner": org, "repo": repo, "rulesets": rawArray(detailed)}
	}
	return envelope(cp, engine.CollectRulesetsRepo(repo), "00_collect_rulesets.py",
		fmt.Sprintf("/repos/%s/%s/rulesets[*]", org, repo), data)
}

func rulesetDetails(ctx context.Context, gh GitHub, summaries []json.RawMessage, detailPath func(id string) string) ([]json.RawMessage, error) {
	detailed := make([]json.RawMessage, 0, len(summaries))
	for _, rs := range summaries {
		id := numField(rs, "id")
		if id == "" {
			continue
		}
		full, status, err := softGet(ctx, gh, detailPath(id))
		if err != nil {
			return nil, err
		}
		if status == 0 && full != nil {
			detailed = append(detailed, full)
		}
	}
	return detailed, nil
}

func collectEnvironments(ctx context.Context, gh GitHub, cp engine.CurrentPhase, org, repo string) error {
	envsResp, _, err := softGet(ctx, gh, fmt.Sprintf("/repos/%s/%s/environments", org, repo))
	if err != nil {
		return err
	}
	if envsResp == nil {
		return nil
	}
	for _, env := range rawArrayField(envsResp, "environments") {
		name := strField(env, "name")
		if name == "" {
			continue
		}
		safe := url.PathEscape(name)
		base, baseS, err := softGet(ctx, gh, fmt.Sprintf("/repos/%s/%s/environments/%s", org, repo, safe))
		if err != nil {
			return err
		}
		branchPolicies, bpS, err := softGet(ctx, gh, fmt.Sprintf("/repos/%s/%s/environments/%s/deployment-branch-policies", org, repo, safe))
		if err != nil {
			return err
		}
		protectionRules, prS, err := softGet(ctx, gh, fmt.Sprintf("/repos/%s/%s/environments/%s/deployment_protection_rules", org, repo, safe))
		if err != nil {
			return err
		}
		data := map[string]any{
			"repo":             repo,
			"name":             name,
			"base":             rawOrNull(base),
			"branch_policies":  rawOrNull(branchPolicies),
			"protection_rules": rawOrNull(protectionRules),
		}
		if failed := only403(map[string]int{"base": baseS, "branch_policies": bpS, "protection_rules": prS}); len(failed) > 0 {
			data["_unavailable_buckets"] = failed
		}
		if err := envelope(cp, engine.CollectEnvironment(repo, name), "00_collect_environments.py",
			fmt.Sprintf("/repos/%s/%s/environments/%s (bundle)", org, repo, name), data); err != nil {
			return err
		}
	}
	return nil
}

func collectSecrets(ctx context.Context, gh GitHub, cp engine.CurrentPhase, org, repo string) error {
	if repo == "" {
		return collectSecretsOrg(ctx, gh, cp, org)
	}
	return collectSecretsRepo(ctx, gh, cp, org, repo)
}

func collectSecretsOrg(ctx context.Context, gh GitHub, cp engine.CurrentPhase, org string) error {
	actions, aStatus, err := softPaginate(ctx, gh, fmt.Sprintf("/orgs/%s/actions/secrets", org), nil, 100)
	if err != nil {
		return err
	}
	enriched, err := enrichSelectedRepos(ctx, gh, org, actions)
	if err != nil {
		return err
	}
	dependabot, dStatus, err := softPaginate(ctx, gh, fmt.Sprintf("/orgs/%s/dependabot/secrets", org), nil, 100)
	if err != nil {
		return err
	}
	codespaces, cStatus, err := softPaginate(ctx, gh, fmt.Sprintf("/orgs/%s/codespaces/secrets", org), nil, 100)
	if err != nil {
		return err
	}
	data := map[string]any{
		"scope":              "org",
		"owner":              org,
		"actions_secrets":    rawArray(enriched),
		"dependabot_secrets": rawArray(dependabot),
		"codespaces_secrets": rawArray(codespaces),
	}
	mergeUnavailable(data, map[string]int{"actions": aStatus, "dependabot": dStatus, "codespaces": cStatus})
	return envelope(cp, engine.CollectSecrets(org), "00_collect_secrets_scope.py",
		fmt.Sprintf("/orgs/%s/...secrets (bundle)", org), data)
}

func collectSecretsRepo(ctx context.Context, gh GitHub, cp engine.CurrentPhase, org, repo string) error {
	actions, aStatus, err := softPaginate(ctx, gh, fmt.Sprintf("/repos/%s/%s/actions/secrets", org, repo), nil, 100)
	if err != nil {
		return err
	}
	dependabot, dStatus, err := softPaginate(ctx, gh, fmt.Sprintf("/repos/%s/%s/dependabot/secrets", org, repo), nil, 100)
	if err != nil {
		return err
	}
	codespaces, cStatus, err := softPaginate(ctx, gh, fmt.Sprintf("/repos/%s/%s/codespaces/secrets", org, repo), nil, 100)
	if err != nil {
		return err
	}
	data := map[string]any{
		"scope":              "repo",
		"owner":              org,
		"repo":               repo,
		"actions_secrets":    rawArray(actions),
		"dependabot_secrets": rawArray(dependabot),
		"codespaces_secrets": rawArray(codespaces),
	}
	mergeUnavailable(data, map[string]int{"actions": aStatus, "dependabot": dStatus, "codespaces": cStatus})
	if err := envelope(cp, engine.CollectSecrets(repo), "00_collect_secrets_scope.py",
		fmt.Sprintf("/repos/%s/%s/...secrets (bundle)", org, repo), data); err != nil {
		return err
	}

	envsResp, _, err := softGet(ctx, gh, fmt.Sprintf("/repos/%s/%s/environments", org, repo))
	if err != nil {
		return err
	}
	if envsResp == nil {
		return nil
	}
	for _, env := range rawArrayField(envsResp, "environments") {
		name := strField(env, "name")
		if name == "" {
			continue
		}
		safe := url.PathEscape(name)
		eActions, eStatus, err := softPaginate(ctx, gh, fmt.Sprintf("/repos/%s/%s/environments/%s/secrets", org, repo, safe), nil, 100)
		if err != nil {
			return err
		}
		// Skip "readable but empty"; only "couldn't read" or non-empty writes a file.
		if len(eActions) == 0 && eStatus == 0 {
			continue
		}
		envData := map[string]any{
			"scope":           "environment",
			"owner":           org,
			"repo":            repo,
			"environment":     name,
			"actions_secrets": rawArray(eActions),
		}
		mergeUnavailable(envData, map[string]int{"actions": eStatus})
		key := repo + "__" + name
		if err := envelope(cp, engine.CollectSecrets(key), "00_collect_secrets_scope.py",
			fmt.Sprintf("/repos/%s/%s/environments/%s/secrets", org, repo, name), envData); err != nil {
			return err
		}
	}
	return nil
}

// Adds a selected_repositories list to each "selected"-visibility org secret.
func enrichSelectedRepos(ctx context.Context, gh GitHub, org string, secrets []json.RawMessage) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, 0, len(secrets))
	for _, s := range secrets {
		if strField(s, "visibility") != "selected" {
			out = append(out, s)
			continue
		}
		name := strField(s, "name")
		safe := url.PathEscape(name)
		repos, _, err := softPaginate(ctx, gh, fmt.Sprintf("/orgs/%s/actions/secrets/%s/repositories", org, safe), nil, 100)
		if err != nil {
			return nil, err
		}
		sel := make([]map[string]any, 0, len(repos))
		for _, r := range repos {
			sel = append(sel, map[string]any{
				"id":        rawOrNull(objField(r, "id")),
				"name":      rawOrNull(objField(r, "name")),
				"full_name": rawOrNull(objField(r, "full_name")),
			})
		}
		merged, err := spliceRaw(s, map[string]any{"selected_repositories": sel})
		if err != nil {
			return nil, err
		}
		out = append(out, merged)
	}
	return out, nil
}

// Unlike secrets, variable values are returned by the API and kept as-is.
func collectVariables(ctx context.Context, gh GitHub, cp engine.CurrentPhase, org, repo string) error {
	if repo == "" {
		orgVars, err := listVariables(ctx, gh, fmt.Sprintf("/orgs/%s/actions/variables", org))
		if err != nil {
			return err
		}
		data := map[string]any{"scope": "org", "owner": org, "variables": rawArray(orgVars)}
		return envelope(cp, engine.CollectVariables(org), "00_collect_variables.py",
			fmt.Sprintf("/orgs/%s/actions/variables", org), data)
	}

	repoVars, err := listVariables(ctx, gh, fmt.Sprintf("/repos/%s/%s/actions/variables", org, repo))
	if err != nil {
		return err
	}
	data := map[string]any{"scope": "repo", "owner": org, "repo": repo, "variables": rawArray(repoVars)}
	if err := envelope(cp, engine.CollectVariables(repo), "00_collect_variables.py",
		fmt.Sprintf("/repos/%s/%s/actions/variables", org, repo), data); err != nil {
		return err
	}

	envsResp, _, err := softGet(ctx, gh, fmt.Sprintf("/repos/%s/%s/environments", org, repo))
	if err != nil {
		return err
	}
	if envsResp == nil {
		return nil
	}
	for _, env := range rawArrayField(envsResp, "environments") {
		name := strField(env, "name")
		if name == "" {
			continue
		}
		safe := url.PathEscape(name)
		evars, err := listVariables(ctx, gh, fmt.Sprintf("/repos/%s/%s/environments/%s/variables", org, repo, safe))
		if err != nil {
			return err
		}
		if len(evars) == 0 {
			continue
		}
		envData := map[string]any{
			"scope":       "environment",
			"owner":       org,
			"repo":        repo,
			"environment": name,
			"variables":   rawArray(evars),
		}
		key := repo + "__" + name
		if err := envelope(cp, engine.CollectVariables(key), "00_collect_variables.py",
			fmt.Sprintf("/repos/%s/%s/environments/%s/variables", org, repo, name), envData); err != nil {
			return err
		}
	}
	return nil
}

// Swallows ALL GhErrors (not just 403/404) to [].
func listVariables(ctx context.Context, gh GitHub, p string) ([]json.RawMessage, error) {
	raw, _, err := gh.Get(ctx, p, nil, true)
	if err != nil {
		var ghErr *GhError
		if asGhError(err, &ghErr) {
			return []json.RawMessage{}, nil
		}
		return nil, err
	}
	if raw == nil {
		return []json.RawMessage{}, nil
	}
	if vars := rawArrayField(raw, "variables"); len(vars) > 0 {
		return vars, nil
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		return arr, nil
	}
	return []json.RawMessage{}, nil
}

func collectApps(ctx context.Context, gh GitHub, cp engine.CurrentPhase, org string) error {
	installations, err := listInstallations(ctx, gh, org)
	if err != nil {
		return err
	}
	if err := envelope(cp, engine.CollectAppsInstallations(org), "00_collect_apps.py",
		fmt.Sprintf("/orgs/%s/installations", org),
		map[string]any{"installations": rawArray(installations)}); err != nil {
		return err
	}
	for _, inst := range installations {
		slug := strField(inst, "app_slug")
		if slug == "" {
			slug = strField(objField(inst, "app"), "slug")
		}
		if slug == "" {
			continue
		}
		appInfo, _, err := softGet(ctx, gh, fmt.Sprintf("/apps/%s", slug))
		if err != nil {
			return err
		}
		data := map[string]any{
			"app_slug":     slug,
			"owner":        org,
			"installation": rawOrNull(inst),
			"app":          rawOrNull(appInfo),
		}
		if err := envelope(cp, engine.CollectApp(org, slug), "00_collect_apps.py",
			fmt.Sprintf("/apps/%s", slug), data); err != nil {
			return err
		}
	}
	return nil
}

// On a 403/404 falls back to /installation/repositories, capturing only the
// current installation's repos as a single partial record.
func listInstallations(ctx context.Context, gh GitHub, org string) ([]json.RawMessage, error) {
	pages, err := gh.Paginate(ctx, fmt.Sprintf("/orgs/%s/installations", org),
		url.Values{"per_page": []string{"100"}}, 100)
	if err != nil {
		if !isSoft(err) {
			return nil, err
		}
		cur, _, ferr := gh.Get(ctx, "/installation/repositories", nil, false)
		if ferr != nil {
			if isSoft(ferr) {
				return []json.RawMessage{}, nil
			}
			return nil, ferr
		}
		partial := map[string]any{
			"_partial":     true,
			"_note":        "only the current installation is visible to this token",
			"repositories": rawArray(rawArrayField(cur, "repositories")),
		}
		b, mErr := json.Marshal(partial)
		if mErr != nil {
			return nil, mErr
		}
		return []json.RawMessage{b}, nil
	}
	return pages, nil
}

func collectRunners(ctx context.Context, gh GitHub, cp engine.CurrentPhase, org, repo string) error {
	if repo == "" {
		return collectRunnersOrg(ctx, gh, cp, org)
	}
	return collectRunnersRepo(ctx, gh, cp, org, repo)
}

func collectRunnersOrg(ctx context.Context, gh GitHub, cp engine.CurrentPhase, org string) error {
	unavailable := map[string]int{}

	groupsResp, gStatus, err := softGet(ctx, gh, fmt.Sprintf("/orgs/%s/actions/runner-groups", org))
	if err != nil {
		return err
	}
	var groups []json.RawMessage
	if gStatus != 0 {
		unavailable["runner_groups"] = gStatus
	} else if groupsResp != nil {
		raw := rawArrayField(groupsResp, "runner_groups")
		groups = make([]json.RawMessage, 0, len(raw))
		for _, g := range raw {
			enriched, err := enrichRunnerGroup(ctx, gh, org, g)
			if err != nil {
				return err
			}
			groups = append(groups, enriched)
		}
	} else {
		unavailable["runner_groups"] = 404
	}

	runnersResp, rStatus, err := softGet(ctx, gh, fmt.Sprintf("/orgs/%s/actions/runners", org))
	if err != nil {
		return err
	}
	var runners []json.RawMessage
	if rStatus != 0 {
		unavailable["runners"] = rStatus
	} else if runnersResp != nil {
		runners = rawArrayField(runnersResp, "runners")
	} else {
		unavailable["runners"] = 404
	}

	data := map[string]any{
		"scope":         "org",
		"owner":         org,
		"runner_groups": rawArray(groups),
		"runners":       rawArray(runners),
	}
	if len(unavailable) > 0 {
		data["_unavailable_buckets"] = unavailable
	}
	if err := envelope(cp, engine.CollectRunners(org), "00_collect_runners.py",
		fmt.Sprintf("/orgs/%s/actions/runners (bundle)", org), data); err != nil {
		return err
	}
	for _, g := range groups {
		gid := numField(g, "id")
		if gid == "" {
			continue
		}
		id, ok := parseInt64(gid)
		if !ok {
			continue
		}
		if err := envelope(cp, engine.CollectRunnerGroup(id), "00_collect_runners.py",
			fmt.Sprintf("/orgs/%s/actions/runner-groups/%s", org, gid), rawOrNull(g)); err != nil {
			return err
		}
	}
	return nil
}

func enrichRunnerGroup(ctx context.Context, gh GitHub, org string, group json.RawMessage) (json.RawMessage, error) {
	gid := numField(group, "id")
	if gid == "" {
		return group, nil
	}
	reposResp, repoStatus, err := softGet(ctx, gh, fmt.Sprintf("/orgs/%s/actions/runner-groups/%s/repositories", org, gid))
	if err != nil {
		return nil, err
	}
	runnersResp, runStatus, err := softGet(ctx, gh, fmt.Sprintf("/orgs/%s/actions/runner-groups/%s/runners", org, gid))
	if err != nil {
		return nil, err
	}
	add := map[string]any{
		"selected_repositories": anyArray(rawArrayField(reposResp, "repositories")),
		"member_runners":        anyArray(rawArrayField(runnersResp, "runners")),
	}
	if repoStatus == 403 || repoStatus == 404 {
		add["_repositories_unavailable"] = repoStatus
	}
	if runStatus == 403 || runStatus == 404 {
		add["_member_runners_unavailable"] = runStatus
	}
	return spliceRaw(group, add)
}

func collectRunnersRepo(ctx context.Context, gh GitHub, cp engine.CurrentPhase, org, repo string) error {
	resp, status, err := softGet(ctx, gh, fmt.Sprintf("/repos/%s/%s/actions/runners", org, repo))
	if err != nil {
		return err
	}
	data := map[string]any{"scope": "repo", "owner": org, "repo": repo}
	if status == 403 || status == 404 {
		data["runners"] = []json.RawMessage{}
		data["_unavailable"] = true
		data["_unavailable_status"] = status
	} else {
		data["runners"] = rawArray(rawArrayField(resp, "runners"))
	}
	return envelope(cp, engine.CollectRunners(repo), "00_collect_runners.py",
		fmt.Sprintf("/repos/%s/%s/actions/runners", org, repo), data)
}

func collectDeployKeys(ctx context.Context, gh GitHub, cp engine.CurrentPhase, org, repo string) error {
	keys, status, err := softPaginate(ctx, gh, fmt.Sprintf("/repos/%s/%s/keys", org, repo), nil, 0)
	if err != nil {
		return err
	}
	data := map[string]any{"repo": repo}
	if status == 403 || status == 404 {
		data["deploy_keys"] = []json.RawMessage{}
		data["_unavailable"] = true
		data["_unavailable_status"] = status
	} else {
		data["deploy_keys"] = rawArray(keys)
	}
	return envelope(cp, engine.CollectDeployKeys(repo), "00_collect_deploy_keys.py",
		fmt.Sprintf("/repos/%s/%s/keys", org, repo), data)
}

func collectMembers(ctx context.Context, gh GitHub, cp engine.CurrentPhase, org string) error {
	members, err := paginateSwallow(ctx, gh, fmt.Sprintf("/orgs/%s/members", org), nil)
	if err != nil {
		return err
	}
	outside, err := paginateSwallow(ctx, gh, fmt.Sprintf("/orgs/%s/outside_collaborators", org), nil)
	if err != nil {
		return err
	}
	teamSummaries, err := paginateSwallow(ctx, gh, fmt.Sprintf("/orgs/%s/teams", org), nil)
	if err != nil {
		return err
	}
	teams := make([]json.RawMessage, 0, len(teamSummaries))
	for _, ts := range teamSummaries {
		slug := strField(ts, "slug")
		if slug == "" {
			continue
		}
		team, terr := collectTeam(ctx, gh, org, slug, ts)
		if terr != nil {
			var ghErr *GhError
			if asGhError(terr, &ghErr) {
				continue
			}
			return terr
		}
		teams = append(teams, team)
	}

	perRepo := map[string]any{}
	perRepoUnavailable := map[string]int{}
	for _, repo := range collectedRepoNames(cp) {
		collabs, status, cerr := collectRepoCollaborators(ctx, gh, org, repo)
		if cerr != nil {
			return cerr
		}
		perRepo[repo] = collabs
		if status == 403 || status == 404 {
			perRepoUnavailable[repo] = status
		}
	}

	data := map[string]any{
		"owner":                  org,
		"members":                loginIDType(members),
		"outside_collaborators":  loginIDType(outside),
		"teams":                  teams,
		"per_repo_collaborators": perRepo,
	}
	if len(perRepoUnavailable) > 0 {
		data["per_repo_collaborators_unavailable"] = perRepoUnavailable
	}
	// The members list (primary call) is graphql-offloaded; stamp accordingly.
	return envelopeAPI(cp, engine.CollectMembers(org), "00_collect_members.py",
		sourceAPI(gh, surfaceOrgMembers), fmt.Sprintf("/orgs/%s/members + ...outside_collaborators + ...teams (bundle)", org), data)
}

func collectRepoCollaborators(ctx context.Context, gh GitHub, org, repo string) ([]map[string]any, int, error) {
	items, status, err := softPaginate(ctx, gh, fmt.Sprintf("/repos/%s/%s/collaborators", org, repo),
		url.Values{"affiliation": []string{"all"}}, 0)
	if err != nil {
		return nil, 0, err
	}
	out := make([]map[string]any, 0, len(items))
	for _, c := range items {
		out = append(out, map[string]any{
			"login":       rawOrNull(objField(c, "login")),
			"id":          rawOrNull(objField(c, "id")),
			"type":        rawOrNull(objField(c, "type")),
			"role_name":   rawOrNull(objField(c, "role_name")),
			"permissions": rawOrNull(objField(c, "permissions")),
		})
	}
	return out, status, nil
}

func collectedRepoNames(cp engine.CurrentPhase) []string {
	dir := filepath.Join(cp.RunDir, "00-collect", "repos")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if name := strings.TrimSuffix(e.Name(), ".json"); name != e.Name() {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func collectTeam(ctx context.Context, gh GitHub, org, slug string, summary json.RawMessage) (json.RawMessage, error) {
	memberItems, err := gh.Paginate(ctx, fmt.Sprintf("/orgs/%s/teams/%s/members", org, slug), nil, 0)
	if err != nil {
		return nil, err
	}
	repoItems, err := gh.Paginate(ctx, fmt.Sprintf("/orgs/%s/teams/%s/repos", org, slug), nil, 0)
	if err != nil {
		return nil, err
	}
	mem := make([]map[string]any, 0, len(memberItems))
	for _, m := range memberItems {
		mem = append(mem, map[string]any{
			"login": rawOrNull(objField(m, "login")),
			"id":    rawOrNull(objField(m, "id")),
		})
	}
	rs := make([]map[string]any, 0, len(repoItems))
	for _, r := range repoItems {
		rs = append(rs, map[string]any{
			"name":       rawOrNull(objField(r, "name")),
			"permission": rawOrNull(objField(r, "permission")),
		})
	}
	return spliceRaw(summary, map[string]any{"slug": slug, "members": mem, "repos": rs})
}

func loginIDType(items []json.RawMessage) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		out = append(out, map[string]any{
			"login": rawOrNull(objField(it, "login")),
			"id":    rawOrNull(objField(it, "id")),
			"type":  rawOrNull(objField(it, "type")),
		})
	}
	return out
}

// Returns a JSON null (not nil) for an absent value so the field serializes as
// null rather than being omitted, since rules key on it.
func rawOrNull(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	return raw
}

// Merges add into a raw JSON object, preserving the original values byte-for-byte
// so numeric ids keep full precision. A non-object raw is returned unchanged.
func spliceRaw(raw json.RawMessage, add map[string]any) (json.RawMessage, error) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return raw, nil
	}
	for k, v := range add {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		m[k] = b
	}
	return json.Marshal(m)
}

// Converts to []any so it always marshals as a JSON array, never null.
func anyArray(items []json.RawMessage) []any {
	out := make([]any, 0, len(items))
	for _, it := range items {
		out = append(out, it)
	}
	return out
}

// For environments, only a 403 (not a 404) marks a bucket unavailable.
func only403(buckets map[string]int) map[string]int {
	out := map[string]int{}
	for k, v := range buckets {
		if v == 403 {
			out[k] = v
		}
	}
	return out
}

// Adds _unavailable_buckets for any soft-failed bucket, and _unavailable=true
// only when every bucket soft-failed.
func mergeUnavailable(data map[string]any, buckets map[string]int) {
	failed := map[string]int{}
	for k, v := range buckets {
		if v != 0 {
			failed[k] = v
		}
	}
	if len(failed) == 0 {
		return
	}
	data["_unavailable_buckets"] = failed
	if len(failed) == len(buckets) {
		data["_unavailable"] = true
	}
}

// Reads an id field (JSON number or string) as a decimal string, "" when absent.
func numField(raw json.RawMessage, key string) string {
	v := objField(raw, key)
	if len(v) == 0 || string(v) == "null" {
		return ""
	}
	s := string(v)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func parseInt64(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	var n int64
	neg := false
	i := 0
	if s[0] == '-' {
		neg = true
		i = 1
	}
	if i >= len(s) {
		return 0, false
	}
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	if neg {
		n = -n
	}
	return n, true
}
