package github

import (
	"encoding/json"
	"fmt"
	"math"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func normalizeEntities(runDir string) error {
	prior := engine.PriorPhase{RunDir: runDir}
	cp := engine.CurrentPhase{RunDir: runDir}

	st, err := engine.LoadState(runDir)
	if err != nil {
		return fmt.Errorf("load run state: %w", err)
	}
	org := st.Org

	if err := normalizeOrg(prior, cp, org); err != nil {
		return fmt.Errorf("normalize org: %w", err)
	}
	if err := normalizeRepos(prior, cp, org); err != nil {
		return fmt.Errorf("normalize repos: %w", err)
	}
	if err := normalizeEnvironments(prior, cp, org); err != nil {
		return fmt.Errorf("normalize environments: %w", err)
	}
	if err := normalizeRulesets(prior, cp, org); err != nil {
		return fmt.Errorf("normalize rulesets: %w", err)
	}
	if err := normalizeApps(prior, cp, org); err != nil {
		return fmt.Errorf("normalize apps: %w", err)
	}
	return nil
}

func normOrgPath(org string) string   { return path.Join("10-normalize", "org", org+".json") }
func normRepoPath(repo string) string { return path.Join("10-normalize", "repos", repo+".json") }

func normEnvPath(repo, env string) string {
	return path.Join("10-normalize", "environments", repo+"__"+env+".json")
}

func normRulesetPath(scopeKey string, rulesetID int64) string {
	return path.Join("10-normalize", "rulesets", fmt.Sprintf("%s__%d.json", scopeKey, rulesetID))
}

func normRulesetSentinelPath(scopeKey, suffix string) string {
	return path.Join("10-normalize", "rulesets", scopeKey+"__"+suffix+".json")
}

func normAppPath(slug string) string { return path.Join("10-normalize", "apps", slug+".json") }

// "write" on one of these (or any "admin") makes an installation admin-class for
// the org aggregate.
var orgAdminClassAppPerms = map[string]bool{
	"administration": true, "organization_administration": true, "members": true,
	"secrets": true, "organization_secrets": true,
	"self_hosted_runners": true, "organization_self_hosted_runners": true,
}

func normalizeOrg(prior engine.PriorPhase, cp engine.CurrentPhase, org string) error {
	if org == "" {
		return nil
	}
	orgPayload := entLoadData(prior, engine.CollectOrg(org))
	if orgPayload == nil {
		return nil
	}
	membersPayload := entLoadData(prior, engine.CollectMembers(org))
	appsInst := entLoadData(prior, engine.CollectAppsInstallations(org))
	runnersPayload := entLoadData(prior, engine.CollectRunners(org))
	secretsPayload := entLoadData(prior, engine.CollectSecrets(org))
	variablesPayload := entLoadData(prior, engine.CollectVariables(org))

	orgInfo := entObj(orgPayload, "org")
	actionsPerms := entObj(orgPayload, "actions_permissions")
	workflowPerms := entObj(orgPayload, "actions_workflow_permissions")
	selectedActions := entObj(orgPayload, "selected_actions")
	hooks := entListOf(orgPayload, "hooks")
	securityManagers := entListOrEmpty(orgPayload["security_managers"])

	elevated := orgElevatedOutside(membersPayload)
	apps := orgAppsSummary(entListOf(appsInst, "installations"))
	groups := orgRunnerGroups(entListOf(runnersPayload, "runner_groups"))
	secrets := entListOf(secretsPayload, "actions_secrets")
	variables := entListOf(variablesPayload, "variables")

	hookURLs := make([]any, 0, len(hooks))
	hooksActive := 0
	for _, h := range hooks {
		ho := entMap(h)
		hookURLs = append(hookURLs, entGetIn(ho, "config", "url"))
		if entTruthy(ho["active"]) {
			hooksActive++
		}
	}

	rec := OrgFact{
		ID:    org,
		Org:   org,
		Owner: orgInfo["login"],
		Type:  orgInfo["type"],

		TwoFactorRequirementEnabled:               orgInfo["two_factor_requirement_enabled"],
		MembersCanCreateRepositories:              orgInfo["members_can_create_repositories"],
		MembersCanCreatePublicRepositories:        orgInfo["members_can_create_public_repositories"],
		MembersCanCreatePrivateRepositories:       orgInfo["members_can_create_private_repositories"],
		MembersCanCreateInternalRepositories:      orgInfo["members_can_create_internal_repositories"],
		MembersCanForkPrivateRepositories:         orgInfo["members_can_fork_private_repositories"],
		DefaultRepositoryPermission:               orgInfo["default_repository_permission"],
		WebCommitSignoffRequired:                  orgInfo["web_commit_signoff_required"],
		AdvancedSecurityEnabledForNewRepositories: orgInfo["advanced_security_enabled_for_new_repositories"],

		Actions: OrgActions{
			EnabledRepositories:          actionsPerms["enabled_repositories"],
			AllowedActions:               actionsPerms["allowed_actions"],
			DefaultWorkflowPermissions:   entCoalesce(workflowPerms["default_workflow_permissions"], actionsPerms["default_workflow_permissions"]),
			CanApprovePullRequestReviews: entCoalesce(workflowPerms["can_approve_pull_request_reviews"], actionsPerms["can_approve_pull_request_reviews"]),
			SelectedActionsPatternsCount: len(entListOf(selectedActions, "patterns_allowed")),
			GithubOwnedAllowed:           selectedActions["github_owned_allowed"],
			VerifiedAllowed:              selectedActions["verified_allowed"],
			PatternsAllowed:              entListOrEmpty(selectedActions["patterns_allowed"]),
		},

		MembersCount:                      len(entListOf(membersPayload, "members")),
		OutsideCollaboratorsCount:         len(entListOf(membersPayload, "outside_collaborators")),
		OutsideCollaboratorsElevated:      elevated,
		OutsideCollaboratorsElevatedCount: len(elevated),
		TeamsCount:                        len(entListOf(membersPayload, "teams")),

		InstallationsCount: len(entListOf(appsInst, "installations")),
		AppsSummary:        apps,
		AnyAppHasAdminPerm: anyAppAdmin(apps),

		RunnerGroups:              groups,
		AnyRunnerGroupPublicRepos: anyRunnerGroupPublic(groups),
		OrgRunnersCount:           len(entListOf(runnersPayload, "runners")),

		HookURLs:         hookURLs,
		HooksCount:       len(hooks),
		HooksActiveCount: hooksActive,

		SecurityManagers: securityManagers,

		OrgActionsSecrets:           orgSecretSummaries(secrets),
		OrgActionsSecretNames:       secretNames(secrets),
		OrgAppKeySecrets:            secretNamesMatching(secrets, isAppKeySecret),
		OrgPatNamedSecrets:          secretNamesMatching(secrets, isPatSecret),
		OrgWebhookSecretNames:       secretNamesMatching(secrets, isWebhookSecret),
		OrgActionsSecretCount:       len(secrets),
		OrgSecretsWithAllVisibility: secretNamesWithVisibilityAll(secrets),
		AnyOrgSecretVisibilityAll:   anySecretVisibilityAll(secrets),
		OrgVariablesWithPatNaming:   variableNamesMatching(variables, isPatLikeVariable),

		Provenance: []SourceProvenance{
			{File: engine.CollectOrg(org)},
			{File: engine.CollectMembers(org)},
			{File: engine.CollectAppsInstallations(org)},
			{File: engine.CollectRunners(org)},
		},
	}
	return cp.Write(normOrgPath(org), rec)
}

func orgElevatedOutside(members map[string]any) []ElevatedOutsideCollaborator {
	out := []ElevatedOutsideCollaborator{}
	perRepo := entObj(members, "per_repo_collaborators")

	outsideLogins := map[string]bool{}
	for _, c := range entListOf(members, "outside_collaborators") {
		if login := entStr(entMap(c)["login"]); login != "" {
			outsideLogins[login] = true
		}
	}

	repos := make([]string, 0, len(perRepo))
	for r := range perRepo {
		repos = append(repos, r)
	}
	sort.Strings(repos)

	elevatedRoles := map[string]bool{"admin": true, "maintain": true, "write": true, "push": true}
	for _, repo := range repos {
		for _, c := range entList(perRepo[repo]) {
			cm := entMap(c)
			login := entStr(cm["login"])
			role := entStr(cm["role_name"])
			if outsideLogins[login] && elevatedRoles[role] {
				out = append(out, ElevatedOutsideCollaborator{Repo: repo, Login: login, RoleName: role})
			}
		}
	}
	return out
}

func orgAppsSummary(installations []any) []AppPermSummary {
	out := make([]AppPermSummary, 0, len(installations))
	for _, inst := range installations {
		im := entMap(inst)
		perms := entObj(im, "permissions")
		out = append(out, AppPermSummary{
			AppSlug:             entStr(im["app_slug"]),
			Permissions:         perms,
			RepositorySelection: entStrPtr(im["repository_selection"]),
			HasAdminPerm:        appHasAdminPerm(perms),
		})
	}
	return out
}

func appHasAdminPerm(perms map[string]any) bool {
	for _, v := range perms {
		if entStr(v) == "admin" {
			return true
		}
	}
	for k, v := range perms {
		if orgAdminClassAppPerms[k] {
			if s := entStr(v); s == "write" || s == "admin" {
				return true
			}
		}
	}
	return false
}

func anyAppAdmin(apps []AppPermSummary) bool {
	return slices.ContainsFunc(apps, func(a AppPermSummary) bool { return a.HasAdminPerm })
}

func orgRunnerGroups(groups []any) []RunnerGroupSummary {
	out := make([]RunnerGroupSummary, 0, len(groups))
	for _, g := range groups {
		gm := entMap(g)
		out = append(out, RunnerGroupSummary{
			ID:                       gm["id"],
			Name:                     entStrPtr(gm["name"]),
			Visibility:               entStrPtr(gm["visibility"]),
			AllowsPublicRepositories: entBoolPtr(gm["allows_public_repositories"]),
			RestrictedToWorkflows:    entBoolPtr(gm["restricted_to_workflows"]),
			SelectedWorkflows:        entListOrEmpty(gm["selected_workflows"]),
			MemberRunnerCount:        len(entList(gm["member_runners"])),
			SelectedRepoCount:        len(entList(gm["selected_repositories"])),
		})
	}
	return out
}

func anyRunnerGroupPublic(groups []RunnerGroupSummary) bool {
	return slices.ContainsFunc(groups, func(g RunnerGroupSummary) bool {
		return g.AllowsPublicRepositories != nil && *g.AllowsPublicRepositories
	})
}

func orgSecretSummaries(secrets []any) []OrgSecretSummary {
	out := make([]OrgSecretSummary, 0, len(secrets))
	for _, s := range secrets {
		sm := entMap(s)
		out = append(out, OrgSecretSummary{
			Name:              entStr(sm["name"]),
			Visibility:        entStr(sm["visibility"]),
			SelectedRepoCount: len(entList(sm["selected_repositories"])),
		})
	}
	return out
}

func secretNames(secrets []any) []string {
	out := []string{}
	for _, s := range secrets {
		if name := entStr(entMap(s)["name"]); name != "" {
			out = append(out, name)
		}
	}
	return out
}

func secretNamesMatching(secrets []any, pred func(upper string) bool) []string {
	out := []string{}
	for _, s := range secrets {
		name := entStr(entMap(s)["name"])
		if name == "" {
			continue
		}
		if pred(strings.ToUpper(name)) {
			out = append(out, name)
		}
	}
	return out
}

func variableNamesMatching(vars []any, pred func(upper string) bool) []string {
	out := []string{}
	for _, v := range vars {
		name := entStr(entMap(v)["name"])
		if name == "" {
			continue
		}
		if pred(strings.ToUpper(name)) {
			out = append(out, name)
		}
	}
	return out
}

func secretNamesWithVisibilityAll(secrets []any) []string {
	out := []string{}
	for _, s := range secrets {
		sm := entMap(s)
		if entStr(sm["visibility"]) == "all" {
			out = append(out, entStr(sm["name"]))
		}
	}
	return out
}

func anySecretVisibilityAll(secrets []any) bool {
	for _, s := range secrets {
		if entStr(entMap(s)["visibility"]) == "all" {
			return true
		}
	}
	return false
}

func isAppKeySecret(u string) bool {
	if strings.Contains(u, "APP") &&
		(strings.Contains(u, "PRIVATE_KEY") || strings.Contains(u, "PEM") || strings.Contains(u, "PK")) {
		return true
	}
	return strings.Contains(u, "APP_KEY") || strings.Contains(u, "GH_APP_KEY")
}

func isPatSecret(u string) bool {
	for _, h := range []string{"PAT", "GH_TOKEN_PAT", "PERSONAL_ACCESS", "GH_PAT", "TOKEN_PAT"} {
		if strings.Contains(u, h) {
			return true
		}
	}
	return false
}

func isWebhookSecret(u string) bool { return strings.Contains(u, "WEBHOOK_SECRET") }

func isPatLikeVariable(u string) bool {
	for _, h := range []string{"PAT", "TOKEN", "GH_TOKEN", "API_KEY", "API_TOKEN", "SECRET"} {
		if strings.Contains(u, h) {
			return true
		}
	}
	return false
}

func normalizeRepos(prior engine.PriorPhase, cp engine.CurrentPhase, org string) error {
	files, err := prior.IterJSON(path.Join("00-collect", "repos"))
	if err != nil {
		return err
	}
	orgActions := entObj(entLoadData(prior, engine.CollectOrg(org)), "actions_permissions")

	for _, f := range files {
		repoName := strings.TrimSuffix(path.Base(f.Rel), ".json")
		repoData := entDataOf(f.Data)
		settings := entLoadData(prior, engine.CollectActionsSettings(repoName))

		repoInfo := entObj(repoData, "repo")
		workflowPerms := entObj(settings, "workflow_permissions")
		actionsPerms := entObj(settings, "permissions")

		var legacyBP *RepoLegacyBPSummary
		bpPresent := repoData["default_branch_protection"] != nil
		if bp := entObj(repoData, "default_branch_protection"); len(bp) > 0 {
			legacyBP = summarizeLegacyBP(bp)
		}

		rec := RepoFact{
			ID:            repoName,
			Repo:          repoName,
			Owner:         entObj(repoInfo, "owner")["login"],
			Visibility:    repoInfo["visibility"],
			Archived:      entOrDefault(repoInfo["archived"], false),
			DefaultBranch: repoInfo["default_branch"],
			Fork:          entOrDefault(repoInfo["fork"], false),
			Private:       repoInfo["private"],

			DefaultWorkflowPermissions:   entCoalesce(workflowPerms["default_workflow_permissions"], orgActions["default_workflow_permissions"]),
			CanApprovePullRequestReviews: entCoalesce(workflowPerms["can_approve_pull_request_reviews"], orgActions["can_approve_pull_request_reviews"]),
			ActionsEnabled:               actionsPerms["enabled"],
			AllowedActions:               entCoalesce(actionsPerms["allowed_actions"], orgActions["allowed_actions"]),
			ShaPinningRequired:           actionsPerms["sha_pinning_required"],

			DefaultBranchProtectionPresent: bpPresent,
			DefaultBranchProtectionSummary: legacyBP,

			Provenance: []SourceProvenance{
				{File: engine.CollectRepo(repoName)},
				{File: engine.CollectActionsSettings(repoName)},
				{File: engine.CollectOrg(org)},
			},
		}
		if err := cp.Write(normRepoPath(repoName), rec); err != nil {
			return err
		}
	}
	return nil
}

func summarizeLegacyBP(bp map[string]any) *RepoLegacyBPSummary {
	var lock any
	if lb, ok := bp["lock_branch"].(map[string]any); ok {
		lock = lb["enabled"]
	}
	return &RepoLegacyBPSummary{
		RequiredReviews:      entObj(bp, "required_pull_request_reviews")["required_approving_review_count"],
		EnforceAdmins:        entObj(bp, "enforce_admins")["enabled"],
		RequiredStatusChecks: entTruthy(bp["required_status_checks"]),
		RestrictionsPresent:  entTruthy(bp["restrictions"]),
		LockBranch:           lock,
	}
}

func normalizeEnvironments(prior engine.PriorPhase, cp engine.CurrentPhase, org string) error {
	files, err := prior.IterJSON(path.Join("00-collect", "environments"))
	if err != nil {
		return err
	}
	for _, f := range files {
		rel := filepath.ToSlash(f.Rel)
		repo := path.Dir(rel)
		if repo == "." || repo == "" {
			continue
		}
		data := entDataOf(f.Data)
		name := entStr(data["name"])
		if name == "" {
			name = strings.TrimSuffix(path.Base(rel), ".json")
		}
		base := entObj(data, "base")

		waitTimer, reviewers, preventSelf, custom := classifyProtectionRules(base)
		bp := entEnvBranchPolicy(base, entObj(data, "branch_policies"))

		rec := EnvironmentFact{
			ID:                     repo + "__" + name,
			Repo:                   repo,
			Name:                   name,
			WaitTimerMinutes:       waitTimer,
			ReviewersRequired:      reviewers,
			ReviewersCount:         len(reviewers),
			PreventSelfReview:      preventSelf,
			HasCustomRules:         custom,
			DeploymentBranchPolicy: bp,
			CanAdminsBypass:        base["can_admins_bypass"],
			ProtectionRulesRaw:     entListOrEmpty(base["protection_rules"]),
			Provenance: []SourceProvenance{
				{File: engine.CollectEnvironment(repo, name)},
			},
		}
		if err := cp.Write(normEnvPath(repo, name), rec); err != nil {
			return err
		}
	}
	return nil
}

func classifyProtectionRules(base map[string]any) (waitTimer int, reviewers []EnvReviewer, preventSelf any, custom bool) {
	reviewers = []EnvReviewer{}
	if base == nil {
		return 0, reviewers, nil, false
	}
	for _, r := range entList(base["protection_rules"]) {
		rm := entMap(r)
		switch entStr(rm["type"]) {
		case "wait_timer":
			waitTimer = entInt(rm["wait_timer"])
		case "required_reviewers":
			for _, rv := range entList(rm["reviewers"]) {
				reviewer := entObj(entMap(rv), "reviewer")
				login := reviewer["login"]
				if login == nil {
					login = reviewer["slug"]
				}
				reviewers = append(reviewers, EnvReviewer{
					ID:    reviewer["id"],
					Type:  reviewer["type"],
					Login: login,
				})
			}
			preventSelf = rm["prevent_self_review"]
		case "branch_policy":
			// No-op: deployment_branch_policy on base is the canonical signal.
		default:
			custom = true
		}
	}
	return waitTimer, reviewers, preventSelf, custom
}

func entEnvBranchPolicy(base, branchPolicies map[string]any) EnvBranchPolicy {
	bp := EnvBranchPolicy{Patterns: []string{}}
	if base == nil {
		bp.Type = nil
		return bp
	}
	dbp := entObj(base, "deployment_branch_policy")
	for _, p := range entListOf(branchPolicies, "branch_policies") {
		pm := entMap(p)
		name := pm["name"]
		if name == nil {
			name = pm["pattern"]
		}
		if s := entStr(name); s != "" {
			bp.Patterns = append(bp.Patterns, s)
		}
	}
	switch {
	case entTruthy(dbp["custom_branch_policies"]):
		bp.Type = "selected"
	case entTruthy(dbp["protected_branches"]):
		bp.Type = "protected_branches"
	default:
		bp.Type = nil
	}
	bp.ProtectedBranches = entOrDefault(dbp["protected_branches"], false)
	bp.CustomBranchPolicies = entOrDefault(dbp["custom_branch_policies"], false)
	return bp
}

func normalizeRulesets(prior engine.PriorPhase, cp engine.CurrentPhase, org string) error {
	files, err := prior.IterJSON(path.Join("00-collect", "rulesets"))
	if err != nil {
		return err
	}
	for _, f := range files {
		data := entDataOf(f.Data)
		scope := entStr(data["scope"])
		owner := data["owner"]
		scopeKey := entStr(data["repo"])
		if scope == "org" {
			scopeKey = entStr(owner)
		}

		if entTruthy(data["_unavailable"]) {
			rec := RulesetSentinel{
				ID:          scopeKey + "__unavailable",
				Scope:       "repo",
				Owner:       nil,
				Repo:        scopeKey,
				Unavailable: true,
				Provenance:  []SourceProvenance{{File: engine.CollectRulesetsRepo(scopeKey)}},
			}
			if err := cp.Write(normRulesetSentinelPath(scopeKey, "unavailable"), rec); err != nil {
				return err
			}
			continue
		}

		sourceFile := engine.CollectRulesetsRepo(scopeKey)
		if scope == "org" {
			sourceFile = engine.CollectRulesetsOrg(scopeKey)
		}

		rulesets := entList(data["rulesets"])
		if len(rulesets) == 0 {
			rec := RulesetSentinel{
				ID:         scopeKey + "__none",
				Scope:      scope,
				Owner:      owner,
				Empty:      true,
				Provenance: []SourceProvenance{{File: sourceFile}},
			}
			if scope == "repo" {
				rec.Repo = scopeKey
			}
			if err := cp.Write(normRulesetSentinelPath(scopeKey, "none"), rec); err != nil {
				return err
			}
			continue
		}

		for _, rs := range rulesets {
			rsm := entMap(rs)
			rec := normalizeOneRuleset(scopeKey, scope, owner, rsm, sourceFile)
			if err := cp.Write(normRulesetPath(scopeKey, entInt64(rsm["id"])), rec); err != nil {
				return err
			}
		}
	}
	return nil
}

func normalizeOneRuleset(scopeKey, scope string, owner any, rs map[string]any, sourceFile string) RulesetFact {
	byType := flattenRules(entList(rs["rules"]))
	bypass := classifyBypass(entList(rs["bypass_actors"]))

	ruleTypes := make([]string, 0, len(byType))
	for k := range byType {
		ruleTypes = append(ruleTypes, k)
	}
	sort.Strings(ruleTypes)

	prParams := firstParams(byType, "pull_request")
	statusParams := firstParams(byType, "required_status_checks")
	_, requiresPR := byType["pull_request"]

	rulesRaw := entList(rs["rules"])
	if rulesRaw == nil {
		rulesRaw = []any{}
	}

	rec := RulesetFact{
		ID:                               fmt.Sprintf("%s__%s", scopeKey, entIDLabel(rs["id"])),
		Scope:                            scope,
		Owner:                            owner,
		RulesetID:                        rs["id"],
		Name:                             rs["name"],
		Enforcement:                      rs["enforcement"],
		Target:                           rs["target"],
		CurrentUserCanBypass:             rs["current_user_can_bypass"],
		Conditions:                       entObj(rs, "conditions"),
		RulesRaw:                         rulesRaw,
		RulesByType:                      byType,
		RuleTypes:                        ruleTypes,
		Bypass:                           bypass,
		RequiresPullRequest:              requiresPR,
		RequiredApprovingReviewCount:     prParams["required_approving_review_count"],
		DismissStaleReviewsOnPush:        prParams["dismiss_stale_reviews_on_push"],
		RequireCodeOwnerReview:           prParams["require_code_owner_review"],
		RequireLastPushApproval:          prParams["require_last_push_approval"],
		RequiredStatusChecks:             statusParams["required_status_checks"],
		StrictRequiredStatusChecksPolicy: statusParams["strict_required_status_checks_policy"],
		Provenance:                       []SourceProvenance{{File: sourceFile}},
	}
	if scope == "repo" {
		rec.Repo = scopeKey
	}
	return rec
}

func flattenRules(rules []any) map[string][]any {
	out := map[string][]any{}
	for _, r := range rules {
		rm := entMap(r)
		rtype := entStr(rm["type"])
		if rtype == "" {
			continue
		}
		out[rtype] = append(out[rtype], entOrDefault(rm["parameters"], map[string]any{}))
	}
	return out
}

func classifyBypass(actors []any) RulesetBypass {
	always := []RulesetBypassActor{}
	prOnly := []RulesetBypassActor{}
	for _, a := range actors {
		am := entMap(a)
		ent := RulesetBypassActor{
			ActorID:    am["actor_id"],
			ActorType:  am["actor_type"],
			BypassMode: am["bypass_mode"],
		}
		if entStr(am["bypass_mode"]) == "pull_request" {
			prOnly = append(prOnly, ent)
		} else {
			always = append(always, ent)
		}
	}
	return RulesetBypass{
		AnyBypassPresent:      len(actors) > 0,
		BypassAlways:          always,
		BypassPullRequestOnly: prOnly,
	}
}

func firstParams(byType map[string][]any, rtype string) map[string]any {
	if lst := byType[rtype]; len(lst) > 0 {
		return entMap(lst[0])
	}
	return map[string]any{}
}

// Deliberately broader than orgAdminClassAppPerms: this is the per-app classifier.
var appBroadAdminPerms = map[string]bool{
	"administration": true, "organization_administration": true, "members": true,
	"secrets": true, "actions": true, "workflows": true, "deployments": true,
	"repository_hooks": true, "organization_hooks": true, "organization_secrets": true,
	"organization_user_blocking": true, "organization_self_hosted_runners": true,
	"self_hosted_runners": true,
}

func normalizeApps(prior engine.PriorPhase, cp engine.CurrentPhase, org string) error {
	files, err := prior.IterJSON(path.Join("00-collect", "apps"))
	if err != nil {
		return err
	}
	for _, f := range files {
		if path.Base(f.Rel) == "installations.json" {
			continue
		}
		payload := entDataOf(f.Data)
		if payload == nil {
			continue
		}
		slug := entStr(payload["app_slug"])
		if slug == "" {
			slug = strings.TrimSuffix(path.Base(f.Rel), ".json")
		}
		inst := entObj(payload, "installation")
		app := entObj(payload, "app")
		perms := entObj(inst, "permissions")

		write, admin, broad := classifyAppPerms(perms)

		rec := AppFact{
			ID:             slug,
			AppSlug:        slug,
			AppID:          entCoalesce(inst["app_id"], app["id"]),
			InstallationID: inst["id"],
			Owner:          payload["owner"],
			OwnerType:      entObj(inst, "account")["type"],

			Permissions:         perms,
			Events:              entListOrEmpty(inst["events"]),
			RepositorySelection: inst["repository_selection"],
			SingleFilePaths:     inst["single_file_paths"],
			SingleFileName:      inst["single_file_name"],
			HTMLURL:             app["html_url"],
			Description:         app["description"],
			SuspendedAt:         inst["suspended_at"],
			SuspendedBy:         inst["suspended_by"],

			WritePermissions: write,
			AdminPermissions: admin,
			BroadAdminWrites: broad,
			PermissionCount:  len(perms),
			WriteCount:       len(write),

			Provenance: []SourceProvenance{
				{File: engine.CollectApp(entStr(payload["owner"]), slug)},
			},
		}
		if err := cp.Write(normAppPath(slug), rec); err != nil {
			return err
		}
	}
	return nil
}

func classifyAppPerms(perms map[string]any) (write, admin, broad []string) {
	write, admin, broad = []string{}, []string{}, []string{}
	for k, v := range perms {
		s := entStr(v)
		if s == "write" || s == "admin" {
			write = append(write, k)
			if appBroadAdminPerms[k] {
				broad = append(broad, k)
			}
		}
		if s == "admin" {
			admin = append(admin, k)
		}
	}
	sort.Strings(write)
	sort.Strings(admin)
	sort.Strings(broad)
	return write, admin, broad
}

// entLoadData returns nil for a missing file or null data so the caller can skip
// the surface.
func entLoadData(prior engine.PriorPhase, rel string) map[string]any {
	var env map[string]any
	if err := engine.ReadJSON(prior.Abs(rel), &env); err != nil {
		return nil
	}
	return entMap(env["data"])
}

func entDataOf(b []byte) map[string]any {
	var env map[string]any
	if err := json.Unmarshal(b, &env); err != nil {
		return nil
	}
	return entMap(env["data"])
}

func entMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func entList(v any) []any {
	l, _ := v.([]any)
	return l
}

// entListOrEmpty never returns nil so a schema list field serializes as [] rather
// than null when the source key is absent.
func entListOrEmpty(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return []any{}
}

// entObj never returns nil so chained indexing is safe.
func entObj(m map[string]any, key string) map[string]any {
	if o := entMap(m[key]); o != nil {
		return o
	}
	return map[string]any{}
}

func entListOf(m map[string]any, key string) []any { return entList(m[key]) }

func entGetIn(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		cm := entMap(cur)
		if cm == nil {
			return nil
		}
		cur = cm[k]
	}
	return cur
}

func entStr(v any) string {
	s, _ := v.(string)
	return s
}

// entStrPtr yields nil for a non-string so the field serializes as JSON null.
func entStrPtr(v any) *string {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	return &s
}

func entBoolPtr(v any) *bool {
	b, ok := v.(bool)
	if !ok {
		return nil
	}
	return &b
}

// entTruthy mirrors Python truthiness over the JSON value set: numbers != 0,
// strings/lists/maps non-empty, nil false.
func entTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	default:
		return true
	}
}

func entInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return int(n)
		}
	}
	return 0
}

func entInt64(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int:
		return int64(x)
	case int64:
		return x
	case string:
		if n, err := strconv.ParseInt(x, 10, 64); err == nil {
			return n
		}
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n
		}
	}
	return 0
}

// entCoalesce falls back on falsy (Python `a or b`), unlike entOrDefault which
// falls back only on nil.
func entCoalesce(a, b any) any {
	if entTruthy(a) {
		return a
	}
	return b
}

func entOrDefault(v, def any) any {
	if v == nil {
		return def
	}
	return v
}

// entIDLabel renders an integral JSON number without a decimal point and nil as
// "None" to match the Python f-string on a missing id.
func entIDLabel(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case float64:
		if x == math.Trunc(x) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case string:
		return x
	default:
		return fmt.Sprintf("%v", x)
	}
}
