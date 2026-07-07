package github

// Fact records for the org / repo / environment / ruleset / app subjects. Slice
// and map fields are emitted non-nil because rules test them with `!= []`, so an
// omitted empty would change rule evaluation.

type OrgSecretSummary struct {
	Name              string `json:"name"`
	Visibility        string `json:"visibility"`
	SelectedRepoCount int    `json:"selected_repo_count"`
}

type AppPermSummary struct {
	AppSlug             string         `json:"app_slug"`
	Permissions         map[string]any `json:"permissions"`
	RepositorySelection *string        `json:"repository_selection"`
	HasAdminPerm        bool           `json:"has_admin_perm"`
}

type RunnerGroupSummary struct {
	ID                       any     `json:"id"`
	Name                     *string `json:"name"`
	Visibility               *string `json:"visibility"`
	AllowsPublicRepositories *bool   `json:"allows_public_repositories"`
	RestrictedToWorkflows    *bool   `json:"restricted_to_workflows"`
	SelectedWorkflows        []any   `json:"selected_workflows"`
	MemberRunnerCount        int     `json:"member_runner_count"`
	SelectedRepoCount        int     `json:"selected_repo_count"`
}

type ElevatedOutsideCollaborator struct {
	Repo     string `json:"repo"`
	Login    string `json:"login"`
	RoleName string `json:"role_name"`
}

type OrgActions struct {
	EnabledRepositories          any   `json:"enabled_repositories"`
	AllowedActions               any   `json:"allowed_actions"`
	DefaultWorkflowPermissions   any   `json:"default_workflow_permissions"`
	CanApprovePullRequestReviews any   `json:"can_approve_pull_request_reviews"`
	SelectedActionsPatternsCount int   `json:"selected_actions_patterns_count"`
	GithubOwnedAllowed           any   `json:"github_owned_allowed"`
	VerifiedAllowed              any   `json:"verified_allowed"`
	PatternsAllowed              []any `json:"patterns_allowed"`
}

type OrgFact struct {
	ID    string `json:"_id"`
	Org   string `json:"org"`
	Owner any    `json:"owner"`
	Type  any    `json:"type"`

	TwoFactorRequirementEnabled               any `json:"two_factor_requirement_enabled"`
	MembersCanCreateRepositories              any `json:"members_can_create_repositories"`
	MembersCanCreatePublicRepositories        any `json:"members_can_create_public_repositories"`
	MembersCanCreatePrivateRepositories       any `json:"members_can_create_private_repositories"`
	MembersCanCreateInternalRepositories      any `json:"members_can_create_internal_repositories"`
	MembersCanForkPrivateRepositories         any `json:"members_can_fork_private_repositories"`
	DefaultRepositoryPermission               any `json:"default_repository_permission"`
	WebCommitSignoffRequired                  any `json:"web_commit_signoff_required"`
	AdvancedSecurityEnabledForNewRepositories any `json:"advanced_security_enabled_for_new_repositories"`

	Actions OrgActions `json:"actions"`

	MembersCount                      int                           `json:"members_count"`
	OutsideCollaboratorsCount         int                           `json:"outside_collaborators_count"`
	OutsideCollaboratorsElevated      []ElevatedOutsideCollaborator `json:"outside_collaborators_elevated"`
	OutsideCollaboratorsElevatedCount int                           `json:"outside_collaborators_elevated_count"`
	TeamsCount                        int                           `json:"teams_count"`

	InstallationsCount int              `json:"installations_count"`
	AppsSummary        []AppPermSummary `json:"apps_summary"`
	AnyAppHasAdminPerm bool             `json:"any_app_has_admin_perm"`

	RunnerGroups              []RunnerGroupSummary `json:"runner_groups"`
	AnyRunnerGroupPublicRepos bool                 `json:"any_runner_group_public_repos"`
	OrgRunnersCount           int                  `json:"org_runners_count"`

	HookURLs         []any `json:"hook_urls"`
	HooksCount       int   `json:"hooks_count"`
	HooksActiveCount int   `json:"hooks_active_count"`

	SecurityManagers []any `json:"security_managers"`

	OrgActionsSecrets           []OrgSecretSummary `json:"org_actions_secrets"`
	OrgActionsSecretNames       []string           `json:"org_actions_secret_names"`
	OrgAppKeySecrets            []string           `json:"org_app_key_secrets"`
	OrgPatNamedSecrets          []string           `json:"org_pat_named_secrets"`
	OrgWebhookSecretNames       []string           `json:"org_webhook_secret_names"`
	OrgActionsSecretCount       int                `json:"org_actions_secret_count"`
	OrgSecretsWithAllVisibility []string           `json:"org_secrets_with_all_visibility"`
	AnyOrgSecretVisibilityAll   bool               `json:"any_org_secret_visibility_all"`
	OrgVariablesWithPatNaming   []string           `json:"org_variables_with_pat_naming"`

	Provenance []SourceProvenance `json:"_provenance"`
}

// RepoLegacyBPSummary is part of the repo fact schema even though no repo rule
// currently reads it.
type RepoLegacyBPSummary struct {
	RequiredReviews      any  `json:"required_reviews"`
	EnforceAdmins        any  `json:"enforce_admins"`
	RequiredStatusChecks bool `json:"required_status_checks"`
	RestrictionsPresent  bool `json:"restrictions_present"`
	LockBranch           any  `json:"lock_branch"`
}

type RepoFact struct {
	ID            string `json:"_id"`
	Repo          string `json:"repo"`
	Owner         any    `json:"owner"`
	Visibility    any    `json:"visibility"`
	Archived      any    `json:"archived"`
	DefaultBranch any    `json:"default_branch"`
	Fork          any    `json:"fork"`
	Private       any    `json:"private"`

	DefaultWorkflowPermissions   any `json:"default_workflow_permissions"`
	CanApprovePullRequestReviews any `json:"can_approve_pull_request_reviews"`
	ActionsEnabled               any `json:"actions_enabled"`
	AllowedActions               any `json:"allowed_actions"`
	ShaPinningRequired           any `json:"sha_pinning_required"`

	DefaultBranchProtectionPresent bool                 `json:"default_branch_protection_present"`
	DefaultBranchProtectionSummary *RepoLegacyBPSummary `json:"default_branch_protection_summary"`

	Provenance []SourceProvenance `json:"_provenance"`
}

type EnvReviewer struct {
	ID    any `json:"id"`
	Type  any `json:"type"`
	Login any `json:"login"`
}

type EnvBranchPolicy struct {
	Type                 any      `json:"type"`
	ProtectedBranches    any      `json:"protected_branches"`
	CustomBranchPolicies any      `json:"custom_branch_policies"`
	Patterns             []string `json:"patterns"`
}

type EnvironmentFact struct {
	ID   string `json:"_id"`
	Repo string `json:"repo"`
	Name string `json:"name"`

	WaitTimerMinutes  int           `json:"wait_timer_minutes"`
	ReviewersRequired []EnvReviewer `json:"reviewers_required"`
	ReviewersCount    int           `json:"reviewers_count"`
	PreventSelfReview any           `json:"prevent_self_review"`
	HasCustomRules    bool          `json:"has_custom_rules"`

	DeploymentBranchPolicy EnvBranchPolicy `json:"deployment_branch_policy"`
	CanAdminsBypass        any             `json:"can_admins_bypass"`
	ProtectionRulesRaw     []any           `json:"protection_rules_raw"`

	Provenance []SourceProvenance `json:"_provenance"`
}

type RulesetBypassActor struct {
	ActorID    any `json:"actor_id"`
	ActorType  any `json:"actor_type"`
	BypassMode any `json:"bypass_mode"`
}

type RulesetBypass struct {
	AnyBypassPresent      bool                 `json:"any_bypass_present"`
	BypassAlways          []RulesetBypassActor `json:"bypass_always"`
	BypassPullRequestOnly []RulesetBypassActor `json:"bypass_pull_request_only"`
}

// RulesetFact emits every key unconditionally (the effective-ruleset join reads
// them whether set or not); Repo is the sole repo-scope-only key, hence omitempty.
type RulesetFact struct {
	ID    string `json:"_id"`
	Scope any    `json:"scope"`
	Owner any    `json:"owner"`

	Repo any `json:"repo,omitempty"`

	RulesetID                        any              `json:"ruleset_id"`
	Name                             any              `json:"name"`
	Enforcement                      any              `json:"enforcement"`
	Target                           any              `json:"target"`
	CurrentUserCanBypass             any              `json:"current_user_can_bypass"`
	Conditions                       map[string]any   `json:"conditions"`
	RulesRaw                         []any            `json:"rules_raw"`
	RulesByType                      map[string][]any `json:"rules_by_type"`
	RuleTypes                        []string         `json:"rule_types"`
	Bypass                           RulesetBypass    `json:"bypass"`
	RequiresPullRequest              bool             `json:"requires_pull_request"`
	RequiredApprovingReviewCount     any              `json:"required_approving_review_count"`
	DismissStaleReviewsOnPush        any              `json:"dismiss_stale_reviews_on_push"`
	RequireCodeOwnerReview           any              `json:"require_code_owner_review"`
	RequireLastPushApproval          any              `json:"require_last_push_approval"`
	RequiredStatusChecks             any              `json:"required_status_checks"`
	StrictRequiredStatusChecksPolicy any              `json:"strict_required_status_checks_policy"`

	Provenance []SourceProvenance `json:"_provenance"`
}

// RulesetSentinel stands in for a scope with no rulesets or an unavailable
// endpoint; the effective-ruleset join skips it because ruleset_id is absent.
type RulesetSentinel struct {
	ID          string `json:"_id"`
	Scope       any    `json:"scope"`
	Owner       any    `json:"owner"`
	Repo        any    `json:"repo,omitempty"`
	Unavailable bool   `json:"_unavailable,omitempty"`
	Empty       bool   `json:"_empty,omitempty"`

	Provenance []SourceProvenance `json:"_provenance"`
}

type AppFact struct {
	ID             string `json:"_id"`
	AppSlug        string `json:"app_slug"`
	AppID          any    `json:"app_id"`
	InstallationID any    `json:"installation_id"`
	Owner          any    `json:"owner"`
	OwnerType      any    `json:"owner_type"`

	Permissions         map[string]any `json:"permissions"`
	Events              []any          `json:"events"`
	RepositorySelection any            `json:"repository_selection"`
	SingleFilePaths     any            `json:"single_file_paths"`
	SingleFileName      any            `json:"single_file_name"`
	HTMLURL             any            `json:"html_url"`
	Description         any            `json:"description"`
	SuspendedAt         any            `json:"suspended_at"`
	SuspendedBy         any            `json:"suspended_by"`

	WritePermissions []string `json:"write_permissions"`
	AdminPermissions []string `json:"admin_permissions"`
	BroadAdminWrites []string `json:"broad_admin_writes"`
	PermissionCount  int      `json:"permission_count"`
	WriteCount       int      `json:"write_count"`

	Provenance []SourceProvenance `json:"_provenance"`
}
