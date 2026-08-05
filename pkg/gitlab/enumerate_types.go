package gitlab

import "github.com/praetorian-inc/trajan/pkg/platforms"

type TokenEnumerateResult struct {
	User             *User                `json:"user,omitempty"`
	Token            *PersonalAccessToken `json:"token,omitempty"`
	TokenType        string               `json:"token_type"`
	IsAdmin          bool                 `json:"is_admin"`
	IsBot            bool                 `json:"is_bot"`
	CanCreateGroup   bool                 `json:"can_create_group"`
	CanCreateProject bool                 `json:"can_create_project"`
	Groups           []GroupInfo          `json:"groups,omitempty"`
	RateLimit        *RateLimitInfo       `json:"rate_limit,omitempty"`
	Errors           []string             `json:"errors,omitempty"`
}

type GroupInfo struct {
	Name     string `json:"name"`
	FullPath string `json:"full_path"`
	ID       int    `json:"id"`
}

type RateLimitInfo struct {
	Limit     int `json:"limit"`
	Remaining int `json:"remaining"`
}

type ProjectWithPermissions struct {
	platforms.Repository
	AccessLevel  int    `json:"access_level"` // 10-50
	Visibility   string `json:"visibility"`   // public, internal, private
	LastActivity string `json:"last_activity,omitempty"`
}

type ProjectsEnumerateResult struct {
	Projects []ProjectWithPermissions `json:"projects"`
	Summary  ProjectsSummary          `json:"summary"`
	Errors   []string                 `json:"errors,omitempty"`
}

type ProjectsSummary struct {
	Total       int `json:"total"`
	Private     int `json:"private"`
	Internal    int `json:"internal"`
	Public      int `json:"public"`
	Archived    int `json:"archived"`
	WriteAccess int `json:"write_access"`
	ReadAccess  int `json:"read_access"`
}

type GroupWithAccess struct {
	Group
	AccessLevel int    `json:"access_level"`
	Shared      bool   `json:"shared"`               // discovered via sharing
	SharedVia   string `json:"shared_via,omitempty"` // parent group path
}

type GroupsEnumerateResult struct {
	Groups []GroupWithAccess `json:"groups"`
	Errors []string          `json:"errors,omitempty"`
}

type SecretsEnumerateResult struct {
	ProjectVariables  map[string][]Variable `json:"project_variables,omitempty"`
	GroupVariables    map[string][]Variable `json:"group_variables,omitempty"`
	InstanceVariables []Variable            `json:"instance_variables,omitempty"`
	PermissionErrors  []string              `json:"permission_errors,omitempty"`
	Errors            []string              `json:"errors,omitempty"`
}

type BranchProtection struct {
	Name                      string        `json:"name"`
	AllowForcePush            bool          `json:"allow_force_push"`
	CodeOwnerApprovalRequired bool          `json:"code_owner_approval_required"`
	MergeAccessLevels         []AccessLevel `json:"merge_access_levels"`
	PushAccessLevels          []AccessLevel `json:"push_access_levels"`
	UnprotectAccessLevels     []AccessLevel `json:"unprotect_access_levels"`
}

type AccessLevel struct {
	AccessLevel            int    `json:"access_level"`
	AccessLevelDescription string `json:"access_level_description"`
	UserID                 *int   `json:"user_id,omitempty"`
	GroupID                *int   `json:"group_id,omitempty"`
}

type BranchProtectionsEnumerateResult struct {
	Project       string             `json:"project"`
	ProjectID     int                `json:"project_id"`
	DefaultBranch string             `json:"default_branch"`
	Protections   []BranchProtection `json:"protections"`
	Errors        []string           `json:"errors,omitempty"`
}

type RunnerInfo struct {
	ID           int      `json:"id"`
	Description  string   `json:"description"`
	RunnerType   string   `json:"runner_type"` // instance_type, group_type, project_type
	Tags         []string `json:"tag_list"`
	Online       bool     `json:"online"`
	Status       string   `json:"status"`
	IPAddress    string   `json:"ip_address,omitempty"`
	Active       bool     `json:"active"`
	Paused       bool     `json:"paused"`
	IsShared     bool     `json:"is_shared"`
	ContactedAt  string   `json:"contacted_at,omitempty"`
	Version      string   `json:"version,omitempty"`
	Platform     string   `json:"platform,omitempty"`
	Architecture string   `json:"architecture,omitempty"`
	Executor     string   `json:"executor_type,omitempty"` // shell, docker, kubernetes, etc.
	Source       string   `json:"source,omitempty"`        // "api" or "logs" - indicates discovery method
	LastSeenAt   string   `json:"last_seen_at,omitempty"`  // For historical runners - last pipeline execution
}

type WorkflowTagAnalysis struct {
	RequiredTags     []string `json:"required_tags"`
	AvailableTags    []string `json:"available_tags"`
	MissingTags      []string `json:"missing_tags"`
	ProjectsAnalyzed int      `json:"projects_analyzed"`
}

type RunnerSummary struct {
	Total    int `json:"total"`
	Online   int `json:"online"`
	Offline  int `json:"offline"`
	Instance int `json:"instance_runners"`
	Group    int `json:"group_runners"`
	Project  int `json:"project_runners"`
}

type RunnersEnumerateResult struct {
	ProjectRunners    []RunnerInfo        `json:"project_runners,omitempty"`
	GroupRunners      []RunnerInfo        `json:"group_runners,omitempty"`
	InstanceRunners   []RunnerInfo        `json:"instance_runners,omitempty"`
	HistoricalRunners []RunnerInfo        `json:"historical_runners,omitempty"` // Runners discovered from pipeline logs
	WorkflowTags      WorkflowTagAnalysis `json:"workflow_tags,omitempty"`
	Summary           RunnerSummary       `json:"summary"`
	Errors            []string            `json:"errors,omitempty"`
}
