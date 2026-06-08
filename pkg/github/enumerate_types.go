package github

import (
	"time"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// TokenEnumerateResult contains token validation and enumeration results
type TokenEnumerateResult struct {
	TokenInfo           *TokenInfo         `json:"token_info,omitempty"`
	Permissions         map[string]string  `json:"permissions,omitempty"`   // Fine-grained permissions
	Organizations       []OrganizationInfo `json:"organizations,omitempty"` // Accessible organizations
	RateLimit           *RateLimitInfo     `json:"rate_limit,omitempty"`
	AccessibleRepos     int                `json:"accessible_repos,omitempty"`
	RepositorySelection string             `json:"repository_selection,omitempty"`
	Errors              []error            `json:"-"`
}

// OrganizationInfo contains organization membership information
type OrganizationInfo struct {
	Name string `json:"name"`
	Role string `json:"role,omitempty"` // admin, member, billing_manager
	URL  string `json:"url,omitempty"`
}

// RateLimitInfo contains GitHub API rate limit status
type RateLimitInfo struct {
	Limit     int       `json:"limit"`
	Remaining int       `json:"remaining"`
	Reset     time.Time `json:"reset"`
	Used      int       `json:"used"`
}

// EnumerateResult contains complete enumeration data
type EnumerateResult struct {
	TokenInfo    *TokenEnumerateResult           `json:"token_info,omitempty"`
	Repositories []platforms.Repository          `json:"repositories,omitempty"`
	Secrets      *SecretsResult                  `json:"secrets,omitempty"`
	Runners      *RunnersResult                  `json:"runners,omitempty"`
	Workflows    map[string][]platforms.Workflow `json:"workflows,omitempty"`
	Metadata     EnumerateMetadata               `json:"metadata"`
}

// EnumerateMetadata tracks enumeration execution information
type EnumerateMetadata struct {
	StartTime     time.Time     `json:"start_time"`
	EndTime       time.Time     `json:"end_time"`
	Duration      time.Duration `json:"duration"`
	APIRequests   int           `json:"api_requests"`
	RateLimitUsed int           `json:"rate_limit_used"`
	Target        string        `json:"target"`
	TargetType    string        `json:"target_type"`
}

// Note: TokenInfoResult already exists in types.go for backward compatibility

// EnvironmentSecret represents a secret scoped to a deployment environment
type EnvironmentSecret struct {
	Secret
	Environment string `json:"environment"`
}

// RepositoryWithPermissions extends Repository with permission metadata
type RepositoryWithPermissions struct {
	platforms.Repository
	Permissions RepositoryPermissions `json:"permissions"`
}

// RepositoryPermissions represents access level to a repository
type RepositoryPermissions struct {
	Admin bool `json:"admin"`
	Push  bool `json:"push"`
	Pull  bool `json:"pull"`
}

// ReposEnumerateResult contains repository enumeration results
type ReposEnumerateResult struct {
	Repositories []RepositoryWithPermissions `json:"repositories"`
	Summary      ReposSummary                `json:"summary"`
	Errors       []error                     `json:"-"`
}

// ReposSummary provides statistics about enumerated repositories
type ReposSummary struct {
	Total       int `json:"total"`
	Private     int `json:"private"`
	Public      int `json:"public"`
	Archived    int `json:"archived"`
	WriteAccess int `json:"write_access"`
	ReadAccess  int `json:"read_access"`
}
