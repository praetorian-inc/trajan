// Package platforms provides CI/CD platform adapters
package platforms

import (
	"context"
	"net/http"
	"time"
)

// Platform name constants
const (
	PlatformGitHub      = "github"
	PlatformGitLab      = "gitlab"
	PlatformAzureDevOps = "azuredevops"
	PlatformJFrog       = "jfrog"
	PlatformJenkins     = "jenkins"
	PlatformLocal       = "local"
)

// TargetType represents what kind of target to scan
type TargetType string

const (
	TargetRepo  TargetType = "repo"
	TargetOrg   TargetType = "org"
	TargetUser  TargetType = "user"
	TargetLocal TargetType = "local"
)

// Target specifies what to scan
type Target struct {
	Type  TargetType
	Value string // "owner/repo", "orgname", or "username"
}

// GitHubAuth contains GitHub-specific authentication
type GitHubAuth struct {
	Token      string `json:"token,omitempty"`           // Personal Access Token
	AppID      int64  `json:"app_id,omitempty"`          // GitHub App ID
	InstallID  int64  `json:"installation_id,omitempty"` // GitHub App Installation ID
	PrivateKey string `json:"private_key,omitempty"`     // GitHub App private key (PEM)
}

// GitLabAuth contains GitLab-specific authentication
type GitLabAuth struct {
	Token      string `json:"token,omitempty"`       // Personal Access Token or Project Token
	OAuthToken string `json:"oauth_token,omitempty"` // OAuth2 token
}

// AzureDevOpsAuth contains Azure DevOps-specific authentication
type AzureDevOpsAuth struct {
	PAT          string `json:"pat,omitempty"`          // Personal Access Token
	BearerToken  string `json:"bearer_token,omitempty"` // Azure Entra ID OAuth token
	Organization string `json:"organization,omitempty"` // Azure DevOps organization
}

// JFrogAuth contains JFrog-specific authentication
type JFrogAuth struct {
	Token    string `json:"token,omitempty"`    // Access token (preferred)
	APIKey   string `json:"api_key,omitempty"`  // API key (deprecated but still used)
	Username string `json:"username,omitempty"` // For basic auth
	Password string `json:"password,omitempty"` // For basic auth
}

// JenkinsAuth contains Jenkins-specific authentication
type JenkinsAuth struct {
	Username string `json:"username,omitempty"`
	Token    string `json:"token,omitempty"`
}

// Config holds platform configuration
type Config struct {
	// Existing fields (keep these)
	Token       string
	BaseURL     string
	Concurrency int
	Timeout     time.Duration

	// Platform-specific auth (new - composition pattern)
	GitHub      *GitHubAuth      `json:"github,omitempty"`
	GitLab      *GitLabAuth      `json:"gitlab,omitempty"`
	AzureDevOps *AzureDevOpsAuth `json:"azuredevops,omitempty"`
	JFrog       *JFrogAuth       `json:"jfrog,omitempty"`
	Jenkins     *JenkinsAuth     `json:"jenkins,omitempty"`

	// HTTPTransport sets a custom HTTP transport. Used in browser (WASM) context
	// to proxy requests through localhost, bypassing CORS restrictions.
	// nil uses the default transport.
	HTTPTransport http.RoundTripper `json:"-"`

	// HTTPProxy is the HTTP proxy URL (e.g., "http://proxy:8080").
	// When set, TLS verification is automatically disabled for interception.
	HTTPProxy string `json:"-"`

	// SOCKSProxy is the SOCKS5 proxy URL (e.g., "socks5://proxy:1080").
	// Supports authentication: "socks5://user:pass@proxy:1080".
	SOCKSProxy string `json:"-"`
}

// Repository represents a source code repository
type Repository struct {
	Owner         string
	Name          string
	DefaultBranch string
	Private       bool
	Archived      bool
	URL           string
}

// FullName returns "owner/repo" format
func (r Repository) FullName() string {
	return r.Owner + "/" + r.Name
}

// Workflow represents a CI/CD workflow file
type Workflow struct {
	Name     string
	Path     string
	Content  []byte
	SHA      string
	RepoSlug string
	Metadata map[string]interface{} // Platform-specific metadata for resolvers
}

// ScanResult contains the results of a platform scan
type ScanResult struct {
	Repositories []Repository
	Workflows    map[string][]Workflow // repo slug -> workflows
	Errors       []error
}

// Platform adapts a CI/CD platform for scanning
type Platform interface {
	// Name returns the platform identifier (e.g., "github", "gitlab")
	Name() string

	// Init initializes the platform with configuration
	Init(ctx context.Context, config Config) error

	// Scan retrieves repositories and workflows from the target
	Scan(ctx context.Context, target Target) (*ScanResult, error)
}

// PlatformFactory creates new platform instances
type PlatformFactory func() Platform
