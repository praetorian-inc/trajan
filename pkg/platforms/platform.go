// Package platforms provides CI/CD platform adapters
package platforms

import (
	"context"
	"net/http"
	"time"
)

const (
	PlatformGitHub      = "github"
	PlatformGitLab      = "gitlab"
	PlatformAzureDevOps = "azuredevops"
	PlatformJFrog       = "jfrog"
	PlatformJenkins     = "jenkins"
	PlatformBitbucket   = "bitbucket"
)

type TargetType string

const (
	TargetRepo TargetType = "repo"
	TargetOrg  TargetType = "org"
	TargetUser TargetType = "user"
)

type Target struct {
	Type  TargetType
	Value string // "owner/repo", "orgname", or "username"
}

type GitHubAuth struct {
	Token      string `json:"token,omitempty"` // Personal Access Token
	AppID      int64  `json:"app_id,omitempty"`
	InstallID  int64  `json:"installation_id,omitempty"`
	PrivateKey string `json:"private_key,omitempty"` // PEM
}

type GitLabAuth struct {
	Token      string `json:"token,omitempty"` // Personal Access Token or Project Token
	OAuthToken string `json:"oauth_token,omitempty"`
}

type AzureDevOpsAuth struct {
	PAT          string `json:"pat,omitempty"`
	BearerToken  string `json:"bearer_token,omitempty"` // Azure Entra ID OAuth token
	Organization string `json:"organization,omitempty"`
}

type JFrogAuth struct {
	Token    string `json:"token,omitempty"`   // Access token (preferred)
	APIKey   string `json:"api_key,omitempty"` // API key (deprecated but still used)
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type JenkinsAuth struct {
	Username string `json:"username,omitempty"`
	Token    string `json:"token,omitempty"`
}

type BitbucketAuth struct {
	Token string `json:"token,omitempty"` // ATCTT3x (access) or ATATT3x (API)
	Email string `json:"email,omitempty"` // Required for ATATT3x tokens
}

type Config struct {
	Token       string
	BaseURL     string
	Concurrency int
	Timeout     time.Duration

	GitHub      *GitHubAuth      `json:"github,omitempty"`
	GitLab      *GitLabAuth      `json:"gitlab,omitempty"`
	AzureDevOps *AzureDevOpsAuth `json:"azuredevops,omitempty"`
	JFrog       *JFrogAuth       `json:"jfrog,omitempty"`
	Jenkins     *JenkinsAuth     `json:"jenkins,omitempty"`
	Bitbucket   *BitbucketAuth   `json:"bitbucket,omitempty"`

	// Set in the browser (WASM) build to proxy through localhost and dodge CORS.
	// nil uses the default transport.
	HTTPTransport http.RoundTripper `json:"-"`

	// URL such as "http://proxy:8080". Setting it also disables TLS verification.
	HTTPProxy string `json:"-"`

	// URL such as "socks5://user:pass@proxy:1080"; credentials in the URL are used.
	SOCKSProxy string `json:"-"`
}

type Repository struct {
	Owner         string
	Name          string
	DefaultBranch string
	Private       bool
	Archived      bool
	URL           string
}

func (r Repository) FullName() string {
	return r.Owner + "/" + r.Name
}

type Workflow struct {
	Name     string
	Path     string
	Content  []byte
	SHA      string
	RepoSlug string
	Metadata map[string]interface{}
}

type ScanResult struct {
	Repositories []Repository
	Workflows    map[string][]Workflow // repo slug -> workflows
	Errors       []error
}

type Platform interface {
	Name() string

	Init(ctx context.Context, config Config) error

	Scan(ctx context.Context, target Target) (*ScanResult, error)
}

type PlatformFactory func() Platform
