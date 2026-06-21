// Package jfrog implements the platforms.Platform interface for JFrog Artifactory
package jfrog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/praetorian-inc/trajan/pkg/platforms/shared/proxy"
)

// DefaultBaseURL is the default JFrog base URL
const DefaultBaseURL = "https://artifactory.jfrog.io"

// Platform implements the platforms.Platform interface for JFrog
type Platform struct {
	client *Client
	config platforms.Config
}

// NewPlatform creates a new JFrog platform adapter
func NewPlatform() *Platform {
	return &Platform{}
}

// Name returns the platform identifier
func (p *Platform) Name() string {
	return "jfrog"
}

// SetClient allows setting a custom client (useful for testing or advanced auth)
func (p *Platform) SetClient(client *Client) {
	p.client = client
}

// Client returns the underlying JFrog client
func (p *Platform) Client() *Client {
	return p.client
}

// Init initializes the platform with configuration
func (p *Platform) Init(ctx context.Context, config platforms.Config) error {
	p.config = config

	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	// Trim trailing slash to avoid double slashes in URL construction
	baseURL = strings.TrimSuffix(baseURL, "/")

	// Check if JFrog-specific auth is provided
	if config.JFrog != nil {
		clientConfig := ClientConfig{
			BaseURL:     baseURL,
			AccessToken: config.JFrog.Token,
			APIKey:      config.JFrog.APIKey,
			Username:    config.JFrog.Username,
			Password:    config.JFrog.Password,
			Timeout:     config.Timeout,
			Concurrency: int64(config.Concurrency),
		}
		p.client = NewClientWithConfig(clientConfig)

		// Apply proxy transport
		transport := config.HTTPTransport
		if transport == nil {
			t, err := proxy.NewTransport(proxy.Config{
				HTTPProxy:  config.HTTPProxy,
				SOCKSProxy: config.SOCKSProxy,
			})
			if err != nil {
				return fmt.Errorf("configuring proxy: %w", err)
			}
			transport = t
		}
		if transport != nil {
			WithHTTPTransport(transport)(p.client)
		}
		return nil
	}

	// Fallback to token-based auth
	var opts []ClientOption
	if config.Timeout > 0 {
		opts = append(opts, WithTimeout(config.Timeout))
	}
	if config.Concurrency > 0 {
		opts = append(opts, WithConcurrency(int64(config.Concurrency)))
	}

	// Resolve proxy transport
	transport := config.HTTPTransport
	if transport == nil {
		t, err := proxy.NewTransport(proxy.Config{
			HTTPProxy:  config.HTTPProxy,
			SOCKSProxy: config.SOCKSProxy,
		})
		if err != nil {
			return fmt.Errorf("configuring proxy: %w", err)
		}
		transport = t
	}
	if transport != nil {
		opts = append(opts, WithHTTPTransport(transport))
	}

	p.client = NewClient(baseURL, config.Token, opts...)
	return nil
}

// Scan retrieves repositories and build info from the target
func (p *Platform) Scan(ctx context.Context, target platforms.Target) (*platforms.ScanResult, error) {
	result := &platforms.ScanResult{
		Workflows: make(map[string][]platforms.Workflow),
	}

	switch target.Type {
	case platforms.TargetOrg:
		// For JFrog, TargetOrg means scanning the entire JFrog instance
		repositories, err := p.listRepositories(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing repositories: %w", err)
		}
		result.Repositories = repositories

		// Get build info (conceptual mapping to "Workflows")
		buildInfo, err := p.getBuildInfo(ctx)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("getting build info: %w", err))
		} else {
			for _, workflow := range buildInfo {
				result.Workflows[workflow.RepoSlug] = append(result.Workflows[workflow.RepoSlug], workflow)
			}
		}

	default:
		return nil, fmt.Errorf("unsupported target type for JFrog: %s (use 'org' to scan entire instance)", target.Type)
	}

	return result, nil
}

// listRepositories retrieves all repositories from JFrog
func (p *Platform) listRepositories(ctx context.Context) ([]platforms.Repository, error) {
	resp, err := p.client.Get(ctx, "/api/repositories")
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API error (%d) listing repositories", resp.StatusCode)
	}

	var jfrogRepos []Repository
	if err := json.NewDecoder(resp.Body).Decode(&jfrogRepos); err != nil {
		return nil, fmt.Errorf("failed to parse repositories response: %w", err)
	}

	// Convert JFrog repositories to platform repositories
	repos := make([]platforms.Repository, len(jfrogRepos))
	for i, r := range jfrogRepos {
		repos[i] = platforms.Repository{
			Name: r.Key,
			URL:  r.URL,
		}
	}

	return repos, nil
}

// getBuildInfo retrieves build information from JFrog
func (p *Platform) getBuildInfo(ctx context.Context) ([]platforms.Workflow, error) {
	resp, err := p.client.Get(ctx, "/api/build")
	if err != nil {
		return nil, fmt.Errorf("failed to get build info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API error (%d) getting build info", resp.StatusCode)
	}

	var buildList struct {
		Builds []struct {
			URI string `json:"uri"`
		} `json:"builds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&buildList); err != nil {
		return nil, fmt.Errorf("failed to parse build info response: %w", err)
	}

	// Convert builds to workflows (conceptual mapping)
	workflows := make([]platforms.Workflow, 0, len(buildList.Builds))
	for _, build := range buildList.Builds {
		name := strings.TrimPrefix(build.URI, "/")

		workflows = append(workflows, platforms.Workflow{
			Name:     name,
			RepoSlug: name, // Use build name as repo slug
		})
	}

	return workflows, nil
}

// Get forwards the Get method to the underlying client
// This allows Platform to implement the tokenprobe.JFrogClient interface
func (p *Platform) Get(ctx context.Context, path string) (*http.Response, error) {
	return p.client.Get(ctx, path)
}

// GetUser forwards the GetUser method to the underlying client
// This allows Platform to implement the tokenprobe.JFrogClient interface
func (p *Platform) GetUser(ctx context.Context) (*User, error) {
	return p.client.GetUser(ctx)
}

// GetSystemInfo forwards the GetSystemInfo method to the underlying client
// This allows Platform to implement the tokenprobe.JFrogClient interface
func (p *Platform) GetSystemInfo(ctx context.Context) (map[string]interface{}, error) {
	return p.client.GetSystemInfo(ctx)
}

// Ensure Platform implements the interface
var _ platforms.Platform = (*Platform)(nil)
