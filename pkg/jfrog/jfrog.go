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

const DefaultBaseURL = "https://artifactory.jfrog.io"

type Platform struct {
	client *Client
	config platforms.Config
}

func NewPlatform() *Platform {
	return &Platform{}
}

func (p *Platform) Name() string {
	return "jfrog"
}

func (p *Platform) SetClient(client *Client) {
	p.client = client
}

func (p *Platform) Client() *Client {
	return p.client
}

func (p *Platform) Init(ctx context.Context, config platforms.Config) error {
	p.config = config

	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	// A trailing slash would double up in every constructed URL.
	baseURL = strings.TrimSuffix(baseURL, "/")

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

	var opts []ClientOption
	if config.Timeout > 0 {
		opts = append(opts, WithTimeout(config.Timeout))
	}
	if config.Concurrency > 0 {
		opts = append(opts, WithConcurrency(int64(config.Concurrency)))
	}

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

func (p *Platform) Scan(ctx context.Context, target platforms.Target) (*platforms.ScanResult, error) {
	result := &platforms.ScanResult{
		Workflows: make(map[string][]platforms.Workflow),
	}

	switch target.Type {
	case platforms.TargetOrg:
		// For JFrog, TargetOrg means the whole instance.
		repositories, err := p.listRepositories(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing repositories: %w", err)
		}
		result.Repositories = repositories

		// Builds are surfaced as Workflows.
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

	repos := make([]platforms.Repository, len(jfrogRepos))
	for i, r := range jfrogRepos {
		repos[i] = platforms.Repository{
			Name: r.Key,
			URL:  r.URL,
		}
	}

	return repos, nil
}

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

	workflows := make([]platforms.Workflow, 0, len(buildList.Builds))
	for _, build := range buildList.Builds {
		name := strings.TrimPrefix(build.URI, "/")

		workflows = append(workflows, platforms.Workflow{
			Name:     name,
			RepoSlug: name,
		})
	}

	return workflows, nil
}

// Get, GetUser and GetSystemInfo forward so Platform satisfies tokenprobe.JFrogClient.
func (p *Platform) Get(ctx context.Context, path string) (*http.Response, error) {
	return p.client.Get(ctx, path)
}

func (p *Platform) GetUser(ctx context.Context) (*User, error) {
	return p.client.GetUser(ctx)
}

func (p *Platform) GetSystemInfo(ctx context.Context) (map[string]interface{}, error) {
	return p.client.GetSystemInfo(ctx)
}

var _ platforms.Platform = (*Platform)(nil)
