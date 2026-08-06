// Package jenkins implements the platforms.Platform interface for Jenkins
package jenkins

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/praetorian-inc/trajan/pkg/platforms/shared/proxy"
)

const DefaultBaseURL = "https://jenkins.example.com"

type Platform struct {
	client *Client
	config platforms.Config
}

func NewPlatform() *Platform {
	return &Platform{}
}

func (p *Platform) Name() string {
	return "jenkins"
}

func (p *Platform) Init(ctx context.Context, config platforms.Config) error {
	p.config = config

	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	var opts []ClientOption
	if config.Timeout > 0 {
		opts = append(opts, WithTimeout(config.Timeout))
	}
	if config.Concurrency > 0 {
		opts = append(opts, WithConcurrency(int64(config.Concurrency)))
	}
	if config.Jenkins != nil && config.Jenkins.Username != "" {
		opts = append(opts, WithUsername(config.Jenkins.Username))
	}

	// An explicit HTTPTransport wins over the proxy config.
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

func (p *Platform) Client() *Client {
	return p.client
}

func (p *Platform) Scan(ctx context.Context, target platforms.Target) (*platforms.ScanResult, error) {
	result := &platforms.ScanResult{
		Workflows: make(map[string][]platforms.Workflow),
	}

	switch target.Type {
	case platforms.TargetRepo:
		// target.Value is "job-name" or "folder/job-name".
		workflow, err := p.getWorkflow(ctx, target.Value)
		if err != nil {
			return nil, fmt.Errorf("getting job: %w", err)
		}
		if workflow != nil {
			result.Repositories = append(result.Repositories, platforms.Repository{
				Name: target.Value,
				URL:  fmt.Sprintf("%s/job/%s", p.client.baseURL, encodeJobPath(target.Value)),
			})
			result.Workflows[target.Value] = []platforms.Workflow{*workflow}
		}

	case platforms.TargetOrg:
		jobs, err := p.client.ListJobsRecursive(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing jobs: %w", err)
		}

		for _, job := range jobs {
			result.Repositories = append(result.Repositories, platforms.Repository{
				Name: job.Name,
				URL:  job.URL,
			})

			workflow, err := p.getWorkflow(ctx, job.Name)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Errorf("%s: %w", job.Name, err))
				continue
			}
			if workflow != nil {
				result.Workflows[job.Name] = []platforms.Workflow{*workflow}
			}
		}

	default:
		return nil, fmt.Errorf("unsupported target type for Jenkins: %s", target.Type)
	}

	return result, nil
}

func (p *Platform) getWorkflow(ctx context.Context, jobName string) (*platforms.Workflow, error) {
	// A multibranch job keeps its Jenkinsfile in SCM, so only config.xml is reachable.
	jobPath := encodeJobPath(jobName)
	path := fmt.Sprintf("/job/%s/config.xml", jobPath)

	content, err := p.client.getRaw(ctx, path)
	if err != nil {
		// A 404 is not an error: the job simply has no pipeline config.
		if strings.Contains(err.Error(), "404") {
			return nil, nil
		}
		return nil, err
	}

	return &platforms.Workflow{
		Name:     "Jenkinsfile",
		Path:     "Jenkinsfile",
		Content:  content,
		RepoSlug: jobName,
	}, nil
}

var _ platforms.Platform = (*Platform)(nil)
