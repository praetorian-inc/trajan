// Package gitlab implements the platforms.Platform interface for GitLab
package gitlab

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/praetorian-inc/trajan/pkg/platforms/shared/proxy"
)

type Platform struct {
	client *Client
	config platforms.Config
}

func NewPlatform() *Platform {
	return &Platform{}
}

func (p *Platform) Name() string {
	return "gitlab"
}

func (p *Platform) Init(ctx context.Context, config platforms.Config) error {
	p.config = config

	baseURL := config.BaseURL
	if baseURL != "" {
		// Rejects file:// and javascript: URLs.
		if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
			return fmt.Errorf("invalid URL scheme: must be http:// or https://, got: %s", baseURL)
		}
	}

	var opts []ClientOption
	if config.Timeout > 0 {
		opts = append(opts, WithTimeout(config.Timeout))
	}
	if config.Concurrency > 0 {
		opts = append(opts, WithConcurrency(int64(config.Concurrency)))
	}

	// An explicit HTTPTransport wins over the proxy config.
	transport := config.HTTPTransport
	if transport == nil {
		var err error
		transport, err = proxy.NewTransport(proxy.Config{
			HTTPProxy:  config.HTTPProxy,
			SOCKSProxy: config.SOCKSProxy,
		})
		if err != nil {
			return fmt.Errorf("configuring proxy: %w", err)
		}
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

	var projects []Project
	var err error

	switch target.Type {
	case platforms.TargetRepo:
		parts := strings.SplitN(target.Value, "/", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid repo format, expected owner/repo: %s", target.Value)
		}
		projectPath := target.Value
		project, err := p.client.GetProject(ctx, projectPath)
		if err != nil {
			return nil, fmt.Errorf("getting project: %w", err)
		}
		projects = []Project{*project}

	case platforms.TargetOrg:
		projects, err = p.client.ListGroupProjects(ctx, target.Value)
		if err != nil {
			return nil, fmt.Errorf("listing group projects: %w", err)
		}

	case platforms.TargetUser:
		projects, err = p.client.ListUserProjects(ctx, target.Value)
		if err != nil {
			return nil, fmt.Errorf("listing user projects: %w", err)
		}

	default:
		return nil, fmt.Errorf("unknown target type: %s", target.Type)
	}

	for i := range projects {
		proj := &projects[i]
		owner := proj.Namespace.FullPath
		if owner == "" {
			owner = proj.Namespace.Name
		}

		result.Repositories = append(result.Repositories, platforms.Repository{
			Owner:         owner,
			Name:          proj.Path,
			DefaultBranch: proj.DefaultBranch,
			Private:       proj.Visibility != "public", // GitLab: public, internal, private
			Archived:      proj.Archived,
			URL:           proj.WebURL,
		})

		workflow, err := p.getWorkflow(ctx, proj.ID, proj.PathWithNamespace, proj.DefaultBranch)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("%s: %w", proj.PathWithNamespace, err))
			continue
		}

		if workflow != nil {
			// Consumed by the include resolver.
			workflow.Metadata = map[string]interface{}{
				"gitlab_client":     p.client,
				"gitlab_project_id": proj.ID,
				"gitlab_ref":        proj.DefaultBranch,
			}

			result.Workflows[proj.PathWithNamespace] = []platforms.Workflow{*workflow}
		}
	}

	return result, nil
}

func (p *Platform) getWorkflow(ctx context.Context, projectID int, pathWithNamespace, ref string) (*platforms.Workflow, error) {
	const ciFile = ".gitlab-ci.yml"

	content, err := p.client.GetWorkflowFile(ctx, projectID, ciFile, ref)
	if err != nil {
		// Not every project has CI, so absence is not an error.
		if IsNotFoundError(err) {
			return nil, nil
		}
		return nil, err
	}

	return &platforms.Workflow{
		Name:     ciFile,
		Path:     ciFile,
		Content:  content,
		RepoSlug: pathWithNamespace,
	}, nil
}

var _ platforms.Platform = (*Platform)(nil)
