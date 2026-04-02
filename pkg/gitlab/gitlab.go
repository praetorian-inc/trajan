// Package gitlab implements the platforms.Platform interface for GitLab
package gitlab

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/praetorian-inc/trajan/pkg/platforms/shared/proxy"
)

// Platform implements the platforms.Platform interface for GitLab
type Platform struct {
	client *Client
	config platforms.Config
}

// NewPlatform creates a new GitLab platform adapter
func NewPlatform() *Platform {
	return &Platform{}
}

// Name returns the platform identifier
func (p *Platform) Name() string {
	return "gitlab"
}

// Init initializes the platform with configuration
func (p *Platform) Init(ctx context.Context, config platforms.Config) error {
	p.config = config

	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	} else {
		// Validate URL scheme for security (prevent file://, javascript:, etc.)
		if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
			return fmt.Errorf("invalid URL scheme: must be http:// or https://, got: %s", baseURL)
		}

		// Ensure baseURL ends with /api/v4 for self-hosted instances
		if !strings.HasSuffix(baseURL, "/api/v4") {
			baseURL = strings.TrimRight(baseURL, "/") + "/api/v4"
		}
	}

	// Build client options from config
	var opts []ClientOption
	if config.Timeout > 0 {
		opts = append(opts, WithTimeout(config.Timeout))
	}
	if config.Concurrency > 0 {
		opts = append(opts, WithConcurrency(int64(config.Concurrency)))
	}

	// Resolve proxy transport: explicit HTTPTransport takes precedence, then proxy config
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

// Client returns the underlying GitLab client
func (p *Platform) Client() *Client {
	return p.client
}

// Scan retrieves repositories and workflows from the target
func (p *Platform) Scan(ctx context.Context, target platforms.Target) (*platforms.ScanResult, error) {
	result := &platforms.ScanResult{
		Workflows: make(map[string][]platforms.Workflow),
	}

	var projects []Project
	var err error

	switch target.Type {
	case platforms.TargetRepo:
		// Single repository: "owner/repo"
		parts := strings.SplitN(target.Value, "/", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid repo format, expected owner/repo: %s", target.Value)
		}
		// In GitLab, we need to URL-encode "owner/repo" as the project ID
		projectPath := target.Value
		project, err := p.client.GetProject(ctx, projectPath)
		if err != nil {
			return nil, fmt.Errorf("getting project: %w", err)
		}
		projects = []Project{*project}

	case platforms.TargetOrg:
		// GitLab group/namespace
		projects, err = p.client.ListGroupProjects(ctx, target.Value)
		if err != nil {
			return nil, fmt.Errorf("listing group projects: %w", err)
		}

	case platforms.TargetUser:
		// User projects
		projects, err = p.client.ListUserProjects(ctx, target.Value)
		if err != nil {
			return nil, fmt.Errorf("listing user projects: %w", err)
		}

	default:
		return nil, fmt.Errorf("unknown target type: %s", target.Type)
	}

	// Convert to platform-agnostic types
	for _, proj := range projects {
		// Extract owner from namespace path or use namespace name
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

		// Get workflow file for each project (.gitlab-ci.yml)
		workflow, err := p.getWorkflow(ctx, proj.ID, proj.PathWithNamespace, proj.DefaultBranch)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("%s: %w", proj.PathWithNamespace, err))
			continue
		}

		if workflow != nil {
			// Attach resolver metadata
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

// getWorkflow retrieves the .gitlab-ci.yml file for a project
func (p *Platform) getWorkflow(ctx context.Context, projectID int, pathWithNamespace, ref string) (*platforms.Workflow, error) {
	const ciFile = ".gitlab-ci.yml"

	content, err := p.client.GetWorkflowFile(ctx, projectID, ciFile, ref)
	if err != nil {
		// If file doesn't exist, return nil (not all projects have CI)
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

// Ensure Platform implements the interface
var _ platforms.Platform = (*Platform)(nil)
