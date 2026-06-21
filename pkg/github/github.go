// pkg/github/github.go
package github

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/analysis/secrets"
	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/praetorian-inc/trajan/pkg/platforms/shared/proxy"
)

// Platform implements the platforms.Platform interface for GitHub
type Platform struct {
	client *Client
	config platforms.Config
}

// NewPlatform creates a new GitHub platform adapter
func NewPlatform() *Platform {
	return &Platform{}
}

// Name returns the platform identifier
func (p *Platform) Name() string {
	return "github"
}

// Init initializes the platform with configuration
func (p *Platform) Init(ctx context.Context, config platforms.Config) error {
	p.config = config

	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}

	// Build client options from config
	var opts []ClientOption
	if config.Timeout > 0 {
		opts = append(opts, WithTimeout(config.Timeout))
	}
	if config.Concurrency > 0 {
		opts = append(opts, WithConcurrency(int64(config.Concurrency)))
	}

	// Resolve proxy transport: explicit HTTPTransport takes precedence (WASM), then proxy config
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

// Client returns the underlying GitHub client
func (p *Platform) Client() *Client {
	return p.client
}

// Scan retrieves repositories and workflows from the target
func (p *Platform) Scan(ctx context.Context, target platforms.Target) (*platforms.ScanResult, error) {
	result := &platforms.ScanResult{
		Workflows: make(map[string][]platforms.Workflow),
	}

	var repos []Repository
	var err error

	switch target.Type {
	case platforms.TargetRepo:
		parts := strings.SplitN(target.Value, "/", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid repo format, expected owner/repo: %s", target.Value)
		}
		repo, err := p.client.GetRepository(ctx, parts[0], parts[1])
		if err != nil {
			return nil, fmt.Errorf("getting repository: %w", err)
		}
		repos = []Repository{*repo}

	case platforms.TargetOrg:
		fmt.Fprintf(os.Stderr, "Enumerating repositories in organization %s...\n", target.Value)
		repos, err = p.client.ListOrgRepos(ctx, target.Value)
		if err != nil {
			return nil, fmt.Errorf("listing org repos: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Found %d repositories\n", len(repos))

	case platforms.TargetUser:
		if target.Value == "" {
			// Empty user = all accessible repos (app token => installation repos;
			// user token => owned + org + collaborator repos).
			fmt.Fprintf(os.Stderr, "Enumerating all accessible repositories...\n")
			repos, err = p.enumerateAllAccessibleRepos(ctx)
			if err != nil {
				return nil, fmt.Errorf("enumerating accessible repos: %w", err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Enumerating repositories for user %s...\n", target.Value)
			repos, err = p.client.ListUserRepos(ctx, target.Value)
			if err != nil {
				return nil, fmt.Errorf("listing user repos: %w", err)
			}
		}
		fmt.Fprintf(os.Stderr, "Found %d repositories\n", len(repos))

	default:
		return nil, fmt.Errorf("unknown target type: %s", target.Type)
	}

	// Convert to platform-agnostic types
	fmt.Fprintf(os.Stderr, "\nFetching workflows from repositories...\n")
	for i, r := range repos {
		fmt.Fprintf(os.Stderr, "[%d/%d] %s/%s... ", i+1, len(repos), r.Owner.Login, r.Name)

		result.Repositories = append(result.Repositories, platforms.Repository{
			Owner:         r.Owner.Login,
			Name:          r.Name,
			DefaultBranch: r.DefaultBranch,
			Private:       r.Private,
			Archived:      r.Archived,
			URL:           r.HTMLURL,
		})

		// Get workflow files for each repo
		workflows, workflowErrors := p.getWorkflows(ctx, r.Owner.Login, r.Name)

		// Add any workflow fetching errors to result
		if len(workflowErrors) > 0 {
			// Wrap all workflow errors with repository context
			for _, wfErr := range workflowErrors {
				result.Errors = append(result.Errors, fmt.Errorf("%s/%s: %w", r.Owner.Login, r.Name, wfErr))
			}
			fmt.Fprintf(os.Stderr, "found %d workflows (%d errors)\n", len(workflows), len(workflowErrors))
		} else {
			fmt.Fprintf(os.Stderr, "found %d workflows\n", len(workflows))
		}

		if len(workflows) > 0 {
			result.Workflows[r.FullName] = workflows
		}
	}
	fmt.Fprintf(os.Stderr, "\n")

	return result, nil
}

// getWorkflows retrieves workflow files for a repository
// Returns workflows and a slice of errors for files that couldn't be read
func (p *Platform) getWorkflows(ctx context.Context, owner, repo string) ([]platforms.Workflow, []error) {
	files, err := p.client.GetWorkflowFiles(ctx, owner, repo)
	if err != nil {
		return nil, []error{err}
	}

	var workflows []platforms.Workflow
	var errors []error

	for _, f := range files {
		content, err := p.client.GetWorkflowContent(ctx, owner, repo, f.Path)
		if err != nil {
			// Collect error instead of silently skipping
			errors = append(errors, fmt.Errorf("%s: %w", f.Path, err))
			continue
		}

		workflows = append(workflows, platforms.Workflow{
			Name:     f.Name,
			Path:     f.Path,
			Content:  content,
			SHA:      f.SHA,
			RepoSlug: fmt.Sprintf("%s/%s", owner, repo),
		})
	}

	return workflows, errors
}

// ScanSecrets enumerates secrets across organization/repository scope
func (p *Platform) ScanSecrets(ctx context.Context, target platforms.Target) (*SecretsResult, error) {
	result := &SecretsResult{
		ActionsSecrets:    make(map[string][]Secret),
		WorkflowSecrets:   make(map[string][]Secret),
		DependabotSecrets: make(map[string][]Secret),
		CodespacesSecrets: make(map[string][]Secret),
	}

	switch target.Type {
	case platforms.TargetOrg:
		// Enumerate org-level Actions secrets
		actionsSecrets, err := p.client.ListOrgActionsSecrets(ctx, target.Value)
		if err != nil {
			// Check if this is a permission error
			if IsPermissionDenied(err) {
				result.PermissionErrors = append(result.PermissionErrors,
					"org-level Actions secrets: requires admin:org scope")
			} else {
				result.Errors = append(result.Errors, fmt.Errorf("org actions secrets: %w", err))
			}
		} else if len(actionsSecrets) > 0 {
			// Mark API secrets with Source="api"
			for i := range actionsSecrets {
				actionsSecrets[i].Source = "api"
			}
			result.ActionsSecrets[target.Value] = actionsSecrets
		}

		// Extract workflow secrets for all org repos
		repos, err := p.client.ListOrgRepos(ctx, target.Value)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("listing org repos for workflow scan: %w", err))
		} else {
			for _, repo := range repos {
				repoTarget := fmt.Sprintf("%s/%s", repo.Owner.Login, repo.Name)
				workflows, workflowErrors := p.getWorkflows(ctx, repo.Owner.Login, repo.Name)

				// Add any workflow fetching errors to result
				if len(workflowErrors) > 0 {
					for _, wfErr := range workflowErrors {
						result.Errors = append(result.Errors, fmt.Errorf("getting workflows for %s: %w", repoTarget, wfErr))
					}
				}

				workflowSecrets := p.extractWorkflowSecrets(workflows)
				if len(workflowSecrets) > 0 {
					result.WorkflowSecrets[repoTarget] = workflowSecrets
				}
			}
		}

	case platforms.TargetRepo:
		parts := strings.SplitN(target.Value, "/", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid repo format: %s", target.Value)
		}
		owner, repo := parts[0], parts[1]

		// Enumerate repo-level Actions secrets
		actionsSecrets, err := p.client.ListRepoActionsSecrets(ctx, owner, repo)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("repo actions secrets: %w", err))
		} else if len(actionsSecrets) > 0 {
			// Mark API secrets with Source="api"
			for i := range actionsSecrets {
				actionsSecrets[i].Source = "api"
			}
			result.ActionsSecrets[target.Value] = actionsSecrets
		}

		// Enumerate org-level secrets accessible to this repo
		orgSecrets, err := p.client.ListRepoOrgSecrets(ctx, owner, repo)
		if err != nil {
			// Don't treat as error - org might not have secrets or user might lack permissions
		} else if len(orgSecrets) > 0 {
			// Mark org secrets with Source="api"
			for i := range orgSecrets {
				orgSecrets[i].Source = "api"
			}
			// Merge org secrets with repo secrets
			result.ActionsSecrets[target.Value] = append(result.ActionsSecrets[target.Value], orgSecrets...)
		}

		// Enumerate environment secrets
		environments, err := p.client.ListRepoEnvironments(ctx, owner, repo)
		if err != nil {
			// Ignore error - not all repos have environments
		} else {
			for _, env := range environments {
				envSecrets, err := p.client.ListEnvironmentSecrets(ctx, owner, repo, env.Name)
				if err != nil {
					// Continue on error - might not have permission for specific environment
					continue
				}

				if len(envSecrets) > 0 {
					// Mark environment secrets with Source="api"
					for i := range envSecrets {
						envSecrets[i].Source = "api"
					}
					// Store with environment-qualified key
					envKey := fmt.Sprintf("%s (environment: %s)", target.Value, env.Name)
					result.ActionsSecrets[envKey] = envSecrets
				}
			}
		}

		// Extract workflow secrets
		workflows, workflowErrors := p.getWorkflows(ctx, owner, repo)

		// Add any workflow fetching errors to result
		if len(workflowErrors) > 0 {
			for _, wfErr := range workflowErrors {
				result.Errors = append(result.Errors, fmt.Errorf("getting workflows: %w", wfErr))
			}
		}

		workflowSecrets := p.extractWorkflowSecrets(workflows)
		if len(workflowSecrets) > 0 {
			result.WorkflowSecrets[target.Value] = workflowSecrets
		}

	default:
		return nil, fmt.Errorf("unsupported target type for secrets scan: %s", target.Type)
	}

	return result, nil
}

// extractWorkflowSecrets extracts secrets from workflow files
func (p *Platform) extractWorkflowSecrets(workflows []platforms.Workflow) []Secret {
	var allSecrets []Secret
	seenSecrets := make(map[string]bool)

	for _, wf := range workflows {
		secretRefs, err := secrets.ExtractSecrets(wf.Path, wf.Content)
		if err != nil {
			// Skip workflows that can't be parsed
			continue
		}

		for _, ref := range secretRefs {
			// Deduplicate secrets (same secret may appear in multiple workflows)
			if !seenSecrets[ref.Name] {
				seenSecrets[ref.Name] = true
				allSecrets = append(allSecrets, Secret{
					Name:   ref.Name,
					Source: "workflow",
				})
			}
		}
	}

	return allSecrets
}

// ScanRunners enumerates self-hosted runners across organization/repository scope
func (p *Platform) ScanRunners(ctx context.Context, target platforms.Target) (*RunnersResult, error) {
	result := &RunnersResult{
		Runners:      make(map[string][]Runner),
		RunnerGroups: make(map[string][]RunnerGroup),
	}

	switch target.Type {
	case platforms.TargetOrg:
		// Enumerate org runners
		runners, err := p.client.ListOrgRunners(ctx, target.Value)
		if err != nil {
			if IsPermissionDenied(err) {
				result.PermissionErrors = append(result.PermissionErrors, "org runners: requires admin:org or manage_runners:org permission")
			} else {
				result.Errors = append(result.Errors, fmt.Errorf("org runners: %w", err))
			}
		} else if len(runners) > 0 {
			result.Runners[target.Value] = runners
		}

		// Enumerate runner groups
		groups, err := p.client.ListOrgRunnerGroups(ctx, target.Value)
		if err != nil {
			if IsPermissionDenied(err) {
				result.PermissionErrors = append(result.PermissionErrors, "runner groups: requires admin:org or manage_runners:org permission")
			} else {
				result.Errors = append(result.Errors, fmt.Errorf("runner groups: %w", err))
			}
		} else if len(groups) > 0 {
			result.RunnerGroups[target.Value] = groups
		}

	case platforms.TargetRepo:
		parts := strings.SplitN(target.Value, "/", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid repo format: %s", target.Value)
		}
		owner, repo := parts[0], parts[1]

		runners, err := p.client.ListRepoRunners(ctx, owner, repo)
		if err != nil {
			if IsPermissionDenied(err) {
				result.PermissionErrors = append(result.PermissionErrors, "repo runners: requires admin access or manage_runners:enterprise permission")
			} else {
				result.Errors = append(result.Errors, fmt.Errorf("repo runners: %w", err))
			}
		} else if len(runners) > 0 {
			result.Runners[target.Value] = runners
		}

	default:
		return nil, fmt.Errorf("unsupported target type for runner scan: %s", target.Type)
	}

	return result, nil
}

// ScanTokenInfo retrieves metadata about the authenticated token
func (p *Platform) ScanTokenInfo(ctx context.Context) (*TokenInfoResult, error) {
	result := &TokenInfoResult{}

	tokenInfo, err := p.client.GetTokenInfo(ctx)
	if err != nil {
		if IsPermissionDenied(err) {
			result.PermissionErrors = append(result.PermissionErrors, err.Error())
		} else {
			result.Errors = append(result.Errors, fmt.Errorf("getting token info: %w", err))
		}
		return result, nil
	}

	result.TokenInfo = tokenInfo
	return result, nil
}

// Ensure Platform implements the interface
var _ platforms.Platform = (*Platform)(nil)
