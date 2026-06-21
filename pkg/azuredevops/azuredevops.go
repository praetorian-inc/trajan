// Package azuredevops implements the platforms.Platform interface for Azure DevOps
package azuredevops

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/praetorian-inc/trajan/pkg/platforms/shared/proxy"
)

// Platform implements the platforms.Platform interface for Azure DevOps
type Platform struct {
	client *Client
	config platforms.Config
}

// NewPlatform creates a new Azure DevOps platform adapter
func NewPlatform() *Platform {
	return &Platform{}
}

// Name returns the platform identifier
func (p *Platform) Name() string {
	return "azuredevops"
}

// Init initializes the platform with configuration
func (p *Platform) Init(ctx context.Context, config platforms.Config) error {
	p.config = config

	// Azure DevOps requires organization URL in BaseURL
	orgURL := config.BaseURL
	if orgURL == "" && config.AzureDevOps != nil {
		// Construct from organization name
		orgURL = fmt.Sprintf("https://dev.azure.com/%s", config.AzureDevOps.Organization)
	}

	if orgURL == "" {
		return fmt.Errorf("missing Azure DevOps organization URL (set BaseURL or AzureDevOps.Organization)")
	}

	// Get PAT from config
	pat := config.Token
	if pat == "" && config.AzureDevOps != nil {
		pat = config.AzureDevOps.PAT
	}

	// Check for bearer token (Entra ID OAuth)
	var bearerToken string
	if config.AzureDevOps != nil {
		bearerToken = config.AzureDevOps.BearerToken
	}

	// Require at least one auth method
	if pat == "" && bearerToken == "" {
		return fmt.Errorf("missing Azure DevOps authentication (set Token, AzureDevOps.PAT, or AzureDevOps.BearerToken)")
	}

	// Build client options from config
	var opts []ClientOption
	if bearerToken != "" {
		opts = append(opts, WithBearerToken(bearerToken))
	}
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

	p.client = NewClient(orgURL, pat, opts...)
	return nil
}

// Client returns the underlying Azure DevOps client
func (p *Platform) Client() *Client {
	return p.client
}

// Scan retrieves repositories and workflows from the target
func (p *Platform) Scan(ctx context.Context, target platforms.Target) (*platforms.ScanResult, error) {
	result := &platforms.ScanResult{
		Workflows: make(map[string][]platforms.Workflow),
	}

	var repositories []Repository

	switch target.Type {
	case platforms.TargetRepo:
		// Single repository: "project/repo"
		parts := strings.SplitN(target.Value, "/", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid repo format, expected project/repo: %s", target.Value)
		}
		projectName := parts[0]
		repoName := parts[1]

		repo, err := p.client.GetRepository(ctx, projectName, repoName)
		if err != nil {
			return nil, fmt.Errorf("getting repository: %w", err)
		}
		repositories = []Repository{*repo}

	case platforms.TargetOrg:
		// Enumerate all projects in the organization, then repos per project
		projects, err := p.client.ListProjects(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing projects: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Found %d projects\n", len(projects))
		for _, proj := range projects {
			repos, err := p.client.ListRepositories(ctx, proj.Name)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Errorf("project %s: %w", proj.Name, err))
				continue
			}
			repositories = append(repositories, repos...)
		}

	default:
		return nil, fmt.Errorf("unsupported target type for Azure DevOps: %s (use 'repo' or 'org')", target.Type)
	}

	// Convert to platform-agnostic types and fetch pipeline workflows.
	for _, repo := range repositories {
		// Extract default branch ref (refs/heads/main -> main)
		defaultBranch := strings.TrimPrefix(repo.DefaultBranch, "refs/heads/")

		result.Repositories = append(result.Repositories, platforms.Repository{
			Owner:         repo.Project.Name,
			Name:          repo.Name,
			DefaultBranch: defaultBranch,
			Private:       repo.Project.Visibility != "public",
			Archived:      repo.IsDisabled,
			URL:           repo.WebURL,
		})

		// Discover all registered pipeline YAML files for this repository.
		workflows, err := p.getWorkflowsFromDefs(ctx, repo.Project.Name, repo.Name, repo.ID, defaultBranch)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("%s/%s: %w", repo.Project.Name, repo.Name, err))
			continue
		}

		if len(workflows) > 0 {
			repoSlug := fmt.Sprintf("%s/%s", repo.Project.Name, repo.Name)
			result.Workflows[repoSlug] = workflows
		}
	}

	return result, nil
}

// getWorkflow retrieves the azure-pipelines.yml file for a repository
func (p *Platform) getWorkflow(ctx context.Context, projectName, repoName, ref string) (*platforms.Workflow, error) {
	const ciFile = "azure-pipelines.yml"

	content, err := p.client.GetWorkflowFile(ctx, projectName, repoName, ciFile, ref)
	if err != nil {
		// If file doesn't exist, return nil (not all repositories have pipelines)
		if strings.Contains(err.Error(), "404") {
			return nil, nil
		}
		return nil, err
	}

	repoSlug := fmt.Sprintf("%s/%s", projectName, repoName)
	return &platforms.Workflow{
		Name:     ciFile,
		Path:     ciFile,
		Content:  content,
		RepoSlug: repoSlug,
	}, nil
}

// getWorkflowsFromDefs discovers all pipeline YAML files for a repository by:
// 1. Listing registered build definitions filtered by repositoryId
// 2. Fetching the full definition for each to get process.yamlFilename
// 3. Fetching the YAML file content for each unique path
//
// Falls back to azure-pipelines.yml if no definitions exist for the repo
// or if the build definitions API is unavailable.
func (p *Platform) getWorkflowsFromDefs(ctx context.Context, projectName, repoName, repoID, defaultBranch string) ([]platforms.Workflow, error) {
	defs, err := p.client.ListBuildDefinitionsByRepo(ctx, projectName, repoID)
	if err != nil {
		// Non-fatal: fall back to azure-pipelines.yml
		return p.getWorkflowFallback(ctx, projectName, repoName, defaultBranch)
	}

	seen := make(map[string]bool)
	var workflows []platforms.Workflow
	repoSlug := fmt.Sprintf("%s/%s", projectName, repoName)

	for _, def := range defs {
		// Fetch full definition to get process.yamlFilename (absent from list response)
		fullDef, err := p.client.GetBuildDefinition(ctx, projectName, def.ID)
		if err != nil || fullDef.Process.YamlFilename == "" {
			continue
		}

		yamlPath := fullDef.Process.YamlFilename
		if seen[yamlPath] {
			continue
		}
		seen[yamlPath] = true

		content, err := p.client.GetWorkflowFile(ctx, projectName, repoName, yamlPath, defaultBranch)
		if err != nil {
			continue
		}
		workflows = append(workflows, platforms.Workflow{
			Name:     fullDef.Name,
			Path:     yamlPath,
			Content:  content,
			RepoSlug: repoSlug,
		})
	}

	if len(workflows) == 0 {
		return p.getWorkflowFallback(ctx, projectName, repoName, defaultBranch)
	}
	return workflows, nil
}

// getWorkflowFallback fetches azure-pipelines.yml as a last resort when no
// registered build definitions are found or the API is unavailable.
func (p *Platform) getWorkflowFallback(ctx context.Context, projectName, repoName, defaultBranch string) ([]platforms.Workflow, error) {
	wf, err := p.getWorkflow(ctx, projectName, repoName, defaultBranch)
	if err != nil {
		return nil, err
	}
	if wf != nil {
		return []platforms.Workflow{*wf}, nil
	}
	return nil, nil
}

// Ensure Platform implements the interface
var _ platforms.Platform = (*Platform)(nil)
