// pkg/platforms/azuredevops/tokenprobe/prober.go
package tokenprobe

import (
	"context"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/praetorian-inc/trajan/pkg/azuredevops"
)

// AzureDevOpsClient defines the interface required by TokenProber
type AzureDevOpsClient interface {
	GetConnectionData(ctx context.Context) (*azuredevops.ConnectionData, error)
	ListProjects(ctx context.Context) ([]azuredevops.Project, error)
	ListRepositories(ctx context.Context, projectNameOrID string) ([]azuredevops.Repository, error)
	ListPipelines(ctx context.Context, projectNameOrID string) ([]azuredevops.Pipeline, error)
	ListAgentPools(ctx context.Context) ([]azuredevops.AgentPool, error)
	ListVariableGroups(ctx context.Context, projectNameOrID string) ([]azuredevops.VariableGroup, error)
	ListServiceConnections(ctx context.Context, projectNameOrID string) ([]azuredevops.ServiceConnection, error)
	ListArtifactFeeds(ctx context.Context) ([]azuredevops.ArtifactFeed, error)
}

// TokenProber probes Azure DevOps PAT capabilities via API calls
type TokenProber struct {
	client      AzureDevOpsClient
	feedsClient AzureDevOpsClient // optional: client for feeds.dev.azure.com; if nil, uses client
}

// NewProber creates a new Azure DevOps token prober
func NewProber(client AzureDevOpsClient) *TokenProber {
	return &TokenProber{client: client}
}

// SetFeedsClient sets a separate client for artifact feeds (feeds.dev.azure.com).
// If not set, the main client is used.
func (p *TokenProber) SetFeedsClient(fc AzureDevOpsClient) {
	p.feedsClient = fc
}

// Probe enumerates the capabilities of the configured PAT
func (p *TokenProber) Probe(ctx context.Context) (*ProbeResult, error) {
	result := &ProbeResult{
		Capabilities: make([]Capability, 0),
		Projects:     make([]Project, 0),
	}

	// Step 1: Validate PAT and get user info
	connData, err := p.client.GetConnectionData(ctx)
	if err != nil {
		result.Valid = false
		return result, nil
	}

	result.Valid = true
	result.addCapability(CapabilityIdentityRead)
	result.User = &User{
		ID:          connData.AuthenticatedUser.ID,
		DisplayName: connData.AuthenticatedUser.ProviderDisplayName,
	}

	// Step 2: List projects
	projects, err := p.client.ListProjects(ctx)
	if err == nil && len(projects) > 0 {
		result.addCapability(CapabilityProjectsRead)
		result.ProjectCount = len(projects)
		for _, proj := range projects {
			result.Projects = append(result.Projects, Project{
				ID:         proj.ID,
				Name:       proj.Name,
				Visibility: proj.Visibility,
			})
		}
	}

	// Step 3: Probe organization-level resources concurrently
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(10)

	// Agent pools
	g.Go(func() error {
		pools, err := p.client.ListAgentPools(gctx)
		if err == nil {
			mu.Lock()
			result.addCapability(CapabilityAgentPoolsRead)
			result.AgentPoolCount = len(pools)
			for _, pool := range pools {
				if !pool.IsHosted {
					result.HasSelfHostedAgents = true
					break
				}
			}
			mu.Unlock()
		}
		return nil
	})

	// Artifact feeds (uses feedsClient if set, otherwise main client)
	g.Go(func() error {
		fc := p.client
		if p.feedsClient != nil {
			fc = p.feedsClient
		}
		feeds, err := fc.ListArtifactFeeds(gctx)
		if err == nil {
			mu.Lock()
			result.addCapability(CapabilityArtifactsRead)
			result.ArtifactFeedCount = len(feeds)
			mu.Unlock()
		}
		return nil
	})

	_ = g.Wait()

	// Step 4: Probe per-project resources (ALL projects)
	if len(projects) > 0 {
		g2, gctx2 := errgroup.WithContext(ctx)
		g2.SetLimit(10)

		// Enumerate repositories across ALL projects
		for _, proj := range projects {
			projName := proj.Name // capture for closure
			g2.Go(func() error {
				repos, err := p.client.ListRepositories(gctx2, projName)
				if err == nil && len(repos) > 0 {
					mu.Lock()
					if !result.HasCapability(CapabilityRepositoriesRead) {
						result.addCapability(CapabilityRepositoriesRead)
					}
					result.RepositoryCount += len(repos)
					mu.Unlock()
				}
				return nil
			})
		}

		// Enumerate pipelines across ALL projects
		for _, proj := range projects {
			projName := proj.Name // capture for closure
			g2.Go(func() error {
				pipelines, err := p.client.ListPipelines(gctx2, projName)
				if err == nil && len(pipelines) > 0 {
					mu.Lock()
					if !result.HasCapability(CapabilityPipelinesRead) {
						result.addCapability(CapabilityPipelinesRead)
					}
					result.PipelineCount += len(pipelines)
					mu.Unlock()
				}
				return nil
			})
		}

		// Enumerate variable groups across ALL projects
		for _, proj := range projects {
			projName := proj.Name // capture for closure
			g2.Go(func() error {
				groups, err := p.client.ListVariableGroups(gctx2, projName)
				if err == nil && len(groups) > 0 {
					mu.Lock()
					if !result.HasCapability(CapabilityVariableGroupsRead) {
						result.addCapability(CapabilityVariableGroupsRead)
					}
					result.VariableGroupCount += len(groups)
					for _, group := range groups {
						for _, v := range group.Variables {
							if v.IsSecret {
								result.HasSecretVariables = true
								break
							}
						}
						if result.HasSecretVariables {
							break
						}
					}
					mu.Unlock()
				}
				return nil
			})
		}

		// Enumerate service connections across ALL projects
		for _, proj := range projects {
			projName := proj.Name // capture for closure
			g2.Go(func() error {
				conns, err := p.client.ListServiceConnections(gctx2, projName)
				if err == nil && len(conns) > 0 {
					mu.Lock()
					if !result.HasCapability(CapabilityServiceConnectionsRead) {
						result.addCapability(CapabilityServiceConnectionsRead)
					}
					result.ServiceConnectionCount += len(conns)
					mu.Unlock()
				}
				return nil
			})
		}

		_ = g2.Wait()
	}

	return result, nil
}

// addCapability adds a capability to the result if not already present
func (r *ProbeResult) addCapability(cp Capability) {
	if !r.HasCapability(cp) {
		r.Capabilities = append(r.Capabilities, cp)
	}
}
