package tokenprobe

// Capability represents an Azure DevOps PAT capability detected via API probing
// Unlike GitHub's fine-grained scopes, Azure DevOps uses coarser permission levels
type Capability string

const (
	// Read capabilities
	CapabilityIdentityRead           Capability = "identity:read"
	CapabilityProjectsRead           Capability = "projects:read"
	CapabilityRepositoriesRead       Capability = "repositories:read"
	CapabilityPipelinesRead          Capability = "pipelines:read"
	CapabilityAgentPoolsRead         Capability = "agent_pools:read"
	CapabilityVariableGroupsRead     Capability = "variable_groups:read"
	CapabilityServiceConnectionsRead Capability = "service_connections:read"
	CapabilityArtifactsRead          Capability = "artifacts:read"
)

// ProbeResult contains the results of Azure DevOps PAT capability probing
type ProbeResult struct {
	// Valid indicates if the PAT is valid (authenticated successfully)
	Valid bool

	// User information from the profile endpoint
	User *User

	// Capabilities detected for the PAT
	Capabilities []Capability

	// Projects accessible with this PAT
	Projects []Project

	// Summary counts
	ProjectCount           int
	RepositoryCount        int
	PipelineCount          int
	AgentPoolCount         int
	VariableGroupCount     int
	ServiceConnectionCount int
	ArtifactFeedCount      int

	// High-value indicators
	HasSecretVariables  bool
	HasSelfHostedAgents bool
}

// User represents Azure DevOps user information
type User struct {
	ID          string
	DisplayName string
	Email       string
}

// Project represents a minimal project for enumeration results
type Project struct {
	ID         string
	Name       string
	Visibility string
}

// HasCapability checks if a capability was detected
func (r *ProbeResult) HasCapability(cp Capability) bool {
	for _, c := range r.Capabilities {
		if c == cp {
			return true
		}
	}
	return false
}

// HasHighValueAccess returns true if PAT has access to high-value resources
// High-value: pipelines, variable groups (secrets), service connections, self-hosted agents
func (r *ProbeResult) HasHighValueAccess() bool {
	highValueCaps := []Capability{
		CapabilityPipelinesRead,
		CapabilityVariableGroupsRead,
		CapabilityServiceConnectionsRead,
		CapabilityAgentPoolsRead,
	}
	for _, cap := range highValueCaps {
		if r.HasCapability(cap) {
			return true
		}
	}
	return r.HasSecretVariables || r.HasSelfHostedAgents
}
