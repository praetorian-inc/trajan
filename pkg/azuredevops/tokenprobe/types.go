package tokenprobe

// Unlike GitHub's fine-grained scopes, Azure DevOps uses coarser permission levels
type Capability string

const (
	CapabilityIdentityRead           Capability = "identity:read"
	CapabilityProjectsRead           Capability = "projects:read"
	CapabilityRepositoriesRead       Capability = "repositories:read"
	CapabilityPipelinesRead          Capability = "pipelines:read"
	CapabilityAgentPoolsRead         Capability = "agent_pools:read"
	CapabilityVariableGroupsRead     Capability = "variable_groups:read"
	CapabilityServiceConnectionsRead Capability = "service_connections:read"
	CapabilityArtifactsRead          Capability = "artifacts:read"
)

type ProbeResult struct {
	Valid bool

	User *User

	Capabilities []Capability

	Projects []Project

	ProjectCount           int
	RepositoryCount        int
	PipelineCount          int
	AgentPoolCount         int
	VariableGroupCount     int
	ServiceConnectionCount int
	ArtifactFeedCount      int

	HasSecretVariables  bool
	HasSelfHostedAgents bool
}

type User struct {
	ID          string
	DisplayName string
	Email       string
}

type Project struct {
	ID         string
	Name       string
	Visibility string
}

func (r *ProbeResult) HasCapability(cp Capability) bool {
	for _, c := range r.Capabilities {
		if c == cp {
			return true
		}
	}
	return false
}

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
