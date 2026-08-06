package tokenprobe

import "time"

type TokenType string

const (
	TokenTypeFederation  TokenType = "federation_token"
	TokenTypeAccessToken TokenType = "access_token"
	TokenTypeAPIKey      TokenType = "api_key"
	TokenTypeBasicAuth   TokenType = "basic_auth"
	TokenTypeUnknown     TokenType = "unknown"
)

type Capability string

const (
	CapabilityIdentityRead      Capability = "identity:read"      // /api/v1/system/security/users/current
	CapabilityRepositoriesRead  Capability = "repositories:read"  // /api/repositories
	CapabilityBuildsRead        Capability = "builds:read"        // /api/build
	CapabilityArtifactsRead     Capability = "artifacts:read"     // AQL queries
	CapabilityUsersRead         Capability = "users:read"         // /api/security/users (admin)
	CapabilityGroupsRead        Capability = "groups:read"        // /api/security/groups
	CapabilityPermissionsRead   Capability = "permissions:read"   // /api/security/permissions
	CapabilityConfigRead        Capability = "config:read"        // /api/system/configuration (admin)
	CapabilityRemoteCredentials Capability = "remote_credentials" // Remote repo credentials
)

type ProbeResult struct {
	Valid bool

	// Token information
	TokenType TokenType
	Scope     string
	ExpiresAt *time.Time

	User *User

	Capabilities []Capability

	// Platform information
	Version string
	License string
	AddOns  []string

	RepositoryCount    int
	RepositoriesByType map[string]int // local, remote, virtual, federated
	Repositories       []Repository

	BuildCount int
	Builds     []string // Build names

	Groups      []Group
	Permissions []Permission

	// High-value indicators
	IsAdmin              bool
	HasRemoteCredentials bool
	HasBuildSecrets      bool
}

type User struct {
	Name   string
	Email  string
	Admin  bool
	Groups []string
}

type Repository struct {
	Key         string
	Type        string // LOCAL, REMOTE, VIRTUAL, FEDERATED
	PackageType string
}

type Group struct {
	Name        string
	Description string
	AutoJoin    bool
	Realm       string
}

type Permission struct {
	Name string
	URI  string
}

func (r *ProbeResult) HasCapability(cp Capability) bool {
	for _, c := range r.Capabilities {
		if c == cp {
			return true
		}
	}
	return false
}

func (r *ProbeResult) addCapability(cp Capability) {
	if !r.HasCapability(cp) {
		r.Capabilities = append(r.Capabilities, cp)
	}
}

func (r *ProbeResult) HasHighValueAccess() bool {
	return r.IsAdmin || r.HasRemoteCredentials || r.HasBuildSecrets
}
