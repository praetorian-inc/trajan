// pkg/platforms/jfrog/tokenprobe/types.go
package tokenprobe

import "time"

// TokenType represents the type of JFrog token
type TokenType string

const (
	TokenTypeFederation  TokenType = "federation_token" // JFrog Federation Token (JWT)
	TokenTypeAccessToken TokenType = "access_token"     // JFrog Access Token
	TokenTypeAPIKey      TokenType = "api_key"          // Deprecated API Key
	TokenTypeBasicAuth   TokenType = "basic_auth"       // Username/Password auth
	TokenTypeUnknown     TokenType = "unknown"
)

// Capability represents a JFrog token capability detected via API probing
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

// ProbeResult contains the results of JFrog token capability probing
type ProbeResult struct {
	// Valid indicates if the token is valid (authenticated successfully)
	Valid bool

	// Token information
	TokenType TokenType
	Scope     string
	ExpiresAt *time.Time

	// User information
	User *User

	// Capabilities detected via API probing
	Capabilities []Capability

	// Platform information
	Version string
	License string
	AddOns  []string // Installed add-ons

	// Repository summary
	RepositoryCount    int
	RepositoriesByType map[string]int // local, remote, virtual, federated
	Repositories       []Repository

	// Build information
	BuildCount int
	Builds     []string // Build names

	// Access control
	Groups      []Group
	Permissions []Permission

	// High-value indicators
	IsAdmin              bool
	HasRemoteCredentials bool
	HasBuildSecrets      bool
}

// User represents JFrog user information
type User struct {
	Name   string
	Email  string
	Admin  bool
	Groups []string
}

// Repository represents a JFrog repository with type
type Repository struct {
	Key         string
	Type        string // LOCAL, REMOTE, VIRTUAL, FEDERATED
	PackageType string
}

// Group represents a JFrog user group
type Group struct {
	Name        string
	Description string
	AutoJoin    bool
	Realm       string
}

// Permission represents a JFrog permission target
type Permission struct {
	Name string
	URI  string
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

// addCapability adds a capability to the result if not already present
func (r *ProbeResult) addCapability(cp Capability) {
	if !r.HasCapability(cp) {
		r.Capabilities = append(r.Capabilities, cp)
	}
}

// HasHighValueAccess returns true if token has access to high-value resources
// High-value: admin access, remote repo credentials, build secrets
func (r *ProbeResult) HasHighValueAccess() bool {
	return r.IsAdmin || r.HasRemoteCredentials || r.HasBuildSecrets
}
