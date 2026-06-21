// pkg/platforms/jfrog/tokenprobe/prober.go
package tokenprobe

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/praetorian-inc/trajan/pkg/jfrog"
)

// JFrogClient defines the interface required by TokenProber from client.go
type JFrogClient interface {
	GetUser(ctx context.Context) (*jfrog.User, error)
	GetSystemInfo(ctx context.Context) (map[string]interface{}, error)
	Get(ctx context.Context, path string) (*http.Response, error)
}

// JFrogPlatform defines the interface required from Platform methods
type JFrogPlatform interface {
	ExtractRemoteRepoCredentials(ctx context.Context) ([]jfrog.RemoteRepoCredentials, error)
	GetLDAPConfig(ctx context.Context) ([]jfrog.LDAPSetting, error)
	ScanBuildsForSecrets(ctx context.Context, limit int) ([]jfrog.BuildSecret, error)
}

// TokenProber probes JFrog token capabilities via API calls
type TokenProber struct {
	client   JFrogClient
	platform JFrogPlatform
}

// NewProber creates a new JFrog token prober
func NewProber(client JFrogClient, platform JFrogPlatform) *TokenProber {
	return &TokenProber{
		client:   client,
		platform: platform,
	}
}

// Probe enumerates the capabilities of the configured token
func (p *TokenProber) Probe(ctx context.Context) (*ProbeResult, error) {
	result := &ProbeResult{
		Capabilities:       make([]Capability, 0),
		RepositoriesByType: make(map[string]int),
		Repositories:       make([]Repository, 0),
		Builds:             make([]string, 0),
		Groups:             make([]Group, 0),
		Permissions:        make([]Permission, 0),
		AddOns:             make([]string, 0),
	}

	// Step 1: Validate token by getting user info
	user, err := p.client.GetUser(ctx)
	if err != nil {
		result.Valid = false
		return result, nil
	}

	result.Valid = true
	result.addCapability(CapabilityIdentityRead)
	result.User = &User{
		Name:   user.Name,
		Email:  user.Email,
		Admin:  user.Admin,
		Groups: user.Groups,
	}
	result.IsAdmin = user.Admin

	// Step 2: Get system info (version, license, addons)
	sysInfo, err := p.client.GetSystemInfo(ctx)
	if err == nil {
		if version, ok := sysInfo["version"].(string); ok {
			result.Version = version
		}
		if licenseType, ok := sysInfo["licenseType"].(string); ok {
			result.License = licenseType
		}
		if addons, ok := sysInfo["addons"].([]interface{}); ok {
			for _, addon := range addons {
				if addonStr, ok := addon.(string); ok {
					result.AddOns = append(result.AddOns, addonStr)
				}
			}
		}
	}

	// Step 3: Probe resources concurrently
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(10)

	// List repositories
	g.Go(func() error {
		repos, err := p.listRepositories(gctx)
		if err == nil && len(repos) > 0 {
			mu.Lock()
			result.addCapability(CapabilityRepositoriesRead)
			result.RepositoryCount = len(repos)
			result.Repositories = repos

			// Count by type
			for _, repo := range repos {
				result.RepositoriesByType[repo.Type]++
			}
			mu.Unlock()
		}
		return nil
	})

	// List builds
	g.Go(func() error {
		builds, err := p.listBuilds(gctx)
		if err == nil && len(builds) > 0 {
			mu.Lock()
			result.addCapability(CapabilityBuildsRead)
			result.BuildCount = len(builds)
			result.Builds = builds
			mu.Unlock()
		}
		return nil
	})

	// List users (admin only)
	g.Go(func() error {
		_, err := p.listUsers(gctx)
		if err == nil {
			mu.Lock()
			result.addCapability(CapabilityUsersRead)
			mu.Unlock()
		}
		return nil
	})

	// List groups
	g.Go(func() error {
		groups, err := p.listGroups(gctx)
		if err == nil && len(groups) > 0 {
			mu.Lock()
			result.addCapability(CapabilityGroupsRead)
			result.Groups = groups
			mu.Unlock()
		}
		return nil
	})

	// List permissions
	g.Go(func() error {
		perms, err := p.listPermissions(gctx)
		if err == nil && len(perms) > 0 {
			mu.Lock()
			result.addCapability(CapabilityPermissionsRead)
			result.Permissions = perms
			mu.Unlock()
		}
		return nil
	})

	// Check LDAP config (admin only)
	g.Go(func() error {
		_, err := p.platform.GetLDAPConfig(gctx)
		if err == nil {
			mu.Lock()
			result.addCapability(CapabilityConfigRead)
			mu.Unlock()
		}
		return nil
	})

	// Remote repo credentials
	g.Go(func() error {
		creds, _ := p.platform.ExtractRemoteRepoCredentials(gctx)
		if len(creds) > 0 {
			mu.Lock()
			result.addCapability(CapabilityRemoteCredentials)
			// Check if any have credentials
			for _, cred := range creds {
				if cred.HasCreds {
					result.HasRemoteCredentials = true
					break
				}
			}
			mu.Unlock()
		}
		return nil
	})

	// Scan builds for secrets
	g.Go(func() error {
		secrets, _ := p.platform.ScanBuildsForSecrets(gctx, 5)
		if len(secrets) > 0 {
			mu.Lock()
			result.HasBuildSecrets = true
			mu.Unlock()
		}
		return nil
	})

	_ = g.Wait()

	return result, nil
}

// listRepositories retrieves all repositories
func (p *TokenProber) listRepositories(ctx context.Context) ([]Repository, error) {
	resp, err := p.client.Get(ctx, "/api/repositories")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	var jfrogRepos []jfrog.Repository
	if err := json.NewDecoder(resp.Body).Decode(&jfrogRepos); err != nil {
		return nil, err
	}

	repos := make([]Repository, len(jfrogRepos))
	for i, r := range jfrogRepos {
		repos[i] = Repository{
			Key:         r.Key,
			Type:        r.Type,
			PackageType: r.PackageType,
		}
	}

	return repos, nil
}

// listBuilds retrieves build names
func (p *TokenProber) listBuilds(ctx context.Context) ([]string, error) {
	resp, err := p.client.Get(ctx, "/api/build")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	var buildList struct {
		Builds []struct {
			URI string `json:"uri"`
		} `json:"builds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&buildList); err != nil {
		return nil, err
	}

	builds := make([]string, len(buildList.Builds))
	for i, build := range buildList.Builds {
		// Extract build name from URI (format: /build-name)
		name := build.URI
		if len(name) > 0 && name[0] == '/' {
			name = name[1:]
		}
		builds[i] = name
	}

	return builds, nil
}

// listUsers checks if user listing is accessible (admin only)
func (p *TokenProber) listUsers(ctx context.Context) (bool, error) {
	resp, err := p.client.Get(ctx, "/api/security/users")
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	return resp.StatusCode == http.StatusOK, nil
}

// listGroups retrieves all groups
func (p *TokenProber) listGroups(ctx context.Context) ([]Group, error) {
	resp, err := p.client.Get(ctx, "/api/security/groups")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	var jfrogGroups []jfrog.Group
	if err := json.NewDecoder(resp.Body).Decode(&jfrogGroups); err != nil {
		return nil, err
	}

	groups := make([]Group, len(jfrogGroups))
	for i, g := range jfrogGroups {
		groups[i] = Group{
			Name:        g.Name,
			Description: g.Description,
			AutoJoin:    g.AutoJoin,
			Realm:       g.Realm,
		}
	}

	return groups, nil
}

// listPermissions retrieves permission targets
func (p *TokenProber) listPermissions(ctx context.Context) ([]Permission, error) {
	resp, err := p.client.Get(ctx, "/api/security/permissions")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	// JFrog API returns an array of {name, uri} objects
	var permList []struct {
		Name string `json:"name"`
		URI  string `json:"uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&permList); err != nil {
		return nil, err
	}

	perms := make([]Permission, 0, len(permList))
	for _, p := range permList {
		perms = append(perms, Permission{Name: p.Name, URI: p.URI})
	}

	return perms, nil
}
