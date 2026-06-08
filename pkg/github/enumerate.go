package github

import (
	"context"
	"fmt"
	"time"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// EnumerateToken validates the token and enumerates accessible organizations.
// This is the primary enumeration method for token reconnaissance.
func (p *Platform) EnumerateToken(ctx context.Context) (*TokenEnumerateResult, error) {
	result := &TokenEnumerateResult{
		Errors: make([]error, 0),
	}

	// Get token information (reuses existing method)
	tokenInfo, err := p.client.GetTokenInfo(ctx)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("getting token info: %w", err))
		return result, nil // Return partial result
	}
	result.TokenInfo = tokenInfo

	if tokenInfo.Type == TokenTypeGitHubApp {
		repos, selection, err := p.client.ListInstallationRepos(ctx)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("listing installation repos: %w", err))
		} else {
			result.AccessibleRepos = len(repos)
			result.RepositorySelection = selection
			// An installation lives on ONE account. Surface it as an org only when
			// owner.type == "Organization" (it may be a personal user account).
			seen := make(map[string]bool)
			for i := range repos {
				owner := repos[i].Owner
				if owner.Type == "Organization" && !seen[owner.Login] {
					seen[owner.Login] = true
					result.Organizations = append(result.Organizations, OrganizationInfo{Name: owner.Login})
				}
			}
		}
	} else {
		// Get organizations (reuses existing method)
		orgs, err := p.client.ListAuthenticatedUserOrgs(ctx)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("listing organizations: %w", err))
		} else {
			result.Organizations = make([]OrganizationInfo, len(orgs))
			for i, org := range orgs {
				result.Organizations[i] = OrganizationInfo{
					Name: org.Login,
					// URL and Role can be enhanced later with additional API calls
				}
			}
		}
	}

	// Get current rate limit status
	rl := p.client.RateLimiter()
	if rl != nil {
		result.RateLimit = &RateLimitInfo{
			Limit:     rl.Limit(),
			Remaining: rl.Remaining(),
			Reset:     time.Time{}, // TODO: Add Reset() accessor to RateLimiter
			Used:      rl.Limit() - rl.Remaining(),
		}
	}

	return result, nil
}

// EnumerateRepos discovers repositories accessible to the authenticated token.
// Supports org, user, and self-enumeration with permission filtering.
func (p *Platform) EnumerateRepos(ctx context.Context, target platforms.Target) (*ReposEnumerateResult, error) {
	result := &ReposEnumerateResult{
		Repositories: make([]RepositoryWithPermissions, 0),
		Errors:       make([]error, 0),
	}

	var repos []Repository
	var err error

	// Fetch repositories based on target type
	switch target.Type {
	case platforms.TargetOrg:
		repos, err = p.client.ListOrgRepos(ctx, target.Value)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("listing org repos: %w", err))
			return result, nil
		}

	case platforms.TargetUser:
		if target.Value == "" {
			// Empty user = authenticated user = enumerate ALL accessible repos (user + all orgs)
			repos, err = p.enumerateAllAccessibleRepos(ctx)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Errorf("enumerating accessible repos: %w", err))
				return result, nil
			}
		} else {
			// Specific user = just that user's public repos
			repos, err = p.client.ListUserRepos(ctx, target.Value)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Errorf("listing user repos: %w", err))
				return result, nil
			}
		}

	case platforms.TargetRepo:
		// Single repo - just get that one
		parts := parseRepoSlug(target.Value)
		if len(parts) != 2 {
			result.Errors = append(result.Errors, fmt.Errorf("invalid repo format: %s", target.Value))
			return result, nil
		}
		repo, err := p.client.GetRepository(ctx, parts[0], parts[1])
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("getting repository: %w", err))
			return result, nil
		}
		repos = []Repository{*repo}

	default:
		// Default: Enumerate all accessible repos for authenticated user
		// This combines direct repos + all org repos
		repos, err = p.enumerateAllAccessibleRepos(ctx)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("enumerating accessible repos: %w", err))
			return result, nil
		}
	}

	// Convert to RepositoryWithPermissions format (preserves permission data)
	for _, repo := range repos {
		result.Repositories = append(result.Repositories, RepositoryWithPermissions{
			Repository: platforms.Repository{
				Owner:         repo.Owner.Login,
				Name:          repo.Name,
				DefaultBranch: repo.DefaultBranch,
				Private:       repo.Private,
				Archived:      repo.Archived,
				URL:           repo.HTMLURL,
			},
			Permissions: RepositoryPermissions{
				Admin: repo.Permissions.Admin,
				Push:  repo.Permissions.Push,
				Pull:  repo.Permissions.Pull,
			},
		})
	}

	// Build summary statistics
	result.Summary = buildReposSummary(result.Repositories)

	return result, nil
}

// buildReposSummary generates summary statistics from repository list
func buildReposSummary(repos []RepositoryWithPermissions) ReposSummary {
	summary := ReposSummary{
		Total: len(repos),
	}

	for _, repo := range repos {
		if repo.Repository.Private {
			summary.Private++
		} else {
			summary.Public++
		}

		if repo.Repository.Archived {
			summary.Archived++
		}

		if repo.Permissions.Push || repo.Permissions.Admin {
			summary.WriteAccess++
		} else if repo.Permissions.Pull {
			summary.ReadAccess++
		}
	}

	return summary
}

// parseRepoSlug splits "owner/repo" into parts
func parseRepoSlug(slug string) []string {
	// Simple split - proper implementation would handle edge cases
	parts := make([]string, 0, 2)
	slashIdx := -1
	for i, c := range slug {
		if c == '/' {
			slashIdx = i
			break
		}
	}
	if slashIdx > 0 && slashIdx < len(slug)-1 {
		parts = append(parts, slug[:slashIdx], slug[slashIdx+1:])
	}
	return parts
}

// enumerateAllAccessibleRepos gets all repos accessible to authenticated user
// by combining direct repos + repos from all organizations
func (p *Platform) enumerateAllAccessibleRepos(ctx context.Context) ([]Repository, error) {
	// GitHub App installation tokens have no user/orgs; the installation's repo set
	// IS the full accessible scope.
	if p.client.IsGitHubAppToken() {
		repos, _, err := p.client.ListInstallationRepos(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing installation repos: %w", err)
		}
		return repos, nil
	}

	// Get organizations user belongs to FIRST
	orgs, err := p.client.ListAuthenticatedUserOrgs(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing user orgs: %w", err)
	}

	// Combine repos into a map for deduplication (by full repo name)
	repoMap := make(map[string]Repository)

	// Enumerate each organization's repos explicitly
	// This ensures we get ALL org repos (matching --org behavior)
	for _, org := range orgs {
		orgRepos, err := p.client.ListOrgRepos(ctx, org.Login)
		if err != nil {
			// Continue on error - user might not have access to some orgs (e.g., SAML protected)
			continue
		}

		for _, repo := range orgRepos {
			key := repo.Owner.Login + "/" + repo.Name
			repoMap[key] = repo
		}
	}

	// Also get user's direct repos (owned + collaborator outside orgs)
	userRepos, err := p.client.ListUserRepos(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("listing user repos: %w", err)
	}

	// Add user repos that aren't already in the map
	for _, repo := range userRepos {
		key := repo.Owner.Login + "/" + repo.Name
		if _, exists := repoMap[key]; !exists {
			repoMap[key] = repo
		}
	}

	// Convert map back to slice
	allRepos := make([]Repository, 0, len(repoMap))
	for _, repo := range repoMap {
		allRepos = append(allRepos, repo)
	}

	return allRepos, nil
}
