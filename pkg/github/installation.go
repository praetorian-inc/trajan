package github

import (
	"context"
	"fmt"
)

// InstallationReposResponse wraps GET /installation/repositories.
// repository_selection is "all" or "selected".
type InstallationReposResponse struct {
	TotalCount          int          `json:"total_count"`
	RepositorySelection string       `json:"repository_selection"`
	Repositories        []Repository `json:"repositories"`
}

// IsGitHubAppToken reports whether this client's token is a GitHub App installation token.
func (c *Client) IsGitHubAppToken() bool {
	return IsAppToken(c.token)
}

// ListInstallationRepos lists repositories accessible to the app installation.
// Works with a bare ghs_ installation token (needs only Metadata: read).
// Pagination terminates on total_count (robust against exact-multiple page sizes).
// Returns the repositories and the repository_selection ("all"|"selected").
func (c *Client) ListInstallationRepos(ctx context.Context) ([]Repository, string, error) {
	var all []Repository
	selection := ""
	page := 1
	perPage := 100

	for {
		var resp InstallationReposResponse
		path := fmt.Sprintf("/installation/repositories?per_page=%d&page=%d", perPage, page)
		if err := c.get(ctx, path, &resp); err != nil {
			return nil, "", fmt.Errorf("listing installation repos: %w", err)
		}
		selection = resp.RepositorySelection
		all = append(all, resp.Repositories...)

		// Stop when we have them all, or the page returned nothing.
		if len(resp.Repositories) == 0 || len(all) >= resp.TotalCount {
			break
		}
		page++
	}

	return all, selection, nil
}
