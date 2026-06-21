package gitlab

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// EnumerateToken validates the token and returns comprehensive token information.
func (p *Platform) EnumerateToken(ctx context.Context) (*TokenEnumerateResult, error) {
	result := &TokenEnumerateResult{}

	// Get user info
	user, err := p.client.GetUser(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "getting user: "+err.Error())
		return result, nil
	}
	result.User = user
	result.IsAdmin = user.IsAdmin
	result.IsBot = user.Bot
	result.CanCreateGroup = user.CanCreateGroup
	result.CanCreateProject = user.CanCreateProject

	// Get personal access token info (may fail for project/group tokens)
	pat, err := p.client.GetPersonalAccessToken(ctx)
	if err != nil {
		// Not fatal - project/group tokens can't access this endpoint
		result.Errors = append(result.Errors, "getting token info: "+err.Error())
	} else {
		result.Token = pat
	}

	// Detect token type from user info
	result.TokenType = detectTokenType(user, pat)

	// Get accessible groups
	groups, err := p.client.ListGroups(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "listing groups: "+err.Error())
	} else {
		result.Groups = make([]GroupInfo, len(groups))
		for i, g := range groups {
			result.Groups[i] = GroupInfo{
				Name:     g.Name,
				FullPath: g.FullPath,
				ID:       g.ID,
			}
		}
	}

	// Get rate limit info
	rl := p.client.rateLimiter
	if rl != nil {
		result.RateLimit = &RateLimitInfo{
			Limit:     rl.Limit(),
			Remaining: rl.Remaining(),
		}
	}

	return result, nil
}

// detectTokenType determines the token type from API responses.
// See design doc: Token Type Detection section.
func detectTokenType(user *User, pat *PersonalAccessToken) string {
	if user == nil {
		return "unknown"
	}

	if user.Bot {
		if strings.HasPrefix(user.Username, "project_") && strings.Contains(user.Username, "_bot_") {
			return "project_access_token"
		}
		if strings.HasPrefix(user.Username, "group_") && strings.Contains(user.Username, "_bot_") {
			return "group_access_token"
		}
		return "bot_token"
	}

	if pat != nil {
		return "personal_access_token"
	}

	return "unknown"
}

// EnumerateProjects discovers projects accessible to the authenticated token.
func (p *Platform) EnumerateProjects(ctx context.Context, target platforms.Target) (*ProjectsEnumerateResult, error) {
	result := &ProjectsEnumerateResult{
		Projects: make([]ProjectWithPermissions, 0),
	}

	var projects []Project
	var err error
	needExplicitAccessLevels := false

	switch target.Type {
	case platforms.TargetOrg:
		projects, err = p.client.ListGroupProjects(ctx, target.Value)
		if err != nil {
			result.Errors = append(result.Errors, "listing group projects: "+err.Error())
			return result, nil
		}
		needExplicitAccessLevels = true // Group projects may not have accurate permissions
	default:
		// Default: member projects
		projects, err = p.client.ListMemberProjects(ctx)
		if err != nil {
			result.Errors = append(result.Errors, "listing member projects: "+err.Error())
			return result, nil
		}
	}

	// Get user ID for access level lookups (only if needed)
	var userID int
	if needExplicitAccessLevels {
		user, err := p.client.GetUser(ctx)
		if err != nil {
			result.Errors = append(result.Errors, "getting user: "+err.Error())
			needExplicitAccessLevels = false // Fall back to permissions from API
		} else {
			userID = user.ID
		}
	}

	for i := range projects {
		proj := &projects[i]
		var accessLevel int
		if needExplicitAccessLevels {
			// Try to get direct project access level first
			level, err := p.client.GetProjectAccessLevel(ctx, proj.ID, userID)
			if err == nil {
				accessLevel = level
			} else {
				// User not a direct project member - check group access
				// Use the project's actual namespace (the group that owns it)
				if proj.Namespace.FullPath != "" {
					group, err := p.client.GetGroup(ctx, proj.Namespace.FullPath)
					if err == nil {
						groupLevel, err := p.client.GetGroupAccessLevel(ctx, group.ID, userID)
						if err == nil {
							accessLevel = groupLevel
						}
					}
				}
				// If still no access level, fall back to API permissions
				if accessLevel == 0 {
					accessLevel = getEffectiveAccessLevel(proj.Permissions)
				}
			}
		} else {
			accessLevel = getEffectiveAccessLevel(proj.Permissions)
		}

		owner := proj.Namespace.FullPath
		if owner == "" {
			owner = proj.Namespace.Name
		}

		result.Projects = append(result.Projects, ProjectWithPermissions{
			Repository: platforms.Repository{
				Owner:         owner,
				Name:          proj.Path,
				DefaultBranch: proj.DefaultBranch,
				Private:       proj.Visibility == "private",
				Archived:      proj.Archived,
				URL:           proj.WebURL,
			},
			AccessLevel:  accessLevel,
			Visibility:   proj.Visibility,
			LastActivity: "", // populated if available
		})
	}

	result.Summary = buildProjectsSummary(result.Projects)
	return result, nil
}

// getEffectiveAccessLevel returns the highest access level from project and group access.
func getEffectiveAccessLevel(perms *ProjectPermissions) int {
	if perms == nil {
		return 0
	}
	level := 0
	if perms.ProjectAccess != nil && perms.ProjectAccess.AccessLevel > level {
		level = perms.ProjectAccess.AccessLevel
	}
	if perms.GroupAccess != nil && perms.GroupAccess.AccessLevel > level {
		level = perms.GroupAccess.AccessLevel
	}
	return level
}

// buildProjectsSummary generates summary statistics from project list.
func buildProjectsSummary(projects []ProjectWithPermissions) ProjectsSummary {
	s := ProjectsSummary{Total: len(projects)}
	for _, p := range projects {
		switch p.Visibility {
		case "private":
			s.Private++
		case "internal":
			s.Internal++
		case "public":
			s.Public++
		}
		if p.Archived {
			s.Archived++
		}
		if p.AccessLevel >= 30 { // Developer+ = write
			s.WriteAccess++
		} else if p.AccessLevel > 0 {
			s.ReadAccess++
		}
	}
	return s
}

// EnumerateGroups discovers groups accessible to the authenticated token.
// When recursive is true, subgroups are also enumerated.
func (p *Platform) EnumerateGroups(ctx context.Context, recursive bool) (*GroupsEnumerateResult, error) {
	result := &GroupsEnumerateResult{
		Groups: make([]GroupWithAccess, 0),
	}

	// Get current user ID for access level lookups
	user, err := p.client.GetUser(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "getting user: "+err.Error())
		return result, nil
	}

	// Get all groups (GitLab /groups API returns all groups including subgroups)
	groups, err := p.client.ListGroups(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "listing groups: "+err.Error())
		return result, nil
	}

	// Collect groups to process
	var allGroups []Group
	if recursive {
		// Explicitly enumerate subgroups via /subgroups endpoint
		// Start with top-level groups only
		for _, g := range groups {
			if g.ParentID == nil {
				allGroups = append(allGroups, g)
			}
		}

		// Recursively discover subgroups
		for i := 0; i < len(allGroups); i++ {
			subgroups, err := p.client.ListSubgroups(ctx, allGroups[i].ID)
			if err != nil {
				result.Errors = append(result.Errors, "listing subgroups for "+allGroups[i].FullPath+": "+err.Error())
				continue
			}
			allGroups = append(allGroups, subgroups...)
		}
	} else {
		// Non-recursive: only top-level groups (ParentID == nil)
		for _, g := range groups {
			if g.ParentID == nil {
				allGroups = append(allGroups, g)
			}
		}
	}

	// Get access levels and shared groups for each group
	seen := make(map[int]bool) // track by ID to avoid duplicates
	var sharedGroups []GroupWithAccess

	// First pass: add all direct groups with access levels
	for _, group := range allGroups {
		if seen[group.ID] {
			continue
		}
		seen[group.ID] = true

		accessLevel := 0
		level, err := p.client.GetGroupAccessLevel(ctx, group.ID, user.ID)
		if err == nil {
			accessLevel = level
		}

		result.Groups = append(result.Groups, GroupWithAccess{
			Group:       group,
			AccessLevel: accessLevel,
			Shared:      false,
		})

		// Discover shared groups for later addition
		shared, err := p.client.ListSharedGroups(ctx, group.ID)
		if err != nil {
			// Non-fatal - may not have permission
			continue
		}

		for _, sg := range shared {
			if seen[sg.ID] {
				continue
			}
			seen[sg.ID] = true

			sharedGroups = append(sharedGroups, GroupWithAccess{
				Group: Group{
					ID:         sg.ID,
					Name:       sg.Name,
					FullPath:   sg.FullPath,
					Visibility: sg.Visibility,
				},
				AccessLevel: sg.GroupAccessLevel,
				Shared:      true,
				SharedVia:   group.FullPath,
			})
		}
	}

	// Second pass: add all shared groups
	result.Groups = append(result.Groups, sharedGroups...)

	return result, nil
}

// EnumerateSecrets discovers CI/CD variables at project, group, and instance level.
func (p *Platform) EnumerateSecrets(ctx context.Context, target platforms.Target) (*SecretsEnumerateResult, error) {
	result := &SecretsEnumerateResult{
		ProjectVariables: make(map[string][]Variable),
		GroupVariables:   make(map[string][]Variable),
	}

	switch target.Type {
	case platforms.TargetRepo:
		// Single project
		project, err := p.client.GetProject(ctx, target.Value)
		if err != nil {
			result.Errors = append(result.Errors, "getting project: "+err.Error())
			return result, nil
		}
		p.enumerateProjectVariables(ctx, result, project)

	case platforms.TargetOrg:
		// Group: get group variables + all project variables
		group, err := p.client.GetGroup(ctx, target.Value)
		if err != nil {
			result.Errors = append(result.Errors, "getting group: "+err.Error())
			return result, nil
		}

		// Group-level variables
		groupVars, err := p.client.ListGroupVariables(ctx, group.ID)
		if err != nil {
			result.PermissionErrors = append(result.PermissionErrors,
				fmt.Sprintf("GET /groups/%d/variables: %s", group.ID, err.Error()))
		} else {
			result.GroupVariables[group.FullPath] = groupVars
		}

		// Project-level variables for each project in the group
		projects, err := p.client.ListGroupProjects(ctx, target.Value)
		if err != nil {
			result.Errors = append(result.Errors, "listing group projects: "+err.Error())
		} else {
			for i := range projects {
				proj := &projects[i]
				p.enumerateProjectVariables(ctx, result, proj)
			}
		}

	default:
		result.Errors = append(result.Errors, "must specify --project or --group")
		return result, nil
	}

	// Always try instance-level variables (requires admin)
	instanceVars, err := p.client.ListInstanceVariables(ctx)
	if err != nil {
		// 403 is expected for non-admin users - don't show as error
		if !IsPermissionError(err) {
			result.PermissionErrors = append(result.PermissionErrors,
				fmt.Sprintf("GET /admin/ci/variables: %s", err.Error()))
		}
	} else {
		result.InstanceVariables = instanceVars
	}

	return result, nil
}

// enumerateProjectVariables fetches CI/CD variables for a single project.
func (p *Platform) enumerateProjectVariables(ctx context.Context, result *SecretsEnumerateResult, project *Project) {
	vars, err := p.client.ListProjectVariables(ctx, project.ID)
	if err != nil {
		result.PermissionErrors = append(result.PermissionErrors,
			fmt.Sprintf("GET /projects/%d/variables: %s", project.ID, err.Error()))
		return
	}
	if len(vars) > 0 {
		result.ProjectVariables[project.PathWithNamespace] = vars
	}
}
