package gitlab

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func (p *Platform) EnumerateToken(ctx context.Context) (*TokenEnumerateResult, error) {
	result := &TokenEnumerateResult{}

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

	pat, err := p.client.GetPersonalAccessToken(ctx)
	if err != nil {
		// Project and group tokens cannot read this endpoint.
		result.Errors = append(result.Errors, "getting token info: "+err.Error())
	} else {
		result.Token = pat
	}

	result.TokenType = detectTokenType(user, pat)

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

	rl := p.client.rateLimiter
	if rl != nil {
		result.RateLimit = &RateLimitInfo{
			Limit:     rl.Limit(),
			Remaining: rl.Remaining(),
		}
	}

	return result, nil
}

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
		projects, err = p.client.ListMemberProjects(ctx)
		if err != nil {
			result.Errors = append(result.Errors, "listing member projects: "+err.Error())
			return result, nil
		}
	}

	var userID int
	if needExplicitAccessLevels {
		user, err := p.client.GetUser(ctx)
		if err != nil {
			result.Errors = append(result.Errors, "getting user: "+err.Error())
			needExplicitAccessLevels = false // fall back to the API's permissions
		} else {
			userID = user.ID
		}
	}

	for i := range projects {
		proj := &projects[i]
		var accessLevel int
		if needExplicitAccessLevels {
			level, err := p.client.GetProjectAccessLevel(ctx, proj.ID, userID)
			if err == nil {
				accessLevel = level
			} else {
				// An error means the user is not a direct member, so try the owning group.
				if proj.Namespace.FullPath != "" {
					group, err := p.client.GetGroup(ctx, proj.Namespace.FullPath)
					if err == nil {
						groupLevel, err := p.client.GetGroupAccessLevel(ctx, group.ID, userID)
						if err == nil {
							accessLevel = groupLevel
						}
					}
				}
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
			LastActivity: "",
		})
	}

	result.Summary = buildProjectsSummary(result.Projects)
	return result, nil
}

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

func (p *Platform) EnumerateGroups(ctx context.Context, recursive bool) (*GroupsEnumerateResult, error) {
	result := &GroupsEnumerateResult{
		Groups: make([]GroupWithAccess, 0),
	}

	user, err := p.client.GetUser(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "getting user: "+err.Error())
		return result, nil
	}

	// GitLab's /groups returns subgroups too, hence the ParentID filtering below.
	groups, err := p.client.ListGroups(ctx)
	if err != nil {
		result.Errors = append(result.Errors, "listing groups: "+err.Error())
		return result, nil
	}

	var allGroups []Group
	if recursive {
		for _, g := range groups {
			if g.ParentID == nil {
				allGroups = append(allGroups, g)
			}
		}

		// The loop appends to allGroups while walking it, so nested subgroups are covered.
		for i := 0; i < len(allGroups); i++ {
			subgroups, err := p.client.ListSubgroups(ctx, allGroups[i].ID)
			if err != nil {
				result.Errors = append(result.Errors, "listing subgroups for "+allGroups[i].FullPath+": "+err.Error())
				continue
			}
			allGroups = append(allGroups, subgroups...)
		}
	} else {
		for _, g := range groups {
			if g.ParentID == nil {
				allGroups = append(allGroups, g)
			}
		}
	}

	seen := make(map[int]bool)
	var sharedGroups []GroupWithAccess

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

		shared, err := p.client.ListSharedGroups(ctx, group.ID)
		if err != nil {
			// Non-fatal: listing shared groups needs permission we may lack.
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

	result.Groups = append(result.Groups, sharedGroups...)

	return result, nil
}

func (p *Platform) EnumerateSecrets(ctx context.Context, target platforms.Target) (*SecretsEnumerateResult, error) {
	result := &SecretsEnumerateResult{
		ProjectVariables: make(map[string][]Variable),
		GroupVariables:   make(map[string][]Variable),
	}

	switch target.Type {
	case platforms.TargetRepo:
		project, err := p.client.GetProject(ctx, target.Value)
		if err != nil {
			result.Errors = append(result.Errors, "getting project: "+err.Error())
			return result, nil
		}
		p.enumerateProjectVariables(ctx, result, project)

	case platforms.TargetOrg:
		group, err := p.client.GetGroup(ctx, target.Value)
		if err != nil {
			result.Errors = append(result.Errors, "getting group: "+err.Error())
			return result, nil
		}

		groupVars, err := p.client.ListGroupVariables(ctx, group.ID)
		if err != nil {
			result.PermissionErrors = append(result.PermissionErrors,
				fmt.Sprintf("GET /groups/%d/variables: %s", group.ID, err.Error()))
		} else {
			result.GroupVariables[group.FullPath] = groupVars
		}

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

	instanceVars, err := p.client.ListInstanceVariables(ctx)
	if err != nil {
		// 403 is expected for non-admins.
		if !IsPermissionError(err) {
			result.PermissionErrors = append(result.PermissionErrors,
				fmt.Sprintf("GET /admin/ci/variables: %s", err.Error()))
		}
	} else {
		result.InstanceVariables = instanceVars
	}

	return result, nil
}

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
