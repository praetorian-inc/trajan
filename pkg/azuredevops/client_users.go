package azuredevops

import (
	"context"
	"fmt"
	"net/url"
)

func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	vssps := c.VSSPSClient()
	basePath := fmt.Sprintf("/_apis/graph/users?api-version=%s", APIVersionPreview)

	var allUsers []User
	continuationToken := ""
	for {
		path := basePath
		if continuationToken != "" {
			path += "&continuationToken=" + url.QueryEscape(continuationToken)
		}

		var result UserList
		if err := vssps.getJSON(ctx, path, &result); err != nil {
			return nil, fmt.Errorf("listing users: %w", err)
		}
		allUsers = append(allUsers, result.Value...)
		if result.ContinuationToken == "" {
			break
		}
		continuationToken = result.ContinuationToken
	}
	return allUsers, nil
}

// storageKey is an ADO storage key, e.g. a project ID.
func (c *Client) GetDescriptor(ctx context.Context, storageKey string) (string, error) {
	vssps := c.VSSPSClient()
	path := fmt.Sprintf("/_apis/graph/descriptors/%s?api-version=%s", url.PathEscape(storageKey), APIVersionPreview)

	var result struct {
		Value string `json:"value"`
	}
	if err := vssps.getJSON(ctx, path, &result); err != nil {
		return "", fmt.Errorf("getting descriptor: %w", err)
	}
	return result.Value, nil
}

// The optional scopeDescriptor narrows the listing to one scope, e.g. a project.
func (c *Client) ListGroups(ctx context.Context, scopeDescriptor ...string) ([]Group, error) {
	vssps := c.VSSPSClient()
	basePath := fmt.Sprintf("/_apis/graph/groups?api-version=%s", APIVersionPreview)
	if len(scopeDescriptor) > 0 && scopeDescriptor[0] != "" {
		basePath += "&scopeDescriptor=" + url.QueryEscape(scopeDescriptor[0])
	}

	var allGroups []Group
	continuationToken := ""
	for {
		path := basePath
		if continuationToken != "" {
			path += "&continuationToken=" + url.QueryEscape(continuationToken)
		}

		var result GroupList
		if err := vssps.getJSON(ctx, path, &result); err != nil {
			return nil, fmt.Errorf("listing groups: %w", err)
		}
		allGroups = append(allGroups, result.Value...)
		if result.ContinuationToken == "" {
			break
		}
		continuationToken = result.ContinuationToken
	}
	return allGroups, nil
}

func (c *Client) ListGroupMembers(ctx context.Context, groupDescriptor string) ([]Membership, error) {
	vssps := c.VSSPSClient()
	encodedDesc := url.PathEscape(groupDescriptor)
	path := fmt.Sprintf("/_apis/graph/memberships/%s?direction=down&api-version=%s", encodedDesc, APIVersionPreview)

	var result MembershipList
	if err := vssps.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing group members: %w", err)
	}
	return result.Value, nil
}

func (c *Client) ListTeams(ctx context.Context, projectNameOrID string) ([]Team, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	basePath := fmt.Sprintf("/_apis/projects/%s/teams?api-version=%s", encodedProject, APIVersionPreview)

	var allTeams []Team
	continuationToken := ""
	for {
		path := basePath
		if continuationToken != "" {
			path += "&continuationToken=" + url.QueryEscape(continuationToken)
		}

		var result TeamList
		if err := c.getJSON(ctx, path, &result); err != nil {
			return nil, fmt.Errorf("listing teams: %w", err)
		}
		allTeams = append(allTeams, result.Value...)
		if result.ContinuationToken == "" {
			break
		}
		continuationToken = result.ContinuationToken
	}
	return allTeams, nil
}

func (c *Client) ListTeamMembers(ctx context.Context, projectNameOrID, teamID string) ([]TeamMember, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	encodedTeam := url.PathEscape(teamID)
	path := fmt.Sprintf("/_apis/projects/%s/teams/%s/members?api-version=%s", encodedProject, encodedTeam, APIVersionPreview)

	var result TeamMemberList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing team members: %w", err)
	}
	return result.Value, nil
}
