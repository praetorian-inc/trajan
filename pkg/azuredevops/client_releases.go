package azuredevops

import (
	"context"
	"fmt"
	"net/url"
)

func (c *Client) ListReleaseDefinitions(ctx context.Context, projectNameOrID string) ([]ReleaseDefinition, error) {
	vsrm := c.VSRMClient()
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/release/definitions?api-version=%s", encodedProject, APIVersion)

	var result ReleaseDefinitionList
	if err := vsrm.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing release definitions: %w", err)
	}
	return result.Value, nil
}

func (c *Client) GetReleaseDefinition(ctx context.Context, projectNameOrID string, definitionID int) (*ReleaseDefinition, error) {
	vsrm := c.VSRMClient()
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/release/definitions/%d?api-version=%s", encodedProject, definitionID, APIVersion)

	var result ReleaseDefinition
	if err := vsrm.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("getting release definition: %w", err)
	}
	return &result, nil
}

func (c *Client) ListDeployments(ctx context.Context, projectNameOrID string) ([]Deployment, error) {
	vsrm := c.VSRMClient()
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/release/deployments?api-version=%s", encodedProject, APIVersion)

	var result DeploymentList
	if err := vsrm.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing deployments: %w", err)
	}
	return result.Value, nil
}
