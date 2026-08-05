package azuredevops

import (
	"context"
	"fmt"
	"net/url"
)

func (c *Client) GetConnectionData(ctx context.Context) (*ConnectionData, error) {
	path := fmt.Sprintf("/_apis/connectionData?api-version=%s", APIVersionPreview)

	var data ConnectionData
	if err := c.getJSON(ctx, path, &data); err != nil {
		return nil, fmt.Errorf("getting connection data: %w", err)
	}

	return &data, nil
}

func (c *Client) ListProjects(ctx context.Context) ([]Project, error) {
	path := fmt.Sprintf("/_apis/projects?api-version=%s", APIVersion)

	var result ProjectList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
	}

	return result.Value, nil
}

func (c *Client) ListPipelines(ctx context.Context, projectNameOrID string) ([]Pipeline, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/pipelines?api-version=%s", encodedProject, APIVersion)

	var result PipelineList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing pipelines: %w", err)
	}

	return result.Value, nil
}

func (c *Client) ListAgentPools(ctx context.Context) ([]AgentPool, error) {
	path := fmt.Sprintf("/_apis/distributedtask/pools?api-version=%s", APIVersion)

	var result AgentPoolList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing agent pools: %w", err)
	}

	return result.Value, nil
}

func (c *Client) ListVariableGroups(ctx context.Context, projectNameOrID string) ([]VariableGroup, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/distributedtask/variablegroups?api-version=%s", encodedProject, APIVersion)

	var result VariableGroupList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing variable groups: %w", err)
	}

	return result.Value, nil
}

func (c *Client) ListServiceConnections(ctx context.Context, projectNameOrID string) ([]ServiceConnection, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/serviceendpoint/endpoints?api-version=%s", encodedProject, APIVersion)

	var result ServiceConnectionList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing service connections: %w", err)
	}

	return result.Value, nil
}

// Feeds live on feeds.dev.azure.com, so callers must invoke this on FeedsClient().
func (c *Client) ListArtifactFeeds(ctx context.Context) ([]ArtifactFeed, error) {
	path := fmt.Sprintf("/_apis/packaging/feeds?api-version=%s", APIVersion)

	var result ArtifactFeedList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing artifact feeds: %w", err)
	}

	return result.Value, nil
}
