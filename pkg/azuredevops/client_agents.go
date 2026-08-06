package azuredevops

import (
	"context"
	"fmt"
	"net/url"
)

func (c *Client) ListAgents(ctx context.Context, poolID int) ([]Agent, error) {
	path := fmt.Sprintf("/_apis/distributedtask/pools/%d/agents?includeCapabilities=true&api-version=%s", poolID, APIVersion)

	var result AgentList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing agents: %w", err)
	}
	return result.Value, nil
}

func (c *Client) ListAgentQueues(ctx context.Context, projectNameOrID string) ([]AgentQueue, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/distributedtask/queues?api-version=%s", encodedProject, APIVersion)

	var result AgentQueueList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing agent queues: %w", err)
	}
	return result.Value, nil
}

func (c *Client) GetEnvironment(ctx context.Context, projectNameOrID string, envID int) (*Environment, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/distributedtask/environments/%d?expands=resourceReferences&api-version=%s", encodedProject, envID, APIVersion)

	var result Environment
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("getting environment: %w", err)
	}
	return &result, nil
}
