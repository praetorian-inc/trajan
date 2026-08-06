package azuredevops

import (
	"context"
	"fmt"
	"net/url"
)

func (c *Client) CreatePipeline(ctx context.Context, projectNameOrID string, req CreatePipelineRequest) (*Pipeline, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/pipelines?api-version=%s", encodedProject, APIVersion)

	var result Pipeline
	if err := c.postJSON(ctx, path, req, &result); err != nil {
		return nil, fmt.Errorf("creating pipeline: %w", err)
	}
	return &result, nil
}

func (c *Client) RunPipeline(ctx context.Context, projectNameOrID string, pipelineID int, req RunPipelineRequest) (*PipelineRun, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/pipelines/%d/runs?api-version=%s", encodedProject, pipelineID, APIVersion)

	var result PipelineRun
	if err := c.postJSON(ctx, path, req, &result); err != nil {
		return nil, fmt.Errorf("running pipeline: %w", err)
	}
	return &result, nil
}

func (c *Client) GetPipelineRun(ctx context.Context, projectNameOrID string, pipelineID, runID int) (*PipelineRun, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/pipelines/%d/runs/%d?api-version=%s", encodedProject, pipelineID, runID, APIVersion)

	var result PipelineRun
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("getting pipeline run: %w", err)
	}
	return &result, nil
}

func (c *Client) DeletePipeline(ctx context.Context, projectNameOrID string, definitionID int) error {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/build/definitions/%d?api-version=%s", encodedProject, definitionID, APIVersion)

	if err := c.deleteRequest(ctx, path); err != nil {
		return fmt.Errorf("deleting pipeline: %w", err)
	}
	return nil
}

func (c *Client) DeleteBuild(ctx context.Context, projectNameOrID string, buildID int) error {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/build/builds/%d?api-version=%s", encodedProject, buildID, APIVersion)

	if err := c.deleteRequest(ctx, path); err != nil {
		return fmt.Errorf("deleting build: %w", err)
	}
	return nil
}

func (c *Client) ListPipelinePermissions(ctx context.Context, projectNameOrID, resourceType string, resourceID int) (map[string]interface{}, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/pipelines/pipelinePermissions/%s/%d?api-version=%s",
		encodedProject, url.PathEscape(resourceType), resourceID, APIVersionPreview)

	var result map[string]interface{}
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing pipeline permissions: %w", err)
	}
	return result, nil
}

func (c *Client) AuthorizePipelineResource(ctx context.Context, projectNameOrID, resourceType string, resourceID, pipelineID int) error {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/pipelines/pipelinePermissions/%s/%d?api-version=%s",
		encodedProject, url.PathEscape(resourceType), resourceID, APIVersionPreview)

	body := PipelinePermissionRequest{
		Pipelines: []PipelinePermission{
			{
				ID:         pipelineID,
				Authorized: true,
			},
		},
	}

	var result map[string]interface{}
	if err := c.patchJSON(ctx, path, body, &result); err != nil {
		return fmt.Errorf("authorizing pipeline %d for %s %d: %w", pipelineID, resourceType, resourceID, err)
	}
	return nil
}

// Secure files and service endpoints are keyed by GUID, not by integer id.
func (c *Client) AuthorizePipelineResourceStr(ctx context.Context, projectNameOrID, resourceType, resourceID string, pipelineID int) error {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/pipelines/pipelinePermissions/%s/%s?api-version=%s",
		encodedProject, url.PathEscape(resourceType), url.PathEscape(resourceID), APIVersionPreview)

	body := PipelinePermissionRequest{
		Pipelines: []PipelinePermission{
			{
				ID:         pipelineID,
				Authorized: true,
			},
		},
	}

	var result map[string]interface{}
	if err := c.patchJSON(ctx, path, body, &result); err != nil {
		return fmt.Errorf("authorizing pipeline %d for %s %s: %w", pipelineID, resourceType, resourceID, err)
	}
	return nil
}

// The API that serves artifacts created by PublishPipelineArtifact@1.
func (c *Client) GetPipelineArtifact(ctx context.Context, projectNameOrID string, pipelineID, runID int, artifactName string) (*PipelineArtifact, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/pipelines/%d/runs/%d/artifacts?artifactName=%s&$expand=signedContent&api-version=%s",
		encodedProject, pipelineID, runID, url.QueryEscape(artifactName), APIVersion)

	var result PipelineArtifact
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("getting pipeline artifact: %w", err)
	}
	return &result, nil
}
