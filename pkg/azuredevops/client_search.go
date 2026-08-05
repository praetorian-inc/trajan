package azuredevops

import (
	"context"
	"fmt"
	"net/url"
)

func (c *Client) SearchCode(ctx context.Context, projectNameOrID string, req CodeSearchRequest) (*CodeSearchResult, error) {
	search := c.SearchClient()
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/search/codesearchresults?api-version=%s", encodedProject, APIVersion)

	var result CodeSearchResult
	if err := search.postJSON(ctx, path, req, &result); err != nil {
		return nil, fmt.Errorf("searching code: %w", err)
	}
	return &result, nil
}

func (c *Client) SearchCodeOrg(ctx context.Context, req CodeSearchRequest) (*CodeSearchResult, error) {
	search := c.SearchClient()
	path := fmt.Sprintf("/_apis/search/codesearchresults?api-version=%s", APIVersion)

	var result CodeSearchResult
	if err := search.postJSON(ctx, path, req, &result); err != nil {
		return nil, fmt.Errorf("searching code: %w", err)
	}
	return &result, nil
}
