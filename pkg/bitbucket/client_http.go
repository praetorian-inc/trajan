package bitbucket

import (
	"context"
	"fmt"
	"net/http"
)

// Returns the response without checking the status code: GetTokenInfo needs the
// headers from a 403.
func (c *Client) getRawResponse(ctx context.Context, method, path string) (*http.Response, error) {
	if err := c.semaphore.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("semaphore acquire: %w", err)
	}
	defer c.semaphore.Release(1)

	reqURL := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, method, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	c.setAuth(req)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("performing request: %w", err)
	}

	return resp, nil
}
