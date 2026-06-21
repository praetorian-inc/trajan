package bitbucket

import (
	"context"
	"fmt"
	"net/http"
)

// getRawResponse performs an HTTP request and returns the raw response
// WITHOUT checking status codes. This is used by callers that need to
// inspect headers or bodies from error responses (e.g., GetTokenInfo
// reads scopes from 403 responses).
func (c *Client) getRawResponse(ctx context.Context, method, path string) (*http.Response, error) {
	// Acquire semaphore for concurrency control
	if err := c.semaphore.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("semaphore acquire: %w", err)
	}
	defer c.semaphore.Release(1)

	// Build full URL
	reqURL := c.baseURL + path

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set authentication and accept headers
	c.setAuth(req)
	req.Header.Set("Accept", "application/json")

	// Perform request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("performing request: %w", err)
	}

	return resp, nil
}
