package bitbucket

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

// bitbucketErrorResponse is the standard Bitbucket API error envelope.
type bitbucketErrorResponse struct {
	Error struct {
		Message string `json:"message"`
		Detail  string `json:"detail"`
	} `json:"error"`
}

// doRequest performs an HTTP request with authentication and concurrency control.
// It handles 429 rate limiting with retries and returns an *APIError for non-2xx responses.
func (c *Client) doRequest(ctx context.Context, method, path string) (*http.Response, error) {
	const maxRetries = 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Acquire semaphore for concurrency control
		if err := c.semaphore.Acquire(ctx, 1); err != nil {
			return nil, fmt.Errorf("semaphore acquire: %w", err)
		}

		// Build full URL
		reqURL := c.baseURL + path

		// Create request
		req, err := http.NewRequestWithContext(ctx, method, reqURL, nil)
		if err != nil {
			c.semaphore.Release(1)
			return nil, fmt.Errorf("creating request: %w", err)
		}

		// Set authentication and accept headers
		c.setAuth(req)
		req.Header.Set("Accept", "application/json")

		// Perform request
		resp, err := c.httpClient.Do(req)
		if err != nil {
			c.semaphore.Release(1)
			return nil, fmt.Errorf("performing request: %w", err)
		}

		// Handle 429 rate limit with retry
		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter := resp.Header.Get("Retry-After")
			seconds := 60
			if retryAfter != "" {
				if parsed, err := strconv.Atoi(retryAfter); err == nil && parsed > 0 {
					seconds = parsed
					if seconds > 300 {
						seconds = 300
					}
				}
			}

			resp.Body.Close()
			c.semaphore.Release(1)

			if attempt >= maxRetries {
				return nil, fmt.Errorf("API error 429: rate limited after %d attempts", maxRetries)
			}

			fmt.Fprintf(os.Stderr, "Bitbucket rate limited (attempt %d/%d). Retrying after %d seconds\n", attempt, maxRetries, seconds)

			select {
			case <-time.After(time.Duration(seconds) * time.Second):
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		// Check for other error status codes
		if resp.StatusCode >= 400 {
			c.semaphore.Release(1)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, parseAPIError(resp.StatusCode, body)
		}

		// Success - release semaphore and return
		c.semaphore.Release(1)
		return resp, nil
	}

	return nil, fmt.Errorf("unexpected: exceeded max retries without returning")
}

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

// getJSON performs a GET request and decodes the JSON response into result.
func (c *Client) getJSON(ctx context.Context, path string, result interface{}) error {
	resp, err := c.doRequest(ctx, "GET", path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return fmt.Errorf("decoding JSON: %w", err)
	}

	return nil
}

// parseAPIError constructs an *APIError from a non-2xx response body.
// It attempts to parse the Bitbucket error JSON envelope; if that fails
// it falls back to using the raw body as the message.
func parseAPIError(statusCode int, body []byte) *APIError {
	apiErr := &APIError{
		StatusCode: statusCode,
		Body:       string(body),
	}

	var errResp bitbucketErrorResponse
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error.Message != "" {
		apiErr.Message = errResp.Error.Message
		apiErr.Detail = errResp.Error.Detail
	} else {
		apiErr.Message = string(body)
	}

	return apiErr
}
