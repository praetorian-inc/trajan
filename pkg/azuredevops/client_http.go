// pkg/platforms/azuredevops/client_http.go
package azuredevops

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// doRequest performs an HTTP request with PAT authentication and TSTU-based rate limiting
// Azure DevOps authentication: Basic Auth with empty username and PAT as password
// Reference: https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/
func (c *Client) doRequest(ctx context.Context, method, path string) (*http.Response, error) {
	const maxRetries = 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Wait for TSTU-based rate limiter
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait: %w", err)
		}

		// Acquire semaphore for concurrency control
		if err := c.semaphore.Acquire(ctx, 1); err != nil {
			return nil, fmt.Errorf("semaphore acquire: %w", err)
		}

		// Prepare and execute request
		req, err := c.prepareRequest(ctx, method, path)
		if err != nil {
			c.semaphore.Release(1)
			return nil, err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			c.semaphore.Release(1)
			return nil, fmt.Errorf("performing request: %w", err)
		}

		// Update TSTU rate limiter from response headers
		c.rateLimiter.Update(resp.Header)

		// Handle 429 rate limit with retry
		if resp.StatusCode == http.StatusTooManyRequests {
			if err := c.handleRateLimitRetry(ctx, resp, attempt, maxRetries); err != nil {
				return nil, err
			}
			continue
		}

		// Check for other error status codes
		if resp.StatusCode >= 400 {
			c.semaphore.Release(1)
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
		}

		// Success - release semaphore and return
		c.semaphore.Release(1)
		return resp, nil
	}

	return nil, fmt.Errorf("unexpected: exceeded max retries without returning")
}

// prepareRequest creates an HTTP request with authentication headers
func (c *Client) prepareRequest(ctx context.Context, method, path string) (*http.Request, error) {
	url := c.orgURL + path

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set authentication header: Bearer token (Entra ID) takes precedence over Basic Auth (PAT)
	if c.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearerToken)
	} else {
		auth := base64.StdEncoding.EncodeToString([]byte(":" + c.pat))
		req.Header.Set("Authorization", "Basic "+auth)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	return req, nil
}

// handleRateLimitRetry handles 429 responses with exponential backoff
func (c *Client) handleRateLimitRetry(ctx context.Context, resp *http.Response, attempt, maxRetries int) error {
	// Parse Retry-After header (default to 60 seconds)
	retryAfter := resp.Header.Get("Retry-After")
	seconds := 60
	if retryAfter != "" {
		if parsed, err := strconv.Atoi(retryAfter); err == nil {
			seconds = parsed
		}
	}

	// Close response body before retrying
	resp.Body.Close()

	// Release semaphore before sleeping
	c.semaphore.Release(1)

	// If we've exhausted retries, return error
	if attempt >= maxRetries {
		return fmt.Errorf("API error 429: rate limited after %d attempts", maxRetries)
	}

	// Log warning and sleep
	log.Printf("Azure DevOps rate limited (attempt %d/%d). Retrying after %d seconds (TSTUs exhausted)",
		attempt, maxRetries, seconds)

	// Sleep for the specified duration
	select {
	case <-time.After(time.Duration(seconds) * time.Second):
		return nil // Continue to retry
	case <-ctx.Done():
		return ctx.Err()
	}
}

// decodeJSONResponse checks the response Content-Type before decoding JSON.
// Returns a clear error if the response is HTML (common with invalid/expired PAT tokens).
func decodeJSONResponse(resp *http.Response, result interface{}) error {
	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "text/html") {
		return fmt.Errorf("authentication failed: server returned HTML instead of JSON (verify your PAT token is valid and not expired)")
	}
	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return fmt.Errorf("decoding JSON: %w", err)
	}
	return nil
}

// getJSON performs a GET request and decodes JSON response
func (c *Client) getJSON(ctx context.Context, path string, result interface{}) error {
	resp, err := c.doRequest(ctx, "GET", path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := decodeJSONResponse(resp, result); err != nil {
		return err
	}

	return nil
}

// getRaw performs a GET request and returns raw bytes (for file content)
func (c *Client) getRaw(ctx context.Context, path string) ([]byte, error) {
	resp, err := c.doRequestRaw(ctx, "GET", path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return body, nil
}

// doRequestRaw performs an HTTP request expecting raw content (not JSON)
func (c *Client) doRequestRaw(ctx context.Context, method, path string) (*http.Response, error) {
	const maxRetries = 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Wait for TSTU-based rate limiter
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait: %w", err)
		}

		// Acquire semaphore for concurrency control
		if err := c.semaphore.Acquire(ctx, 1); err != nil {
			return nil, fmt.Errorf("semaphore acquire: %w", err)
		}

		// Prepare request with raw content Accept header
		url := c.orgURL + path
		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			c.semaphore.Release(1)
			return nil, fmt.Errorf("creating request: %w", err)
		}

		// Set authentication header: Bearer token (Entra ID) takes precedence over Basic Auth (PAT)
		if c.bearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+c.bearerToken)
		} else {
			auth := base64.StdEncoding.EncodeToString([]byte(":" + c.pat))
			req.Header.Set("Authorization", "Basic "+auth)
		}
		// Request raw text content instead of JSON metadata
		req.Header.Set("Accept", "text/plain")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			c.semaphore.Release(1)
			return nil, fmt.Errorf("performing request: %w", err)
		}

		// Update TSTU rate limiter from response headers
		c.rateLimiter.Update(resp.Header)

		// Handle 429 rate limit with retry
		if resp.StatusCode == http.StatusTooManyRequests {
			if err := c.handleRateLimitRetry(ctx, resp, attempt, maxRetries); err != nil {
				return nil, err
			}
			continue
		}

		// Check for other error status codes
		if resp.StatusCode >= 400 {
			c.semaphore.Release(1)
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
		}

		// Success - release semaphore and return
		c.semaphore.Release(1)
		return resp, nil
	}

	return nil, fmt.Errorf("unexpected: exceeded max retries without returning")
}

// doRequestWithBody performs an HTTP request with a body, using the same
// rate limiting, semaphore, and retry logic as doRequest.
// body is []byte so it can be re-read on retries (io.Reader would be consumed).
func (c *Client) doRequestWithBody(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	const maxRetries = 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait: %w", err)
		}
		if err := c.semaphore.Acquire(ctx, 1); err != nil {
			return nil, fmt.Errorf("semaphore acquire: %w", err)
		}

		url := c.orgURL + path
		var bodyReader io.Reader
		if body != nil {
			bodyReader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			c.semaphore.Release(1)
			return nil, fmt.Errorf("creating request: %w", err)
		}

		// Set authentication header: Bearer token (Entra ID) takes precedence over Basic Auth (PAT)
		if c.bearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+c.bearerToken)
		} else {
			auth := base64.StdEncoding.EncodeToString([]byte(":" + c.pat))
			req.Header.Set("Authorization", "Basic "+auth)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			c.semaphore.Release(1)
			return nil, fmt.Errorf("performing request: %w", err)
		}

		c.rateLimiter.Update(resp.Header)

		if resp.StatusCode == http.StatusTooManyRequests {
			if err := c.handleRateLimitRetry(ctx, resp, attempt, maxRetries); err != nil {
				return nil, err
			}
			continue
		}

		if resp.StatusCode >= 400 {
			c.semaphore.Release(1)
			defer resp.Body.Close()
			respBody, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
		}

		c.semaphore.Release(1)
		return resp, nil
	}
	return nil, fmt.Errorf("unexpected: exceeded max retries without returning")
}

// postJSON performs a POST request with JSON body and decodes JSON response
func (c *Client) postJSON(ctx context.Context, path string, body interface{}, result interface{}) error {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshaling request body: %w", err)
	}

	resp, err := c.doRequestWithBody(ctx, "POST", path, jsonBody)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if result != nil {
		if err := decodeJSONResponse(resp, result); err != nil {
			return err
		}
	}
	return nil
}

// patchJSON performs a PATCH request with JSON body and decodes JSON response
func (c *Client) patchJSON(ctx context.Context, path string, body interface{}, result interface{}) error {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshaling request body: %w", err)
	}

	resp, err := c.doRequestWithBody(ctx, "PATCH", path, jsonBody)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if result != nil {
		if err := decodeJSONResponse(resp, result); err != nil {
			return err
		}
	}
	return nil
}

// deleteRequest performs a DELETE request
func (c *Client) deleteRequest(ctx context.Context, path string) error {
	resp, err := c.doRequestWithBody(ctx, "DELETE", path, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
