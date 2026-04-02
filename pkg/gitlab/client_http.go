// pkg/gitlab/client_http.go
package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// doRequestWithBody performs an HTTP request with JSON body, authentication and rate limiting
func (c *Client) doRequestWithBody(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	const maxRetries = 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Wait for rate limiter
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait: %w", err)
		}

		// Acquire semaphore for concurrency control
		if err := c.semaphore.Acquire(ctx, 1); err != nil {
			return nil, fmt.Errorf("semaphore acquire: %w", err)
		}

		// Build full URL
		url := c.baseURL + path

		// Marshal body to JSON
		var bodyReader io.Reader
		if body != nil {
			jsonBytes, err := json.Marshal(body)
			if err != nil {
				c.semaphore.Release(1)
				return nil, fmt.Errorf("marshaling request body: %w", err)
			}
			bodyReader = strings.NewReader(string(jsonBytes))
		}

		// Create request
		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			c.semaphore.Release(1)
			return nil, fmt.Errorf("creating request: %w", err)
		}

		// Set headers
		req.Header.Set("PRIVATE-TOKEN", c.token)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		// Perform request
		resp, err := c.httpClient.Do(req)
		if err != nil {
			c.semaphore.Release(1)
			return nil, fmt.Errorf("performing request: %w", err)
		}

		// Update rate limiter from response headers
		c.rateLimiter.Update(resp.Header)

		// Handle 429 rate limit with retry (same logic as doRequest)
		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter := resp.Header.Get("Retry-After")
			seconds := 60
			if retryAfter != "" {
				if parsed, err := strconv.Atoi(retryAfter); err == nil {
					seconds = parsed
				}
			}

			resp.Body.Close()
			c.semaphore.Release(1)

			if attempt >= maxRetries {
				return nil, fmt.Errorf("API error 429: rate limited after %d attempts", maxRetries)
			}

			log.Printf("GitLab rate limited (attempt %d/%d). Retrying after %d seconds", attempt, maxRetries, seconds)

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
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			return nil, &APIError{StatusCode: resp.StatusCode, Body: string(body)}
		}

		// Success
		c.semaphore.Release(1)
		return resp, nil
	}

	return nil, fmt.Errorf("unexpected: exceeded max retries without returning")
}

// doRequest performs an HTTP request with authentication and rate limiting
func (c *Client) doRequest(ctx context.Context, method, path string) (*http.Response, error) {
	const maxRetries = 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Wait for rate limiter
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait: %w", err)
		}

		// Acquire semaphore for concurrency control
		if err := c.semaphore.Acquire(ctx, 1); err != nil {
			return nil, fmt.Errorf("semaphore acquire: %w", err)
		}

		// Build full URL
		url := c.baseURL + path

		// Create request
		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			c.semaphore.Release(1)
			return nil, fmt.Errorf("creating request: %w", err)
		}

		// Set authentication header (GitLab uses PRIVATE-TOKEN, not Bearer or Basic)
		req.Header.Set("PRIVATE-TOKEN", c.token)
		req.Header.Set("Accept", "application/json")

		// Perform request
		resp, err := c.httpClient.Do(req)
		if err != nil {
			c.semaphore.Release(1)
			return nil, fmt.Errorf("performing request: %w", err)
		}

		// Update rate limiter from response headers
		// GitLab uses RateLimit-* headers (NO X- prefix!)
		c.rateLimiter.Update(resp.Header)

		// Handle 429 rate limit with retry
		if resp.StatusCode == http.StatusTooManyRequests {
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
				return nil, fmt.Errorf("API error 429: rate limited after %d attempts", maxRetries)
			}

			// Log warning and sleep
			log.Printf("GitLab rate limited (attempt %d/%d). Retrying after %d seconds", attempt, maxRetries, seconds)

			// Sleep for the specified duration
			select {
			case <-time.After(time.Duration(seconds) * time.Second):
				// Continue to retry
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		// Check for other error status codes
		if resp.StatusCode >= 400 {
			c.semaphore.Release(1)
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			return nil, &APIError{StatusCode: resp.StatusCode, Body: string(body)}
		}

		// Success - release semaphore and return
		c.semaphore.Release(1)
		return resp, nil
	}

	// Should never reach here, but just in case
	return nil, fmt.Errorf("unexpected: exceeded max retries without returning")
}

// getJSON performs a GET request and decodes JSON response
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

// postJSON performs a POST request with JSON body and decodes JSON response
func (c *Client) postJSON(ctx context.Context, path string, body interface{}, result interface{}) error {
	resp, err := c.doRequestWithBody(ctx, "POST", path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("decoding JSON: %w", err)
		}
	}

	return nil
}

// getRaw performs a GET request and returns raw bytes
func (c *Client) getRaw(ctx context.Context, path string) ([]byte, error) {
	resp, err := c.doRequest(ctx, "GET", path)
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

// getPaginatedJSON fetches all pages of a paginated API endpoint
func (c *Client) getPaginatedJSON(ctx context.Context, path string, perPage int, result interface{}) error {
	// Use reflection to work with the slice
	resultSlice := reflect.ValueOf(result).Elem()

	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}

	page := 1
	for {
		pagePath := fmt.Sprintf("%s%sper_page=%d&page=%d", path, separator, perPage, page)

		resp, err := c.doRequest(ctx, "GET", pagePath)
		if err != nil {
			return fmt.Errorf("fetching page %d: %w", page, err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("reading page %d body: %w", page, err)
		}

		// Decode this page into a temporary slice of the same type
		pageSlice := reflect.New(resultSlice.Type())
		if err := json.Unmarshal(body, pageSlice.Interface()); err != nil {
			return fmt.Errorf("decoding page %d: %w", page, err)
		}

		// Append page results to the accumulator
		resultSlice.Set(reflect.AppendSlice(resultSlice, pageSlice.Elem()))

		// Check for next page
		nextPage := resp.Header.Get("X-Next-Page")
		if nextPage == "" {
			break
		}

		var nextPageNum int
		if _, err := fmt.Sscanf(nextPage, "%d", &nextPageNum); err != nil {
			break
		}
		if nextPageNum <= page {
			break // Safety: avoid infinite loops
		}
		page = nextPageNum
	}

	return nil
}
