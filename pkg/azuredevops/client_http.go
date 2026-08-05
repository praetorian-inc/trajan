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

func (c *Client) doRequest(ctx context.Context, method, path string) (*http.Response, error) {
	const maxRetries = 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait: %w", err)
		}

		if err := c.semaphore.Acquire(ctx, 1); err != nil {
			return nil, fmt.Errorf("semaphore acquire: %w", err)
		}

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
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
		}

		c.semaphore.Release(1)
		return resp, nil
	}

	return nil, fmt.Errorf("unexpected: exceeded max retries without returning")
}

func (c *Client) prepareRequest(ctx context.Context, method, path string) (*http.Request, error) {
	url := c.orgURL + path

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Basic auth with an empty username and the PAT as the password.
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

func (c *Client) handleRateLimitRetry(ctx context.Context, resp *http.Response, attempt, maxRetries int) error {
	retryAfter := resp.Header.Get("Retry-After")
	seconds := 60
	if retryAfter != "" {
		if parsed, err := strconv.Atoi(retryAfter); err == nil {
			seconds = parsed
		}
	}

	resp.Body.Close()

	// Released before sleeping so the slot is not held for the whole backoff.
	c.semaphore.Release(1)

	if attempt >= maxRetries {
		return fmt.Errorf("API error 429: rate limited after %d attempts", maxRetries)
	}

	log.Printf("Azure DevOps rate limited (attempt %d/%d). Retrying after %d seconds (TSTUs exhausted)",
		attempt, maxRetries, seconds)

	select {
	case <-time.After(time.Duration(seconds) * time.Second):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ADO answers an invalid or expired PAT with an HTML sign-in page, not JSON.
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

func (c *Client) doRequestRaw(ctx context.Context, method, path string) (*http.Response, error) {
	const maxRetries = 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait: %w", err)
		}

		if err := c.semaphore.Acquire(ctx, 1); err != nil {
			return nil, fmt.Errorf("semaphore acquire: %w", err)
		}

		url := c.orgURL + path
		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			c.semaphore.Release(1)
			return nil, fmt.Errorf("creating request: %w", err)
		}

		if c.bearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+c.bearerToken)
		} else {
			auth := base64.StdEncoding.EncodeToString([]byte(":" + c.pat))
			req.Header.Set("Authorization", "Basic "+auth)
		}
		// ADO returns JSON item metadata unless the request asks for text/plain.
		req.Header.Set("Accept", "text/plain")

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
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
		}

		c.semaphore.Release(1)
		return resp, nil
	}

	return nil, fmt.Errorf("unexpected: exceeded max retries without returning")
}

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

func (c *Client) deleteRequest(ctx context.Context, path string) error {
	resp, err := c.doRequestWithBody(ctx, "DELETE", path, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
