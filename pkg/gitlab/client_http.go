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

// retryAfterSeconds reads a 429 Retry-After delay, falling back to 60s when the
// header is absent or not a plain integer.
func retryAfterSeconds(h http.Header) int {
	if v := h.Get("Retry-After"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			return parsed
		}
	}
	return 60
}

func (c *Client) doRequestWithBody(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	const maxRetries = 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait: %w", err)
		}

		if err := c.semaphore.Acquire(ctx, 1); err != nil {
			return nil, fmt.Errorf("semaphore acquire: %w", err)
		}

		url := c.baseURL + path

		var bodyReader io.Reader
		if body != nil {
			jsonBytes, err := json.Marshal(body)
			if err != nil {
				c.semaphore.Release(1)
				return nil, fmt.Errorf("marshaling request body: %w", err)
			}
			bodyReader = strings.NewReader(string(jsonBytes))
		}

		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			c.semaphore.Release(1)
			return nil, fmt.Errorf("creating request: %w", err)
		}

		req.Header.Set("PRIVATE-TOKEN", c.token)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			c.semaphore.Release(1)
			return nil, fmt.Errorf("performing request: %w", err)
		}

		c.rateLimiter.Update(resp.Header)

		if resp.StatusCode == http.StatusTooManyRequests {
			seconds := retryAfterSeconds(resp.Header)

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

		if resp.StatusCode >= 400 {
			c.semaphore.Release(1)
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			return nil, &APIError{StatusCode: resp.StatusCode, Body: string(body)}
		}

		c.semaphore.Release(1)
		return resp, nil
	}

	return nil, fmt.Errorf("unexpected: exceeded max retries without returning")
}

func (c *Client) doRequest(ctx context.Context, method, path string) (*http.Response, error) {
	const maxRetries = 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait: %w", err)
		}

		if err := c.semaphore.Acquire(ctx, 1); err != nil {
			return nil, fmt.Errorf("semaphore acquire: %w", err)
		}

		url := c.baseURL + path

		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			c.semaphore.Release(1)
			return nil, fmt.Errorf("creating request: %w", err)
		}

		// GitLab authenticates with PRIVATE-TOKEN, not Bearer or Basic.
		req.Header.Set("PRIVATE-TOKEN", c.token)
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			c.semaphore.Release(1)
			return nil, fmt.Errorf("performing request: %w", err)
		}

		c.rateLimiter.Update(resp.Header)

		if resp.StatusCode == http.StatusTooManyRequests {
			seconds := retryAfterSeconds(resp.Header)

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

		if resp.StatusCode >= 400 {
			c.semaphore.Release(1)
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			return nil, &APIError{StatusCode: resp.StatusCode, Body: string(body)}
		}

		c.semaphore.Release(1)
		return resp, nil
	}

	return nil, fmt.Errorf("unexpected: exceeded max retries without returning")
}

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

func (c *Client) getPaginatedJSON(ctx context.Context, path string, perPage int, result interface{}) error {
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

		pageSlice := reflect.New(resultSlice.Type())
		if err := json.Unmarshal(body, pageSlice.Interface()); err != nil {
			return fmt.Errorf("decoding page %d: %w", page, err)
		}

		resultSlice.Set(reflect.AppendSlice(resultSlice, pageSlice.Elem()))

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
