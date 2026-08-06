package search

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultSourceGraphBaseURL = "https://sourcegraph.com"
)

type SourceGraphSearchProvider struct {
	httpClient *http.Client
	baseURL    string
}

func NewSourceGraphSearchProvider(proxyURL string) *SourceGraphSearchProvider {
	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	if proxyURL != "" {
		proxyURLParsed, err := url.Parse(proxyURL)
		if err == nil {
			transport := &http.Transport{
				Proxy: http.ProxyURL(proxyURLParsed),
			}
			client.Transport = transport
		}
	}

	return &SourceGraphSearchProvider{
		httpClient: client,
		baseURL:    DefaultSourceGraphBaseURL,
	}
}

func (p *SourceGraphSearchProvider) Name() string {
	return "sourcegraph"
}

func DefaultSourceGraphQuery(org string) string {
	repoFilter := ""
	if org != "" {
		repoFilter = fmt.Sprintf("repo:%s/ ", org)
	}

	githubHostedLabels := []string{
		"ubuntu-16.04", "ubuntu-18.04", "ubuntu-20.04", "ubuntu-22.04", "ubuntu-latest",
		"windows-2019", "windows-2022", "windows-latest",
		"macos-11", "macos-12", "macos-13", "macos-12-xl", "macos-13-xl", "macos-latest",
	}

	labelsPattern := strings.Join(githubHostedLabels, "|")

	return fmt.Sprintf(
		"context:global self-hosted OR (runs-on AND NOT /(%s)/) %slang:YAML file:.github/workflows/ count:100000",
		labelsPattern, repoFilter,
	)
}

func (p *SourceGraphSearchProvider) Search(ctx context.Context, query string) (*SearchResult, error) {
	result := &SearchResult{
		Repositories: make([]string, 0),
	}

	seen := make(map[string]bool)

	searchURL := fmt.Sprintf("%s/.api/search/stream?q=%s",
		p.baseURL, url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("search failed (%d): %s", resp.StatusCode, body)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()

		if !strings.HasPrefix(line, "data:") {
			continue
		}

		jsonData := strings.TrimPrefix(line, "data:")
		jsonData = strings.TrimSpace(jsonData)

		if jsonData == "" {
			continue
		}

		// The stream can carry an error object where a match array is expected.
		var errorResp struct {
			Title       string `json:"title"`
			Description string `json:"description"`
		}
		if err := json.Unmarshal([]byte(jsonData), &errorResp); err == nil {
			if errorResp.Title == "Unable To Process Query" {
				return nil, fmt.Errorf("SourceGraph query error: %s", errorResp.Description)
			}
		}

		var matches []struct {
			Repository string `json:"repository"`
		}
		if err := json.Unmarshal([]byte(jsonData), &matches); err != nil {
			continue // progress events share the stream and are not match arrays
		}

		for _, match := range matches {
			if match.Repository != "" {
				repoName := strings.TrimPrefix(match.Repository, "github.com/")
				if !seen[repoName] {
					seen[repoName] = true
					result.Repositories = append(result.Repositories, repoName)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("reading SSE stream: %w", err)
	}

	result.TotalCount = len(result.Repositories)
	return result, nil
}
