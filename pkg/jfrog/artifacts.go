package jfrog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// AQLResult represents a single artifact result from AQL query
type AQLResult struct {
	Repo     string `json:"repo"`
	Path     string `json:"path"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
}

// AQLResponse represents the AQL API response
type AQLResponse struct {
	Results []AQLResult `json:"results"`
}

// ArtifactSearchOptions configures artifact search
type ArtifactSearchOptions struct {
	Name  string // Artifact name pattern (e.g., *.jar)
	Repo  string // Repository to search in
	Type  string // Artifact type (e.g., jar, war)
	Limit int    // Maximum number of results
}

// ArtifactDownloadOptions configures artifact downloads
type ArtifactDownloadOptions struct {
	Repo        string // Repository name
	Path        string // Path within repository
	OutputDir   string // Output directory for downloads
	MaxFileSize string // Maximum file size (e.g., "50MB", "1GB")
	MaxTotal    string // Maximum total download size
	MaxFiles    int    // Maximum number of files to download
}

// DownloadResult tracks download statistics
type DownloadResult struct {
	FilesDownloaded int
	TotalSize       int64
	Skipped         int
}

// ArtifactSecret represents a detected secret in an artifact
type ArtifactSecret struct {
	Artifact    string   `json:"artifact"`
	Path        string   `json:"path"`
	Repo        string   `json:"repo"`
	SecretTypes []string `json:"secretTypes"`
	Value       string   `json:"value,omitempty"`
}

// SearchArtifacts searches artifacts using AQL
func (p *Platform) SearchArtifacts(ctx context.Context, opts ArtifactSearchOptions) ([]AQLResult, error) {
	// Build AQL query
	aql := buildAQLQuery(opts.Name, opts.Repo, opts.Type, opts.Limit)

	resp, err := p.client.PostAQL(ctx, aql)
	if err != nil {
		return nil, fmt.Errorf("searching artifacts: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	var aqlResp AQLResponse
	if err := json.NewDecoder(resp.Body).Decode(&aqlResp); err != nil {
		return []AQLResult{}, fmt.Errorf("decoding response: %w", err)
	}

	if aqlResp.Results == nil {
		return []AQLResult{}, nil
	}

	return aqlResp.Results, nil
}

// DownloadArtifacts downloads artifacts with limits
func (p *Platform) DownloadArtifacts(ctx context.Context, opts ArtifactDownloadOptions) (DownloadResult, error) {
	result := DownloadResult{}

	// Parse limits
	maxFileSize := parseSize(opts.MaxFileSize)
	maxTotal := parseSize(opts.MaxTotal)

	// Build AQL query to list files
	aql := fmt.Sprintf(`items.find({"repo":%q`, opts.Repo)
	if opts.Path != "" {
		aql += fmt.Sprintf(`,"path":{"$match":"*%s*"}`, opts.Path)
	}
	aql += `}).limit(1000)`

	resp, err := p.client.PostAQL(ctx, aql)
	if err != nil {
		return result, fmt.Errorf("searching artifacts: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return result, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	var aqlResp AQLResponse
	if err := json.NewDecoder(resp.Body).Decode(&aqlResp); err != nil {
		return result, fmt.Errorf("decoding response: %w", err)
	}

	if len(aqlResp.Results) == 0 {
		return result, nil
	}

	// Create output directory
	if err := os.MkdirAll(opts.OutputDir, 0o755); err != nil {
		return result, fmt.Errorf("creating output directory: %w", err)
	}

	var totalDownloaded int64

	for _, artifact := range aqlResp.Results {
		// Check file size limit
		if maxFileSize > 0 && artifact.Size > maxFileSize {
			result.Skipped++
			continue
		}

		// Check total size limit
		if maxTotal > 0 && totalDownloaded+artifact.Size > maxTotal {
			break
		}

		// Check file count limit
		if opts.MaxFiles > 0 && result.FilesDownloaded >= opts.MaxFiles {
			break
		}

		// Download artifact
		artifactPath := fmt.Sprintf("/artifactory/%s/%s/%s", artifact.Repo, artifact.Path, artifact.Name)

		resp, err := p.client.Get(ctx, artifactPath)
		if err != nil {
			continue
		}

		// Create local file with path traversal protection
		localPath := filepath.Join(opts.OutputDir, artifact.Name)
		absLocal, err := filepath.Abs(localPath)
		if err != nil {
			_ = resp.Body.Close()
			continue
		}
		absDir, err := filepath.Abs(opts.OutputDir)
		if err != nil {
			_ = resp.Body.Close()
			continue
		}
		if !strings.HasPrefix(absLocal, absDir+string(os.PathSeparator)) && absLocal != absDir {
			_ = resp.Body.Close()
			continue
		}
		f, err := os.Create(localPath)
		if err != nil {
			_ = resp.Body.Close()
			return result, fmt.Errorf("creating file %s: %w", localPath, err)
		}

		written, err := io.Copy(f, resp.Body)
		_ = f.Close()
		_ = resp.Body.Close()

		if err != nil {
			_ = os.Remove(localPath)
			continue
		}

		totalDownloaded += written
		result.FilesDownloaded++
	}

	result.TotalSize = totalDownloaded
	return result, nil
}

// ScanArtifactsForSecrets scans artifacts for secrets
func (p *Platform) ScanArtifactsForSecrets(ctx context.Context, repo, mode string) ([]ArtifactSecret, error) {
	// Build AQL query for config files that may contain secrets
	var aql string

	if mode == "selective" || mode == "" {
		// Scan only config-type files
		aql = `items.find({"$and":[
			{"type":"file"},
			{"repo":{"$ne":"jfrog-usage-logs"}},
			{"$or":[
				{"name":{"$match":"*.env"}},
				{"name":{"$match":"*.yaml"}},
				{"name":{"$match":"*.yml"}},
				{"name":{"$match":"*.json"}},
				{"name":{"$match":"*.properties"}},
				{"name":{"$match":"*.conf"}},
				{"name":{"$match":"*.config"}},
				{"name":{"$match":"*secret*"}},
				{"name":{"$match":"*credential*"}}
			]}`
		if repo != "" {
			aql += fmt.Sprintf(`,{"repo":%q}`, repo)
		}
		aql += `]}).include("repo","path","name","size").limit(500)`
	} else {
		// Scan all files (metadata mode)
		aql = `items.find({"type":"file","repo":{"$ne":"jfrog-usage-logs"}}`
		if repo != "" {
			aql = fmt.Sprintf(`items.find({"type":"file","repo":%q}`, repo)
		}
		aql += `).include("repo","path","name","size").limit(500)`
	}

	resp, err := p.client.PostAQL(ctx, aql)
	if err != nil {
		return []ArtifactSecret{}, fmt.Errorf("searching artifacts: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return []ArtifactSecret{}, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	var aqlResp AQLResponse
	if err := json.NewDecoder(resp.Body).Decode(&aqlResp); err != nil {
		return []ArtifactSecret{}, fmt.Errorf("decoding response: %w", err)
	}

	secrets := []ArtifactSecret{}

	for _, artifact := range aqlResp.Results {
		switch mode {
		case "metadata":
			// Scan just the artifact name/path for secret-like patterns
			secretTypes := scanForSecrets(artifact.Name + "/" + artifact.Path)
			if len(secretTypes) > 0 {
				secrets = append(secrets, ArtifactSecret{
					Artifact:    artifact.Name,
					Path:        artifact.Path,
					Repo:        artifact.Repo,
					SecretTypes: secretTypes,
				})
			}

		case "selective", "sample", "":
			// Skip files larger than 1MB
			if artifact.Size > 1024*1024 {
				continue
			}

			// Build download path - handle "." path correctly
			var downloadPath string
			if artifact.Path == "." || artifact.Path == "" {
				downloadPath = fmt.Sprintf("/artifactory/%s/%s", artifact.Repo, artifact.Name)
			} else {
				downloadPath = fmt.Sprintf("/artifactory/%s/%s/%s", artifact.Repo, artifact.Path, artifact.Name)
			}

			resp, err := p.client.Get(ctx, downloadPath)
			if err != nil {
				continue
			}

			if resp.StatusCode != 200 {
				_ = resp.Body.Close()
				continue
			}

			content, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			// Scan content for secrets
			secretTypes := scanForSecrets(string(content))
			if len(secretTypes) > 0 {
				secrets = append(secrets, ArtifactSecret{
					Artifact:    artifact.Name,
					Path:        artifact.Path,
					Repo:        artifact.Repo,
					SecretTypes: secretTypes,
					Value:       maskSecretValue(string(content)),
				})
			}
		}
	}

	return secrets, nil
}

// Helper functions

// buildAQLQuery builds an AQL query from filters
func buildAQLQuery(name, repo, artifactType string, limit int) string {
	var filters []string

	if name != "" {
		// Use name pattern as-is for AQL match
		filters = append(filters, fmt.Sprintf(`"name":{"$match":"%s*"}`, name))
	}

	if repo != "" {
		filters = append(filters, fmt.Sprintf(`"repo":%q`, repo))
	}

	if artifactType != "" {
		filters = append(filters, fmt.Sprintf(`"type":%q`, artifactType))
	}

	filterStr := ""
	if len(filters) > 0 {
		filterStr = ".find({" + strings.Join(filters, ",") + "})"
	} else {
		// When no filters provided, use default wildcard query
		filterStr = `.find({"type":"file"})`
	}

	return fmt.Sprintf(`items%s.limit(%d)`, filterStr, limit)
}

// parseSize parses size strings like "50MB", "1GB" into bytes
func parseSize(s string) int64 {
	if s == "" {
		return 0
	}

	s = strings.ToUpper(strings.TrimSpace(s))
	multiplier := int64(1)

	if strings.HasSuffix(s, "KB") {
		multiplier = 1024
		s = strings.TrimSuffix(s, "KB")
	} else if strings.HasSuffix(s, "MB") {
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "MB")
	} else if strings.HasSuffix(s, "GB") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "GB")
	}

	value, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}

	return value * multiplier
}

// secretPatterns defines patterns for detecting secrets
var secretPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"credential", regexp.MustCompile(`(?i)(credential|password|secret|token|key|api_key)`)},
	{"aws", regexp.MustCompile(`(?i)(aws_access_key|aws_secret|AKIA[0-9A-Z]{16})`)},
	{"private_key", regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`)},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+`)},
}

// scanForSecrets scans content for secret patterns
func scanForSecrets(content string) []string {
	var types []string
	for _, sp := range secretPatterns {
		if sp.Pattern.MatchString(content) {
			types = append(types, sp.Name)
		}
	}
	return types
}

// maskSecretValue returns the secret value for display
// Note: In a red team context, we want to see full values
func maskSecretValue(content string) string {
	return content
}
