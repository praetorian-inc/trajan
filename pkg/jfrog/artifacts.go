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

type AQLResult struct {
	Repo     string `json:"repo"`
	Path     string `json:"path"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
}

type AQLResponse struct {
	Results []AQLResult `json:"results"`
}

type ArtifactSearchOptions struct {
	Name  string // Artifact name pattern (e.g., *.jar)
	Repo  string
	Type  string // Artifact type (e.g., jar, war)
	Limit int
}

type ArtifactDownloadOptions struct {
	Repo        string
	Path        string
	OutputDir   string
	MaxFileSize string // Maximum file size (e.g., "50MB", "1GB")
	MaxTotal    string
	MaxFiles    int
}

type DownloadResult struct {
	FilesDownloaded int
	TotalSize       int64
	Skipped         int
}

type ArtifactSecret struct {
	Artifact    string   `json:"artifact"`
	Path        string   `json:"path"`
	Repo        string   `json:"repo"`
	SecretTypes []string `json:"secretTypes"`
	Value       string   `json:"value,omitempty"`
}

func (p *Platform) SearchArtifacts(ctx context.Context, opts ArtifactSearchOptions) ([]AQLResult, error) {
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

func (p *Platform) DownloadArtifacts(ctx context.Context, opts ArtifactDownloadOptions) (DownloadResult, error) {
	result := DownloadResult{}

	maxFileSize := parseSize(opts.MaxFileSize)
	maxTotal := parseSize(opts.MaxTotal)

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

	if err := os.MkdirAll(opts.OutputDir, 0o755); err != nil {
		return result, fmt.Errorf("creating output directory: %w", err)
	}

	var totalDownloaded int64

	for _, artifact := range aqlResp.Results {
		if maxFileSize > 0 && artifact.Size > maxFileSize {
			result.Skipped++
			continue
		}

		if maxTotal > 0 && totalDownloaded+artifact.Size > maxTotal {
			break
		}

		if opts.MaxFiles > 0 && result.FilesDownloaded >= opts.MaxFiles {
			break
		}

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

func (p *Platform) ScanArtifactsForSecrets(ctx context.Context, repo, mode string) ([]ArtifactSecret, error) {
	var aql string

	if mode == "selective" || mode == "" {
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
			if artifact.Size > 1024*1024 {
				continue
			}

			// AQL reports a root-level file with path "." or empty.
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

func buildAQLQuery(name, repo, artifactType string, limit int) string {
	var filters []string

	if name != "" {
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
		filterStr = `.find({"type":"file"})`
	}

	return fmt.Sprintf(`items%s.limit(%d)`, filterStr, limit)
}

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

var secretPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"credential", regexp.MustCompile(`(?i)(credential|password|secret|token|key|api_key)`)},
	{"aws", regexp.MustCompile(`(?i)(aws_access_key|aws_secret|AKIA[0-9A-Z]{16})`)},
	{"private_key", regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`)},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+`)},
}

func scanForSecrets(content string) []string {
	var types []string
	for _, sp := range secretPatterns {
		if sp.Pattern.MatchString(content) {
			types = append(types, sp.Name)
		}
	}
	return types
}

// Does not mask: an assessment report needs the full value.
func maskSecretValue(content string) string {
	return content
}
