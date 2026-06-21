package jfrog

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/detections/shared/secrets"
)

// ExtractRemoteRepoCredentials extracts credentials from remote repositories
func (p *Platform) ExtractRemoteRepoCredentials(ctx context.Context) ([]RemoteRepoCredentials, error) {
	// Get all repos
	resp, err := p.client.Get(ctx, "/api/repositories")
	if err != nil {
		return nil, fmt.Errorf("listing repositories: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (%d) listing repositories", resp.StatusCode)
	}

	var repos []Repository
	if err := json.NewDecoder(resp.Body).Decode(&repos); err != nil {
		return nil, fmt.Errorf("parsing repositories response: %w", err)
	}

	// Filter remote repos and get their configs
	results := []RemoteRepoCredentials{}
	for _, repo := range repos {
		if repo.Type != "REMOTE" {
			continue
		}

		repoResp, err := p.client.Get(ctx, "/api/repositories/"+repo.Key)
		if err != nil {
			continue
		}

		if repoResp.StatusCode != http.StatusOK {
			_ = repoResp.Body.Close()
			continue
		}

		var repoConfig struct {
			Key      string `json:"key"`
			URL      string `json:"url"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(repoResp.Body).Decode(&repoConfig); err != nil {
			_ = repoResp.Body.Close()
			continue
		}
		_ = repoResp.Body.Close()

		result := RemoteRepoCredentials{
			Key:      repoConfig.Key,
			URL:      repoConfig.URL,
			Username: repoConfig.Username,
			Password: repoConfig.Password,
			HasCreds: repoConfig.Username != "" || repoConfig.Password != "",
		}
		results = append(results, result)
	}

	return results, nil
}

// GetAPIKey retrieves the current user's API key
func (p *Platform) GetAPIKey(ctx context.Context) (string, error) {
	resp, err := p.client.Get(ctx, "/api/security/apiKey")
	if err != nil {
		return "", fmt.Errorf("getting API key: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API error (%d) getting API key", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("parsing API key response: %w", err)
	}

	if apiKey, ok := result["apiKey"].(string); ok {
		return apiKey, nil
	}

	return "", nil
}

// GetLDAPConfig retrieves LDAP configuration
func (p *Platform) GetLDAPConfig(ctx context.Context) ([]LDAPSetting, error) {
	resp, err := p.client.Get(ctx, "/api/system/configuration")
	if err != nil {
		return nil, fmt.Errorf("getting config: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("access denied: admin privileges required")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (%d) getting config", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading config response: %w", err)
	}

	var config LDAPConfig
	if err := xml.Unmarshal(body, &config); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return config.Security.LdapSettings.Settings, nil
}

// ScanBuildsForSecrets scans builds for secrets
func (p *Platform) ScanBuildsForSecrets(ctx context.Context, limit int) ([]BuildSecret, error) {
	// Get build list
	resp, err := p.client.Get(ctx, "/api/build")
	if err != nil {
		return nil, fmt.Errorf("listing builds: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (%d) listing builds", resp.StatusCode)
	}

	var buildList struct {
		Builds []struct {
			URI string `json:"uri"`
		} `json:"builds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&buildList); err != nil {
		return nil, fmt.Errorf("parsing build list response: %w", err)
	}

	detector := secrets.New()
	allSecrets := []BuildSecret{}

	// For each build, get build numbers and scan
	for _, build := range buildList.Builds {
		// API returns URI as "/build-name" not "/api/build/build-name"
		buildName := strings.TrimPrefix(build.URI, "/")

		// Get build numbers
		resp, err := p.client.Get(ctx, fmt.Sprintf("/api/build/%s", url.PathEscape(buildName)))
		if err != nil {
			continue
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			continue
		}

		var buildNumbers struct {
			BuildsNumbers []struct {
				URI string `json:"uri"`
			} `json:"buildsNumbers"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&buildNumbers); err != nil {
			_ = resp.Body.Close()
			continue
		}
		_ = resp.Body.Close()

		// Limit build numbers scanned per project
		numToScan := limit
		if numToScan > len(buildNumbers.BuildsNumbers) {
			numToScan = len(buildNumbers.BuildsNumbers)
		}

		// For each build number (up to limit), get build info and scan
		for i := 0; i < numToScan; i++ {
			buildNum := buildNumbers.BuildsNumbers[i]
			// API returns URI as "/42" not "/api/build/build-name/42"
			buildNumber := strings.TrimPrefix(buildNum.URI, "/")

			// Get build info
			resp, err := p.client.Get(ctx, fmt.Sprintf("/api/build/%s/%s", url.PathEscape(buildName), url.PathEscape(buildNumber)))
			if err != nil {
				continue
			}

			if resp.StatusCode != http.StatusOK {
				_ = resp.Body.Close()
				continue
			}

			var buildInfo struct {
				BuildInfo struct {
					Properties map[string]string `json:"properties"`
				} `json:"buildInfo"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&buildInfo); err != nil {
				_ = resp.Body.Close()
				continue
			}
			_ = resp.Body.Close()

			// Scan properties for secrets
			for key, value := range buildInfo.BuildInfo.Properties {
				if strings.HasPrefix(key, "buildInfo.env.") {
					envName := strings.TrimPrefix(key, "buildInfo.env.")

					// Check for secrets using detector
					matches := detector.DetectSecretPattern(value)
					if len(matches) > 0 {
						secretTypes := make([]string, len(matches))
						for i, m := range matches {
							secretTypes[i] = m.Pattern
						}

						allSecrets = append(allSecrets, BuildSecret{
							BuildName:   buildName,
							BuildNumber: buildNumber,
							EnvVar:      envName,
							Value:       value,
							SecretTypes: secretTypes,
						})
					}
				}
			}
		}
	}

	return allSecrets, nil
}
