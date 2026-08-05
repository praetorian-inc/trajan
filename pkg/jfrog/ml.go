package jfrog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
)

type ModelInfo struct {
	Name         string `json:"name"`
	Path         string `json:"path"`
	Size         int64  `json:"size"`
	LastModified string `json:"lastModified"`
}

type MLRepoInfo struct {
	Key         string `json:"key"`
	Type        string `json:"type"`
	Description string `json:"description"`
	PackageType string `json:"packageType"`
	Notes       string `json:"notes,omitempty"`
}

type MLSecret struct {
	FilePath    string `json:"filePath"`
	SecretType  string `json:"secretType"`
	MaskedValue string `json:"maskedValue"`
}

// From the Artifactory storage API.
type storageItem struct {
	Repo         string `json:"repo"`
	Path         string `json:"path"`
	Created      string `json:"created"`
	LastModified string `json:"lastModified,omitempty"`
	Size         string `json:"size,omitempty"`
	Children     []struct {
		URI    string `json:"uri"`
		Folder bool   `json:"folder"`
	} `json:"children,omitempty"`
}

func (p *Platform) ScanMLModels(ctx context.Context, repo string) ([]ModelInfo, error) {
	return p.scanModelsRecursive(ctx, repo, "/")
}

func (p *Platform) scanModelsRecursive(ctx context.Context, repo, path string) ([]ModelInfo, error) {
	models := []ModelInfo{}

	resp, err := p.client.Get(ctx, fmt.Sprintf("/api/storage/%s%s", repo, path))
	if err != nil {
		return []ModelInfo{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return models, nil // Skip if can't access
	}

	var storage storageItem
	if err := json.NewDecoder(resp.Body).Decode(&storage); err != nil {
		return []ModelInfo{}, err
	}

	for _, child := range storage.Children {
		childPath := path
		if !strings.HasSuffix(childPath, "/") {
			childPath += "/"
		}
		childPath += strings.TrimPrefix(child.URI, "/")

		if child.Folder {
			subModels, err := p.scanModelsRecursive(ctx, repo, childPath)
			if err != nil {
				continue // Skip errors in subdirectories
			}
			models = append(models, subModels...)
		} else {
			fileResp, err := p.client.Get(ctx, fmt.Sprintf("/api/storage/%s%s", repo, childPath))
			if err != nil {
				continue
			}

			var fileInfo storageItem
			_ = json.NewDecoder(fileResp.Body).Decode(&fileInfo)
			_ = fileResp.Body.Close()

			size, _ := strconv.ParseInt(fileInfo.Size, 10, 64)

			models = append(models, ModelInfo{
				Name:         childPath,
				Path:         childPath,
				Size:         size,
				LastModified: fileInfo.LastModified,
			})
		}
	}

	return models, nil
}

func (p *Platform) GetMLRepositories(ctx context.Context) ([]MLRepoInfo, error) {
	resp, err := p.client.Get(ctx, "/api/repositories?type=local&packageType=generic")
	if err != nil {
		return nil, fmt.Errorf("getting repositories: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	var repos []MLRepoInfo
	if err := json.NewDecoder(resp.Body).Decode(&repos); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	mlRepos := []MLRepoInfo{}
	for _, repo := range repos {
		isML := strings.Contains(strings.ToLower(repo.Key), "ml") ||
			strings.Contains(strings.ToLower(repo.Key), "model") ||
			strings.Contains(strings.ToLower(repo.Description), "ml") ||
			strings.Contains(strings.ToLower(repo.Description), "model") ||
			strings.Contains(strings.ToLower(repo.Description), "machine learning") ||
			strings.Contains(strings.ToLower(repo.Notes), "ml") ||
			strings.Contains(strings.ToLower(repo.Notes), "model")

		if isML {
			mlRepos = append(mlRepos, repo)
		}
	}

	return mlRepos, nil
}

func (p *Platform) ScanMLSecretsInConfig(ctx context.Context, repo string) ([]MLSecret, error) {
	return p.scanForSecretsRecursive(ctx, repo, "/")
}

func (p *Platform) scanForSecretsRecursive(ctx context.Context, repo, path string) ([]MLSecret, error) {
	secrets := []MLSecret{}

	resp, err := p.client.Get(ctx, fmt.Sprintf("/api/storage/%s%s", repo, path))
	if err != nil {
		return []MLSecret{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return secrets, nil
	}

	var storage storageItem
	if err := json.NewDecoder(resp.Body).Decode(&storage); err != nil {
		return []MLSecret{}, err
	}

	for _, child := range storage.Children {
		childPath := path
		if !strings.HasSuffix(childPath, "/") {
			childPath += "/"
		}
		childPath += strings.TrimPrefix(child.URI, "/")

		if child.Folder {
			subSecrets, err := p.scanForSecretsRecursive(ctx, repo, childPath)
			if err != nil {
				continue
			}
			secrets = append(secrets, subSecrets...)
		} else {
			filename := strings.ToLower(filepath.Base(childPath))
			isMLConfig := filename == ".mlflow" ||
				filename == "mlflow.yml" ||
				filename == "mlflow.yaml" ||
				filename == "ml-config.yml" ||
				filename == "ml-config.yaml" ||
				strings.HasSuffix(filename, "config.yaml") ||
				strings.HasSuffix(filename, "config.yml")

			if isMLConfig {
				fileSecrets := p.scanFile(ctx, repo, childPath)
				secrets = append(secrets, fileSecrets...)
			}
		}
	}

	return secrets, nil
}

func (p *Platform) scanFile(ctx context.Context, repo, path string) []MLSecret {
	var secrets []MLSecret

	// A non-/api/ path, since client.Get prepends /artifactory only for /api/ paths.
	downloadPath := fmt.Sprintf("/artifactory/%s%s", repo, path)
	resp, err := p.client.Get(ctx, downloadPath)
	if err != nil {
		return secrets
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return secrets
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return secrets
	}

	contentStr := string(content)
	for _, sp := range secretPatterns {
		matches := sp.Pattern.FindAllString(contentStr, -1)
		for _, match := range matches {
			secrets = append(secrets, MLSecret{
				FilePath:    path,
				SecretType:  sp.Name,
				MaskedValue: maskSecretValue(match),
			})
		}
	}

	return secrets
}
