package azuredevops

import (
	"context"
	"regexp"
	"strings"
)

// commonYAMLPaths are the typical locations for Azure DevOps pipeline YAML files
var commonYAMLPaths = []string{
	"/azure-pipelines.yml",
	"/azure-pipelines.yaml",
	"/.azure-pipelines/azure-pipelines.yml",
	"/.azure-pipelines/azure-pipelines.yaml",
	"/pipelines/azure-pipelines.yml",
	"/build/azure-pipelines.yml",
}

// extractServiceConnectionsFromYAML parses YAML content and extracts service connection references with metadata
func extractServiceConnectionsFromYAML(content, repoName, filePath string) []DiscoveredServiceConnection {
	var connections []DiscoveredServiceConnection
	seen := make(map[string]bool) // Track name+type to avoid duplicates

	// Direct field patterns (case-insensitive)
	// Order matters: more specific patterns should come before generic ones
	patterns := []struct {
		regex     *regexp.Regexp
		usageType string
	}{
		{regexp.MustCompile(`(?i)dockerRegistryServiceConnection:\s*['"]([^'"$]+)['"]`), "dockerRegistryServiceConnection"},
		{regexp.MustCompile(`(?i)kubernetesServiceConnection:\s*['"]([^'"$]+)['"]`), "kubernetesServiceConnection"},
		{regexp.MustCompile(`(?i)connectedServiceNameARM:\s*['"]([^'"$]+)['"]`), "connectedServiceNameARM"},
		{regexp.MustCompile(`(?i)connectedServiceName:\s*['"]([^'"$]+)['"]`), "connectedServiceName"},
		{regexp.MustCompile(`(?i)azureSubscription:\s*['"]([^'"$]+)['"]`), "azureSubscription"},
		{regexp.MustCompile(`(?i)containerRegistry:\s*['"]([^'"$]+)['"]`), "containerRegistry"},
		{regexp.MustCompile(`(?i)awsCredentials:\s*['"]([^'"$]+)['"]`), "awsCredentials"},
		{regexp.MustCompile(`(?i)sshEndpoint:\s*['"]([^'"$]+)['"]`), "sshEndpoint"},
		// Generic serviceConnection pattern last (after more specific ones)
		{regexp.MustCompile(`(?i)(?:^|[^a-zA-Z])serviceConnection:\s*['"]([^'"$]+)['"]`), "serviceConnection"},
	}

	for _, p := range patterns {
		matches := p.regex.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 && match[1] != "" {
				key := match[1] + "|" + p.usageType
				if !seen[key] {
					seen[key] = true
					connections = append(connections, DiscoveredServiceConnection{
						Name:       match[1],
						Repository: repoName,
						FilePath:   filePath,
						UsageType:  p.usageType,
					})
				}
			}
		}
	}

	// Parameter default patterns for SERVICE_CONNECTION variables
	paramPattern := regexp.MustCompile(`(?i)-\s*name:\s*\w*SERVICE_CONNECTION\w*\s*\n\s*(?:type:\s*\w+\s*\n\s*)?default:\s*['"]([^'"]+)['"]`)
	for _, match := range paramPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 && match[1] != "" {
			connections = append(connections, DiscoveredServiceConnection{
				Name:       match[1],
				Repository: repoName,
				FilePath:   filePath,
				UsageType:  "parameter-default",
			})
		}
	}

	// Azure subscription parameter defaults
	azureParamPattern := regexp.MustCompile(`(?i)-\s*name:\s*\w*(?:azure|subscription)\w*\s*\n\s*(?:type:\s*\w+\s*\n\s*)?default:\s*['"]([^'"]+)['"]`)
	for _, match := range azureParamPattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 && match[1] != "" && !strings.Contains(strings.ToLower(match[1]), "pool") {
			connections = append(connections, DiscoveredServiceConnection{
				Name:       match[1],
				Repository: repoName,
				FilePath:   filePath,
				UsageType:  "parameter-default",
			})
		}
	}

	return connections
}

// DiscoverServiceConnectionsFromYAML scans pipeline YAML files across repos to discover service connections.
// This is useful when the service connections API returns empty due to permission restrictions.
func (c *Client) DiscoverServiceConnectionsFromYAML(ctx context.Context, project string) ([]DiscoveredServiceConnection, error) {
	repos, err := c.ListRepositories(ctx, project)
	if err != nil {
		return nil, err
	}

	discovered := make(map[string]DiscoveredServiceConnection)

	for _, repo := range repos {
		for _, yamlPath := range commonYAMLPaths {
			content, err := c.GetRepoFileContent(ctx, project, repo.Name, yamlPath)
			if err != nil || content == "" {
				continue
			}

			connections := extractServiceConnectionsFromYAML(content, repo.Name, yamlPath)
			for _, conn := range connections {
				if _, exists := discovered[conn.Name]; !exists {
					discovered[conn.Name] = conn
				}
			}
		}
	}

	var result []DiscoveredServiceConnection
	for _, conn := range discovered {
		result = append(result, conn)
	}
	return result, nil
}
