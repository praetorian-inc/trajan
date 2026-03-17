package runnerexec

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// GeneratePipelineYAML generates .gitlab-ci.yml for command execution
// Targets runners with specified tags and base64-encodes output
func GeneratePipelineYAML(runnerTags []string, command string) (string, error) {
	// Validate inputs
	if len(runnerTags) == 0 {
		return "", fmt.Errorf("runnerTags cannot be empty")
	}
	if command == "" {
		return "", fmt.Errorf("command cannot be empty")
	}
	if strings.ContainsAny(command, "\n\r") {
		return "", fmt.Errorf("command cannot contain line breaks: %q", command)
	}

	// Validate runner tags don't contain line breaks (breaks YAML structure)
	for _, tag := range runnerTags {
		if strings.ContainsAny(tag, "\n\r") {
			return "", fmt.Errorf("runner tags cannot contain line breaks: %q", tag)
		}
	}

	// Use yaml.Marshal for safe serialization of tags (prevents YAML injection
	// via metacharacters like ':', '#', '{', etc.)
	pipeline := map[string]interface{}{
		"runner-exec-job": map[string]interface{}{
			"tags":   runnerTags,
			"script": []string{fmt.Sprintf("(%s) 2>&1 | base64 || true", command)},
		},
	}

	yamlBytes, err := yaml.Marshal(pipeline)
	if err != nil {
		return "", fmt.Errorf("marshaling pipeline YAML: %w", err)
	}

	return string(yamlBytes), nil
}
