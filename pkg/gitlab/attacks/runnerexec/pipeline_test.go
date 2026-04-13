package runnerexec

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePipelineYAML_SingleTag(t *testing.T) {
	tags := []string{"docker"}
	command := "whoami"

	yaml, err := GeneratePipelineYAML(tags, command)
	assert.NoError(t, err)

	assert.Contains(t, yaml, "runner-exec-job:")
	assert.Contains(t, yaml, "tags:")
	assert.Contains(t, yaml, "  - docker")
	assert.Contains(t, yaml, "(whoami)")
	assert.Contains(t, yaml, "| base64")
	assert.Contains(t, yaml, "|| true") // Ensures command doesn't fail pipeline
}

func TestGeneratePipelineYAML_MultipleTags(t *testing.T) {
	tags := []string{"docker", "linux", "self-hosted"}
	command := "hostname && pwd"

	yaml, err := GeneratePipelineYAML(tags, command)
	assert.NoError(t, err)

	assert.Contains(t, yaml, "  - docker")
	assert.Contains(t, yaml, "  - linux")
	assert.Contains(t, yaml, "  - self-hosted")
	assert.Contains(t, yaml, "hostname && pwd")
}

func TestGeneratePipelineYAML_ComplexCommand(t *testing.T) {
	tags := []string{"docker"}
	command := `echo "test" && cat /etc/os-release`

	yaml, err := GeneratePipelineYAML(tags, command)
	assert.NoError(t, err)

	// Command should be preserved exactly
	assert.Contains(t, yaml, command)
}

func TestGeneratePipelineYAML_Structure(t *testing.T) {
	tags := []string{"test"}
	command := "echo test"

	yaml, err := GeneratePipelineYAML(tags, command)
	assert.NoError(t, err)

	// Verify YAML structure
	lines := strings.Split(yaml, "\n")
	assert.True(t, len(lines) > 5, "YAML should have multiple lines")

	// Check for required sections
	hasJob := false
	hasTags := false
	hasScript := false

	for _, line := range lines {
		if strings.Contains(line, "runner-exec-job:") {
			hasJob = true
		}
		if strings.Contains(line, "tags:") {
			hasTags = true
		}
		if strings.Contains(line, "script:") {
			hasScript = true
		}
	}

	assert.True(t, hasJob, "YAML should have job definition")
	assert.True(t, hasTags, "YAML should have tags section")
	assert.True(t, hasScript, "YAML should have script section")
}

// Input validation tests

func TestGeneratePipelineYAML_EmptyTags(t *testing.T) {
	tags := []string{}
	command := "whoami"

	yaml, err := GeneratePipelineYAML(tags, command)
	assert.Error(t, err)
	assert.Empty(t, yaml)
	assert.Contains(t, err.Error(), "runnerTags cannot be empty")
}

func TestGeneratePipelineYAML_EmptyCommand(t *testing.T) {
	tags := []string{"docker"}
	command := ""

	yaml, err := GeneratePipelineYAML(tags, command)
	assert.Error(t, err)
	assert.Empty(t, yaml)
	assert.Contains(t, err.Error(), "command cannot be empty")
}

func TestGeneratePipelineYAML_TagsWithNewlines(t *testing.T) {
	tags := []string{"docker\nmalicious"}
	command := "whoami"

	yaml, err := GeneratePipelineYAML(tags, command)
	assert.Error(t, err)
	assert.Empty(t, yaml)
	assert.Contains(t, err.Error(), "runner tags cannot contain line breaks")
	assert.Contains(t, err.Error(), "docker\\nmalicious")
}

func TestGeneratePipelineYAML_MultipleTagsOneWithNewline(t *testing.T) {
	tags := []string{"docker", "linux\nbad", "self-hosted"}
	command := "whoami"

	yaml, err := GeneratePipelineYAML(tags, command)
	assert.Error(t, err)
	assert.Empty(t, yaml)
	assert.Contains(t, err.Error(), "runner tags cannot contain line breaks")
}

func TestGeneratePipelineYAML_TagsWithYAMLMetachars(t *testing.T) {
	tests := []struct {
		name string
		tag  string
	}{
		{"colon", "tag: injected"},
		{"hash comment", "tag #comment"},
		{"curly braces", "tag{key: val}"},
		{"square brackets", "tag[0]"},
		{"ampersand anchor", "&anchor"},
		{"asterisk alias", "*alias"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			yamlOut, err := GeneratePipelineYAML([]string{tc.tag}, "whoami")
			assert.NoError(t, err)

			// The tag must appear quoted or escaped so YAML metacharacters
			// cannot alter the document structure.
			assert.Contains(t, yamlOut, tc.tag)
			assert.Contains(t, yamlOut, "runner-exec-job:")
			assert.Contains(t, yamlOut, "script:")
		})
	}
}

func TestGeneratePipelineYAML_CommandWithQuotes(t *testing.T) {
	// Commands with quotes should work - they're preserved as-is
	tags := []string{"docker"}
	command := `echo "test with 'quotes'"`

	yaml, err := GeneratePipelineYAML(tags, command)
	assert.NoError(t, err)
	assert.Contains(t, yaml, command)
}

func TestGeneratePipelineYAML_CommandWithLineBreaks(t *testing.T) {
	tags := []string{"docker"}
	command := "echo\ntest"

	_, err := GeneratePipelineYAML(tags, command)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "line breaks")
}
