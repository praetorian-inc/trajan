package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseIncludeMap_SingleFileProject(t *testing.T) {
	p := &GitLabParser{}
	m := map[string]interface{}{
		"project": "devops/ci-cd/pipelines",
		"ref":     "latest",
		"file":    "terraform/terraform.yml",
	}

	result := p.parseIncludeMap(m)
	require.Len(t, result, 1)
	assert.Equal(t, IncludeTypeProject, result[0].Type)
	assert.Equal(t, "devops/ci-cd/pipelines", result[0].Project)
	assert.Equal(t, "terraform/terraform.yml", result[0].Path)
	assert.Equal(t, "latest", result[0].Ref)
}

func TestParseIncludeMap_MultiFileProject(t *testing.T) {
	p := &GitLabParser{}
	m := map[string]interface{}{
		"project": "devops/ci-cd/pipelines",
		"ref":     "latest",
		"file": []interface{}{
			"terraform/terraform.yml",
			"terraform/deploy/continuous.yml",
		},
	}

	result := p.parseIncludeMap(m)
	require.Len(t, result, 2)

	assert.Equal(t, IncludeTypeProject, result[0].Type)
	assert.Equal(t, "devops/ci-cd/pipelines", result[0].Project)
	assert.Equal(t, "terraform/terraform.yml", result[0].Path)
	assert.Equal(t, "latest", result[0].Ref)

	assert.Equal(t, IncludeTypeProject, result[1].Type)
	assert.Equal(t, "devops/ci-cd/pipelines", result[1].Project)
	assert.Equal(t, "terraform/deploy/continuous.yml", result[1].Path)
	assert.Equal(t, "latest", result[1].Ref)
}

func TestParseIncludeMap_ProjectNoFile(t *testing.T) {
	p := &GitLabParser{}
	m := map[string]interface{}{
		"project": "devops/ci-cd/pipelines",
		"ref":     "main",
	}

	result := p.parseIncludeMap(m)
	require.Len(t, result, 1)
	assert.Equal(t, IncludeTypeProject, result[0].Type)
	assert.Equal(t, "devops/ci-cd/pipelines", result[0].Project)
	assert.Equal(t, "", result[0].Path)
	assert.Equal(t, "main", result[0].Ref)
}

func TestParseIncludeMap_Local(t *testing.T) {
	p := &GitLabParser{}
	m := map[string]interface{}{
		"local": "/templates/build.yml",
	}

	result := p.parseIncludeMap(m)
	require.Len(t, result, 1)
	assert.Equal(t, IncludeTypeLocal, result[0].Type)
	assert.Equal(t, "/templates/build.yml", result[0].Path)
}

func TestParseIncludeMap_Remote(t *testing.T) {
	p := &GitLabParser{}
	m := map[string]interface{}{
		"remote": "https://example.com/ci/template.yml",
	}

	result := p.parseIncludeMap(m)
	require.Len(t, result, 1)
	assert.Equal(t, IncludeTypeRemote, result[0].Type)
	assert.Equal(t, "https://example.com/ci/template.yml", result[0].Remote)
}

func TestParseIncludeMap_Template(t *testing.T) {
	p := &GitLabParser{}
	m := map[string]interface{}{
		"template": "Auto-DevOps.gitlab-ci.yml",
	}

	result := p.parseIncludeMap(m)
	require.Len(t, result, 1)
	assert.Equal(t, IncludeTypeTemplate, result[0].Type)
	assert.Equal(t, "Auto-DevOps.gitlab-ci.yml", result[0].Template)
}

func TestParseIncludes_MixedWithMultiFile(t *testing.T) {
	p := &GitLabParser{}

	// Simulates:
	// include:
	//   - local: /templates/build.yml
	//   - project: devops/ci-cd/pipelines
	//     ref: latest
	//     file:
	//       - terraform/terraform.yml
	//       - terraform/deploy/continuous.yml
	raw := []interface{}{
		map[string]interface{}{
			"local": "/templates/build.yml",
		},
		map[string]interface{}{
			"project": "devops/ci-cd/pipelines",
			"ref":     "latest",
			"file": []interface{}{
				"terraform/terraform.yml",
				"terraform/deploy/continuous.yml",
			},
		},
	}

	result := p.parseIncludes(raw)
	require.Len(t, result, 3)

	assert.Equal(t, IncludeTypeLocal, result[0].Type)
	assert.Equal(t, "/templates/build.yml", result[0].Path)

	assert.Equal(t, IncludeTypeProject, result[1].Type)
	assert.Equal(t, "terraform/terraform.yml", result[1].Path)

	assert.Equal(t, IncludeTypeProject, result[2].Type)
	assert.Equal(t, "terraform/deploy/continuous.yml", result[2].Path)
}
