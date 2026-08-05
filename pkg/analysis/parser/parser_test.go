package parser

import (
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetRegistry clears the parser registry for clean test state
func resetRegistry() {
	parserRegistry = make(map[string]WorkflowParser)
}

// mockParser is a test implementation of WorkflowParser
type mockParser struct {
	platform string
	canParse func(string) bool
}

func (m *mockParser) Platform() string {
	return m.platform
}

func (m *mockParser) CanParse(path string) bool {
	if m.canParse != nil {
		return m.canParse(path)
	}
	return false
}

func (m *mockParser) Parse(data []byte) (*NormalizedWorkflow, error) {
	return &NormalizedWorkflow{
		Platform: m.platform,
		Jobs:     make(map[string]*NormalizedJob),
	}, nil
}

// ============================================================================
// Registry Tests
// ============================================================================

func TestGetParser_Unknown(t *testing.T) {
	resetRegistry()

	// Test retrieval of non-existent parser
	retrieved := GetParser("nonexistent")
	assert.Nil(t, retrieved)
}

func TestDetectParser(t *testing.T) {
	resetRegistry()

	// Register parser that can handle .github/workflows/ paths
	githubParser := &mockParser{
		platform: "github",
		canParse: func(path string) bool {
			return path == ".github/workflows/test.yml"
		},
	}
	RegisterParser(githubParser)

	// Test detection
	detected := DetectParser(".github/workflows/test.yml")
	assert.NotNil(t, detected)
	assert.Equal(t, "github", detected.Platform())
}

func TestDetectParser_NotFound(t *testing.T) {
	resetRegistry()

	// Register parser that doesn't match the path
	parser := &mockParser{
		platform: "github",
		canParse: func(path string) bool {
			return path == ".github/workflows/test.yml"
		},
	}
	RegisterParser(parser)

	// Test with non-matching path
	detected := DetectParser("some/other/path.yml")
	assert.Nil(t, detected)
}

func TestDetectParser_MultipleRegistered(t *testing.T) {
	resetRegistry()

	// Register multiple parsers
	githubParser := &mockParser{
		platform: "github",
		canParse: func(path string) bool {
			return path == ".github/workflows/test.yml"
		},
	}
	gitlabParser := &mockParser{
		platform: "gitlab",
		canParse: func(path string) bool {
			return path == ".gitlab-ci.yml"
		},
	}
	RegisterParser(githubParser)
	RegisterParser(gitlabParser)

	// Test GitHub path detection
	detected := DetectParser(".github/workflows/test.yml")
	assert.NotNil(t, detected)
	assert.Equal(t, "github", detected.Platform())

	// Test GitLab path detection
	detected = DetectParser(".gitlab-ci.yml")
	assert.NotNil(t, detected)
	assert.Equal(t, "gitlab", detected.Platform())
}

func TestConcurrentParserRegistration(t *testing.T) {
	resetRegistry()

	parserCount := 50
	var wg sync.WaitGroup

	// Register parsers concurrently
	for i := 0; i < parserCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			platform := string(rune('a' + (id % 26)))
			RegisterParser(&mockParser{platform: platform})
		}(i)
	}

	wg.Wait()

	// Verify registrations succeeded by fetching each
	for i := 0; i < parserCount; i++ {
		platform := string(rune('a' + (i % 26)))
		p := GetParser(platform)
		assert.NotNil(t, p, "Failed to get parser for platform: %s", platform)
	}
}

// TestParserRegistryRaceConditions tests all registry operations under high concurrency
// This test will fail with -race flag if mutex protection is missing
func TestParserRegistryRaceConditions(t *testing.T) {
	resetRegistry()

	const goroutines = 10
	const operations = 100
	var wg sync.WaitGroup

	// Register initial parser for reading tests
	RegisterParser(&mockParser{
		platform: "test",
		canParse: func(path string) bool {
			return path == "test.yml"
		},
	})

	// Concurrent writes (RegisterParser)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < operations; j++ {
				parser := &mockParser{
					platform: "test",
					canParse: func(path string) bool {
						return path == "test.yml"
					},
				}
				RegisterParser(parser)
			}
		}()
	}

	// Concurrent reads (GetParser)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < operations; j++ {
				_ = GetParser("test")
			}
		}()
	}

	// Concurrent reads (DetectParser)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < operations; j++ {
				_ = DetectParser("test.yml")
			}
		}()
	}

	wg.Wait()

	// Verify the registry is still functional after all concurrent operations
	parser := GetParser("test")
	assert.NotNil(t, parser)
	assert.Equal(t, "test", parser.Platform())

	detected := DetectParser("test.yml")
	assert.NotNil(t, detected)
	assert.Equal(t, "test", detected.Platform())
}

// ============================================================================
// GitHubParser Tests
// ============================================================================

func TestGitHubParser_CanParse(t *testing.T) {
	parser := NewGitHubParser()

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "valid GitHub workflow yml",
			path:     ".github/workflows/ci.yml",
			expected: true,
		},
		{
			name:     "valid GitHub workflow yaml",
			path:     ".github/workflows/build.yaml",
			expected: true,
		},
		{
			name:     "nested GitHub workflow",
			path:     ".github/workflows/subdir/test.yml",
			expected: true,
		},
		{
			name:     "absolute path GitHub workflow",
			path:     "/home/user/project/.github/workflows/deploy.yml",
			expected: true,
		},
		{
			name:     "not in workflows directory",
			path:     ".github/ci.yml",
			expected: false,
		},
		{
			name:     "wrong extension",
			path:     ".github/workflows/test.json",
			expected: false,
		},
		{
			name:     "gitlab CI file",
			path:     ".gitlab-ci.yml",
			expected: false,
		},
		{
			name:     "random yaml file",
			path:     "config.yml",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.CanParse(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGitHubParser_Parse_InvalidYAML(t *testing.T) {
	parser := NewGitHubParser()

	invalidYAML := `
name: CI
on: push
jobs:
  build:
    steps: [invalid yaml structure
`

	workflow, err := parser.Parse([]byte(invalidYAML))
	assert.Error(t, err)
	assert.Nil(t, workflow)
	assert.Contains(t, err.Error(), "parsing YAML node")
}

func TestGitHubParser_ParseConvertsToNormalized(t *testing.T) {
	parser := NewGitHubParser()

	yaml := `
name: Full Workflow
on:
  push:
    branches: [main]
  pull_request:
env:
  GLOBAL_VAR: "global"
permissions:
  contents: read
  issues: write
jobs:
  test:
    name: Run Tests
    runs-on: ubuntu-latest
    needs: build
    if: github.event_name == 'push'
    permissions:
      contents: read
    env:
      JOB_VAR: "job"
    outputs:
      result: steps.test.outputs.result
    services:
      postgres:
        image: postgres:14
        env:
          POSTGRES_PASSWORD: secret
        ports:
          - 5432:5432
        options: --health-cmd pg_isready
    steps:
      - id: checkout
        name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: "0"
        env:
          STEP_VAR: "step"
      - name: Test
        run: npm test
        working-directory: ./app
        shell: bash
        continue-on-error: true
        if: success()
  build:
    runs-on: self-hosted
    steps:
      - run: echo "build"
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)
	require.NotNil(t, workflow)

	// Verify normalized workflow structure
	assert.Equal(t, "github", workflow.Platform)
	assert.Equal(t, "Full Workflow", workflow.Name)

	// Verify triggers
	assert.Len(t, workflow.Triggers, 2)
	assert.Contains(t, workflow.Triggers, "push")
	assert.Contains(t, workflow.Triggers, "pull_request")

	// Verify workflow-level env
	assert.Equal(t, "global", workflow.Env["GLOBAL_VAR"])

	// Verify workflow-level permissions
	require.NotNil(t, workflow.Permissions)
	assert.Equal(t, "read", workflow.Permissions.Scopes["contents"])
	assert.Equal(t, "write", workflow.Permissions.Scopes["issues"])

	// Verify jobs
	assert.Len(t, workflow.Jobs, 2)

	// Test job details
	testJob := workflow.Jobs["test"]
	require.NotNil(t, testJob)
	assert.Equal(t, "test", testJob.ID)
	assert.Equal(t, "Run Tests", testJob.Name)
	assert.Equal(t, "ubuntu-latest", testJob.RunsOn)
	assert.Equal(t, []string{"build"}, testJob.Needs)
	assert.Equal(t, "github.event_name == 'push'", testJob.Condition)

	// Verify job-level env
	assert.Equal(t, "job", testJob.Env["JOB_VAR"])

	// Verify job outputs
	assert.Equal(t, "steps.test.outputs.result", testJob.Outputs["result"])

	// Verify job permissions
	require.NotNil(t, testJob.Permissions)
	assert.Equal(t, "read", testJob.Permissions.Scopes["contents"])

	// Verify services
	require.Len(t, testJob.Services, 1)
	postgres := testJob.Services["postgres"]
	require.NotNil(t, postgres)
	assert.Equal(t, "postgres:14", postgres.Image)
	assert.Equal(t, "secret", postgres.Env["POSTGRES_PASSWORD"])
	assert.Contains(t, postgres.Ports, "5432:5432")
	assert.Equal(t, "--health-cmd pg_isready", postgres.Options)

	// Verify steps
	require.Len(t, testJob.Steps, 2)

	// First step (uses action)
	step1 := testJob.Steps[0]
	assert.Equal(t, "checkout", step1.ID)
	assert.Equal(t, "Checkout", step1.Name)
	assert.Equal(t, "actions/checkout@v4", step1.Uses)
	assert.Equal(t, "0", step1.With["fetch-depth"])
	assert.Equal(t, "step", step1.Env["STEP_VAR"])

	// Second step (run command)
	step2 := testJob.Steps[1]
	assert.Equal(t, "Test", step2.Name)
	assert.Equal(t, "npm test", step2.Run)
	assert.Equal(t, "./app", step2.WorkingDirectory)
	assert.Equal(t, "bash", step2.Shell)
	assert.True(t, step2.ContinueOnError)
	assert.Equal(t, "success()", step2.Condition)

	// Build job (verify self-hosted runner handling)
	buildJob := workflow.Jobs["build"]
	require.NotNil(t, buildJob)
	assert.Equal(t, "self-hosted", buildJob.RunsOn)

	// Verify raw GitHub workflow is preserved
	assert.NotNil(t, workflow.Raw)
	ghWorkflow, ok := workflow.Raw.(*GitHubWorkflow)
	require.True(t, ok, "Raw should be *GitHubWorkflow")
	assert.Equal(t, "Full Workflow", ghWorkflow.Name)
}

func TestGitHubParser_Parse_MultipleRunsOn(t *testing.T) {
	parser := NewGitHubParser()

	yaml := `
name: Matrix
on: push
jobs:
  test:
    runs-on: [ubuntu-latest, macos-latest]
    steps:
      - run: echo "test"
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)

	// Should take first element of array
	job := workflow.Jobs["test"]
	assert.Equal(t, "ubuntu-latest", job.RunsOn)
}

func TestGitHubParser_Parse_MultipleNeeds(t *testing.T) {
	parser := NewGitHubParser()

	yaml := `
name: Pipeline
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "build"
  test:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - run: echo "test"
  deploy:
    runs-on: ubuntu-latest
    needs: [build, test]
    steps:
      - run: echo "deploy"
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)

	// Build has no dependencies
	assert.Empty(t, workflow.Jobs["build"].Needs)

	// Test depends on build
	assert.Equal(t, []string{"build"}, workflow.Jobs["test"].Needs)

	// Deploy depends on both
	deploy := workflow.Jobs["deploy"]
	assert.Len(t, deploy.Needs, 2)
	assert.Contains(t, deploy.Needs, "build")
	assert.Contains(t, deploy.Needs, "test")
}

func TestGitHubParser_Parse_PermissionsReadAll(t *testing.T) {
	parser := NewGitHubParser()

	yaml := `
name: ReadAll
on: push
permissions: read-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)

	require.NotNil(t, workflow.Permissions)
	assert.True(t, workflow.Permissions.ReadAll)
	assert.False(t, workflow.Permissions.WriteAll)
}

func TestGitHubParser_Parse_PermissionsWriteAll(t *testing.T) {
	parser := NewGitHubParser()

	yaml := `
name: WriteAll
on: push
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)

	require.NotNil(t, workflow.Permissions)
	assert.False(t, workflow.Permissions.ReadAll)
	assert.True(t, workflow.Permissions.WriteAll)
}

func TestGitHubParser_Parse_WorkflowPermissionsInheritedByJob(t *testing.T) {
	parser := NewGitHubParser()

	yaml := `
name: Inherited Perms
on: issue_comment
permissions:
  members: write
  administration: write
  contents: read
jobs:
  admin:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)

	// Workflow-level permissions should be set
	require.NotNil(t, workflow.Permissions)
	assert.Equal(t, "write", workflow.Permissions.Scopes["members"])

	// Job should inherit workflow permissions since it has none of its own
	job := workflow.Jobs["admin"]
	require.NotNil(t, job)
	require.NotNil(t, job.Permissions, "job should inherit workflow-level permissions")
	assert.Equal(t, "write", job.Permissions.Scopes["members"])
	assert.Equal(t, "write", job.Permissions.Scopes["administration"])
	assert.Equal(t, "read", job.Permissions.Scopes["contents"])
}

func TestGitHubParser_Parse_JobPermissionsOverrideWorkflow(t *testing.T) {
	parser := NewGitHubParser()

	yaml := `
name: Overridden Perms
on: push
permissions:
  contents: write
  packages: write
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - run: echo "test"
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)

	// Job has explicit permissions — should NOT inherit workflow level
	job := workflow.Jobs["build"]
	require.NotNil(t, job)
	require.NotNil(t, job.Permissions)
	assert.Equal(t, "read", job.Permissions.Scopes["contents"])
	_, hasPackages := job.Permissions.Scopes["packages"]
	assert.False(t, hasPackages, "job should not inherit packages:write from workflow")
}

func TestGitHubParser_Parse_EmptyJobPermissionsDoNotInherit(t *testing.T) {
	parser := NewGitHubParser()

	yaml := `
name: Empty Job Perms
on: pull_request_target
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - run: echo "test"
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)

	// Explicit empty permissions = read-only, should NOT inherit workflow level
	job := workflow.Jobs["build"]
	require.NotNil(t, job)
	require.NotNil(t, job.Permissions)
	assert.Empty(t, job.Permissions.Scopes, "explicit empty permissions should not inherit workflow scopes")
	assert.False(t, job.Permissions.WriteAll)
}

func TestGitHubParser_Parse_InheritedPermissionsAreCopied(t *testing.T) {
	parser := NewGitHubParser()

	yaml := `
name: Copy Test
on: push
permissions:
  contents: write
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "a"
  b:
    runs-on: ubuntu-latest
    steps:
      - run: echo "b"
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)

	jobA := workflow.Jobs["a"]
	jobB := workflow.Jobs["b"]
	require.NotNil(t, jobA.Permissions)
	require.NotNil(t, jobB.Permissions)

	// Both should have the same values
	assert.Equal(t, "write", jobA.Permissions.Scopes["contents"])
	assert.Equal(t, "write", jobB.Permissions.Scopes["contents"])

	// But they should be independent copies (not the same pointer)
	assert.NotSame(t, jobA.Permissions, jobB.Permissions, "inherited permissions should be independent copies")
	assert.NotSame(t, jobA.Permissions, workflow.Permissions, "inherited permissions should not alias workflow permissions")
}

func TestGitHubParser_Parse_WriteAllInheritedByJob(t *testing.T) {
	parser := NewGitHubParser()

	yaml := `
name: WriteAll Inherit
on: issue_comment
permissions: write-all
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo "deploy"
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)

	require.NotNil(t, workflow.Permissions)
	assert.True(t, workflow.Permissions.WriteAll)

	job := workflow.Jobs["deploy"]
	require.NotNil(t, job)
	require.NotNil(t, job.Permissions, "job should inherit write-all from workflow")
	assert.True(t, job.Permissions.WriteAll, "inherited WriteAll should be true")
}

func TestGitHubParser_Parse_ReadAllInheritedByJob(t *testing.T) {
	parser := NewGitHubParser()

	yaml := `
name: ReadAll Inherit
on: push
permissions: read-all
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: echo "lint"
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)

	require.NotNil(t, workflow.Permissions)
	assert.True(t, workflow.Permissions.ReadAll)

	job := workflow.Jobs["lint"]
	require.NotNil(t, job)
	require.NotNil(t, job.Permissions, "job should inherit read-all from workflow")
	assert.True(t, job.Permissions.ReadAll, "inherited ReadAll should be true")
	assert.False(t, job.Permissions.WriteAll)
}

func TestGitHubParser_Parse_NoWorkflowPermissionsJobStaysNil(t *testing.T) {
	parser := NewGitHubParser()

	yaml := `
name: No Perms
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "build"
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)

	assert.Nil(t, workflow.Permissions, "workflow with no permissions key should be nil")

	job := workflow.Jobs["build"]
	require.NotNil(t, job)
	assert.Nil(t, job.Permissions, "job should remain nil when workflow has no permissions")
}

func TestGitHubParser_Parse_EmptyWorkflow(t *testing.T) {
	parser := NewGitHubParser()

	yaml := `
name: Empty
on: push
jobs: {}
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)

	assert.Equal(t, "Empty", workflow.Name)
	assert.Empty(t, workflow.Jobs)
}

func TestGitHubParser_InitRegistration(t *testing.T) {
	// The init() function in github.go registers the parser
	// Re-register to test the initialization behavior
	RegisterParser(NewGitHubParser())

	// Verify it's registered
	parser := GetParser("github")
	require.NotNil(t, parser, "GitHub parser should be registered")
	assert.Equal(t, "github", parser.Platform())

	// Verify it can parse GitHub Actions paths
	assert.True(t, parser.CanParse(".github/workflows/test.yml"))
}

// ============================================================================
// GitLabParser Tests
// ============================================================================

func TestGitLabParser_CanParse(t *testing.T) {
	parser := NewGitLabParser()

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "valid GitLab CI yml",
			path:     ".gitlab-ci.yml",
			expected: true,
		},
		{
			name:     "valid GitLab CI yaml",
			path:     ".gitlab-ci.yaml",
			expected: true,
		},
		{
			name:     "nested GitLab CI",
			path:     "project/.gitlab-ci.yml",
			expected: true,
		},
		{
			name:     "absolute path GitLab CI",
			path:     "/home/user/project/.gitlab-ci.yml",
			expected: true,
		},
		{
			name:     "GitHub workflow file",
			path:     ".github/workflows/ci.yml",
			expected: false,
		},
		{
			name:     "wrong extension",
			path:     ".gitlab-ci.json",
			expected: false,
		},
		{
			name:     "random yaml file",
			path:     "config.yml",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.CanParse(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGitLabParser_Parse_Basic(t *testing.T) {
	parser := NewGitLabParser()

	yaml := `
stages:
  - build
  - test

build-job:
  stage: build
  script:
    - echo "Building"
    - npm ci
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)
	require.NotNil(t, workflow)

	// Verify basic structure
	assert.Equal(t, "gitlab", workflow.Platform)
	assert.Len(t, workflow.Jobs, 1)

	// Verify job exists
	buildJob := workflow.Jobs["build-job"]
	require.NotNil(t, buildJob)
	assert.Equal(t, "build-job", buildJob.ID)

	// Exact match, not Contains: the script lines are joined in source order and a
	// reordering or duplication regression has to fail here.
	assert.Len(t, buildJob.Steps, 1)
	assert.Equal(t, "echo \"Building\"\nnpm ci", buildJob.Steps[0].Run)
}

func TestGitLabParser_Parse_InvalidYAML(t *testing.T) {
	parser := NewGitLabParser()

	invalidYAML := `
stages:
  - build
jobs: [invalid yaml structure
`

	workflow, err := parser.Parse([]byte(invalidYAML))
	assert.Error(t, err)
	assert.Nil(t, workflow)
	assert.Contains(t, err.Error(), "parsing YAML")
}

func TestGitLabParser_ParseConvertsToNormalized(t *testing.T) {
	parser := NewGitLabParser()

	yaml := `
stages:
  - build
  - test
  - deploy

variables:
  NODE_VERSION: "18"
  GLOBAL_VAR: "global"

default:
  image: node:18
  before_script:
    - npm install

build-job:
  stage: build
  image: node:18-alpine
  script:
    - npm run build
  before_script:
    - echo "Starting build"
  after_script:
    - echo "Build complete"
  variables:
    BUILD_VAR: "build"
  artifacts:
    paths:
      - dist/

test-job:
  stage: test
  script:
    - npm test
  needs:
    - build-job
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  services:
    - name: postgres:14
      alias: postgres
  tags:
    - docker

deploy-job:
  stage: deploy
  script:
    - ./deploy.sh
  environment:
    name: production
  only:
    - main
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)
	require.NotNil(t, workflow)

	// Verify normalized workflow structure
	assert.Equal(t, "gitlab", workflow.Platform)

	// Verify workflow-level env (from variables)
	assert.Equal(t, "18", workflow.Env["NODE_VERSION"])
	assert.Equal(t, "global", workflow.Env["GLOBAL_VAR"])

	// Verify jobs
	assert.Len(t, workflow.Jobs, 3)

	// Build job details
	buildJob := workflow.Jobs["build-job"]
	require.NotNil(t, buildJob)
	assert.Equal(t, "build-job", buildJob.ID)
	assert.Equal(t, "node:18-alpine", buildJob.RunsOn)
	assert.Equal(t, "build", buildJob.Env["BUILD_VAR"])

	// Verify build job has steps (script + before_script + after_script)
	require.GreaterOrEqual(t, len(buildJob.Steps), 1)
	// Main script step should contain the script commands
	foundScriptStep := false
	for _, step := range buildJob.Steps {
		if strings.Contains(step.Run, "npm run build") {
			foundScriptStep = true
			break
		}
	}
	assert.True(t, foundScriptStep, "Should have script step")

	// Test job details
	testJob := workflow.Jobs["test-job"]
	require.NotNil(t, testJob)
	assert.Equal(t, "test-job", testJob.ID)
	assert.Equal(t, []string{"build-job"}, testJob.Needs)

	// Verify rule was converted to condition
	require.Len(t, testJob.Steps, 1)
	// The condition might be on the job or step level depending on implementation
	hasCondition := testJob.Condition != "" || testJob.Steps[0].Condition != ""
	assert.True(t, hasCondition, "Should have condition from rules")

	// Verify services
	require.Len(t, testJob.Services, 1)
	assert.Contains(t, testJob.Services, "postgres")

	// Deploy job details
	deployJob := workflow.Jobs["deploy-job"]
	require.NotNil(t, deployJob)
	assert.Equal(t, "deploy-job", deployJob.ID)

	// Verify raw GitLab CI is preserved
	assert.NotNil(t, workflow.Raw)
	glCI, ok := workflow.Raw.(*GitLabCI)
	require.True(t, ok, "Raw should be *GitLabCI")
	assert.Len(t, glCI.Stages, 3)
}

func TestGitLabParser_Parse_ComplexNeeds(t *testing.T) {
	parser := NewGitLabParser()

	yaml := `
stages:
  - build
  - test
  - deploy

build-job:
  stage: build
  script:
    - echo "build"

test-job-1:
  stage: test
  script:
    - echo "test 1"
  needs: [build-job]

test-job-2:
  stage: test
  script:
    - echo "test 2"
  needs:
    - job: build-job

deploy-job:
  stage: deploy
  script:
    - echo "deploy"
  needs:
    - build-job
    - test-job-1
    - test-job-2
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)

	// Build has no dependencies
	assert.Empty(t, workflow.Jobs["build-job"].Needs)

	// test-job-1 with array syntax
	assert.Equal(t, []string{"build-job"}, workflow.Jobs["test-job-1"].Needs)

	// test-job-2 with complex syntax
	assert.Equal(t, []string{"build-job"}, workflow.Jobs["test-job-2"].Needs)

	// deploy depends on multiple jobs
	deploy := workflow.Jobs["deploy-job"]
	assert.Len(t, deploy.Needs, 3)
	assert.Contains(t, deploy.Needs, "build-job")
	assert.Contains(t, deploy.Needs, "test-job-1")
	assert.Contains(t, deploy.Needs, "test-job-2")
}

func TestGitLabParser_InitRegistration(t *testing.T) {
	// The init() function in gitlab.go registers the parser
	// Re-register to test the initialization behavior
	RegisterParser(NewGitLabParser())

	// Verify it's registered
	parser := GetParser("gitlab")
	require.NotNil(t, parser, "GitLab parser should be registered")
	assert.Equal(t, "gitlab", parser.Platform())

	// Verify it can parse GitLab CI paths
	assert.True(t, parser.CanParse(".gitlab-ci.yml"))
	assert.True(t, parser.CanParse(".gitlab-ci.yaml"))
}

// ============================================================================
// GitLabParser Include Tests
// ============================================================================

func TestGitLabParser_Parse_Include_LocalString(t *testing.T) {
	parser := NewGitLabParser()

	yaml := `
include: '/templates/ci.yml'

stages:
  - test

test-job:
  stage: test
  script:
    - echo "test"
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)
	require.NotNil(t, workflow)

	// Verify include was parsed
	glCI, ok := workflow.Raw.(*GitLabCI)
	require.True(t, ok, "Raw should be *GitLabCI")
	require.Len(t, glCI.Includes, 1)

	inc := glCI.Includes[0]
	assert.Equal(t, IncludeTypeLocal, inc.Type)
	assert.Equal(t, "/templates/ci.yml", inc.Path)
	assert.Empty(t, inc.Remote)
	assert.Empty(t, inc.Project)
	assert.Empty(t, inc.Template)
}

func TestGitLabParser_Parse_Include_LocalArray(t *testing.T) {
	parser := NewGitLabParser()

	yaml := `
include:
  - '/templates/build.yml'
  - '/templates/test.yml'

stages:
  - test

test-job:
  stage: test
  script:
    - echo "test"
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)
	require.NotNil(t, workflow)

	glCI, ok := workflow.Raw.(*GitLabCI)
	require.True(t, ok, "Raw should be *GitLabCI")
	require.Len(t, glCI.Includes, 2)

	// First include
	inc1 := glCI.Includes[0]
	assert.Equal(t, IncludeTypeLocal, inc1.Type)
	assert.Equal(t, "/templates/build.yml", inc1.Path)

	// Second include
	inc2 := glCI.Includes[1]
	assert.Equal(t, IncludeTypeLocal, inc2.Type)
	assert.Equal(t, "/templates/test.yml", inc2.Path)
}

func TestGitLabParser_Parse_Include_Project(t *testing.T) {
	parser := NewGitLabParser()

	yaml := `
include:
  - project: 'group/project'
    file: '/templates/ci.yml'
    ref: 'main'

stages:
  - test

test-job:
  stage: test
  script:
    - echo "test"
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)
	require.NotNil(t, workflow)

	glCI, ok := workflow.Raw.(*GitLabCI)
	require.True(t, ok, "Raw should be *GitLabCI")
	require.Len(t, glCI.Includes, 1)

	inc := glCI.Includes[0]
	assert.Equal(t, IncludeTypeProject, inc.Type)
	assert.Equal(t, "group/project", inc.Project)
	assert.Equal(t, "/templates/ci.yml", inc.Path)
	assert.Equal(t, "main", inc.Ref)
	assert.Empty(t, inc.Remote)
	assert.Empty(t, inc.Template)
}

func TestGitLabParser_Parse_Include_Mixed(t *testing.T) {
	parser := NewGitLabParser()

	yaml := `
include:
  - local: '/templates/ci.yml'
  - remote: 'https://example.com/ci.yml'
  - project: 'group/project'
    file: '/templates/ci.yml'
  - template: 'Auto-DevOps.gitlab-ci.yml'

stages:
  - test

test-job:
  stage: test
  script:
    - echo "test"
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)
	require.NotNil(t, workflow)

	glCI, ok := workflow.Raw.(*GitLabCI)
	require.True(t, ok, "Raw should be *GitLabCI")
	require.Len(t, glCI.Includes, 4)

	// Verify local include
	assert.Equal(t, IncludeTypeLocal, glCI.Includes[0].Type)
	assert.Equal(t, "/templates/ci.yml", glCI.Includes[0].Path)

	// Verify remote include
	assert.Equal(t, IncludeTypeRemote, glCI.Includes[1].Type)
	assert.Equal(t, "https://example.com/ci.yml", glCI.Includes[1].Remote)

	// Verify project include
	assert.Equal(t, IncludeTypeProject, glCI.Includes[2].Type)
	assert.Equal(t, "group/project", glCI.Includes[2].Project)
	assert.Equal(t, "/templates/ci.yml", glCI.Includes[2].Path)

	// Verify template include
	assert.Equal(t, IncludeTypeTemplate, glCI.Includes[3].Type)
	assert.Equal(t, "Auto-DevOps.gitlab-ci.yml", glCI.Includes[3].Template)
}

func TestGitLabParser_Parse_Include_NoIncludes(t *testing.T) {
	parser := NewGitLabParser()

	yaml := `
stages:
  - test

test-job:
  stage: test
  script:
    - echo "test"
`

	workflow, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)
	require.NotNil(t, workflow)

	glCI, ok := workflow.Raw.(*GitLabCI)
	require.True(t, ok, "Raw should be *GitLabCI")
	assert.Empty(t, glCI.Includes)
}

// ============================================================================
// GitLabParser Trigger Tests
// ============================================================================

func TestGitLabParser_ParseTriggers(t *testing.T) {
	parser := NewGitLabParser()

	tests := []struct {
		name             string
		yaml             string
		expectedTriggers []string
	}{
		{
			name: "merge_request_event trigger",
			yaml: `
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

stages:
  - test

test-job:
  stage: test
  script:
    - echo "test"
`,
			expectedTriggers: []string{"merge_request"},
		},
		{
			name: "push trigger",
			yaml: `
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "push"

stages:
  - test

test-job:
  stage: test
  script:
    - echo "test"
`,
			expectedTriggers: []string{"push"},
		},
		{
			name: "schedule trigger",
			yaml: `
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"

stages:
  - test

test-job:
  stage: test
  script:
    - echo "test"
`,
			expectedTriggers: []string{"schedule"},
		},
		{
			name: "external_pull_request_event trigger",
			yaml: `
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "external_pull_request_event"

stages:
  - test

test-job:
  stage: test
  script:
    - echo "test"
`,
			expectedTriggers: []string{"external_pull_request"},
		},
		{
			name: "multiple triggers",
			yaml: `
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_PIPELINE_SOURCE == "push"

stages:
  - test

test-job:
  stage: test
  script:
    - echo "test"
`,
			expectedTriggers: []string{"merge_request", "push"},
		},
		{
			name: "no workflow rules",
			yaml: `
stages:
  - test

test-job:
  stage: test
  script:
    - echo "test"
`,
			expectedTriggers: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workflow, err := parser.Parse([]byte(tt.yaml))
			require.NoError(t, err)
			require.NotNil(t, workflow)

			// Verify triggers are populated
			if tt.expectedTriggers == nil {
				assert.Empty(t, workflow.Triggers)
			} else {
				assert.Equal(t, tt.expectedTriggers, workflow.Triggers)
			}
		})
	}
}
