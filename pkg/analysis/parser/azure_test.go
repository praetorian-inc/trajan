package parser

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureParser_CanParse(t *testing.T) {
	parser := NewAzureParser()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "main azure pipelines file",
			path: "azure-pipelines.yml",
			want: true,
		},
		{
			name: "prefixed azure pipelines file",
			path: "build.azure-pipelines.yml",
			want: true,
		},
		{
			name: "azure pipelines in subdirectory",
			path: ".azure-pipelines/build.yml",
			want: true,
		},
		{
			name: "azure pipelines yaml extension",
			path: "azure-pipelines.yaml",
			want: true,
		},
		{
			name: "github actions workflow",
			path: ".github/workflows/build.yml",
			want: false,
		},
		{
			name: "gitlab ci file",
			path: ".gitlab-ci.yml",
			want: false,
		},
		{
			name: "bitbucket pipelines file",
			path: "bitbucket-pipelines.yml",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parser.CanParse(tt.path); got != tt.want {
				t.Errorf("CanParse(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestAzureParser_Parse_PoolStringShorthand(t *testing.T) {
	parser := NewAzureParser()

	// Pipeline-level pool as string (common for self-hosted pools)
	yaml := []byte(`
pool: shire-self-hosted

jobs:
  - job: Build
    steps:
      - script: echo hi
`)

	wf, err := parser.Parse(yaml)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	job := wf.Jobs["Build"]
	if job == nil {
		t.Fatal("Expected job 'Build' to exist")
	}

	if job.RunsOn != "shire-self-hosted" {
		t.Errorf("RunsOn = %q, want 'shire-self-hosted'", job.RunsOn)
	}
}

func TestAzureParser_Parse_JobPoolStringShorthand(t *testing.T) {
	parser := NewAzureParser()

	// Job-level pool as string
	yaml := []byte(`
jobs:
  - job: Build
    pool: my-custom-pool
    steps:
      - script: echo hi
`)

	wf, err := parser.Parse(yaml)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	job := wf.Jobs["Build"]
	if job == nil {
		t.Fatal("Expected job 'Build' to exist")
	}

	if job.RunsOn != "my-custom-pool" {
		t.Errorf("RunsOn = %q, want 'my-custom-pool'", job.RunsOn)
	}
}

func TestAzureParser_Parse_StepsToNormalizedSteps(t *testing.T) {
	parser := NewAzureParser()

	yaml := []byte(`
jobs:
  - job: Build
    pool:
      vmImage: 'ubuntu-20.04'
    steps:
      - script: echo "Hello"
        displayName: 'Greeting'
      - task: Docker@2
        inputs:
          command: 'build'
      - checkout: self
`)

	wf, err := parser.Parse(yaml)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(wf.Jobs) != 1 {
		t.Fatalf("Expected 1 job, got %d", len(wf.Jobs))
	}

	job := wf.Jobs["Build"]
	if job == nil {
		t.Fatal("Expected job 'Build' to exist")
	}

	if len(job.Steps) != 3 {
		t.Errorf("Expected 3 steps, got %d", len(job.Steps))
	}

	// Check script step
	if job.Steps[0].Run != "echo \"Hello\"" {
		t.Errorf("Step 0 Run = %q, want echo \"Hello\"", job.Steps[0].Run)
	}

	// Check task step
	if job.Steps[1].Uses != "Docker@2" {
		t.Errorf("Step 1 Uses = %q, want Docker@2", job.Steps[1].Uses)
	}

	// Check checkout step
	if job.Steps[2].Uses != "checkout:self" {
		t.Errorf("Step 2 Uses = %q, want checkout:self", job.Steps[2].Uses)
	}
}

func TestAzureParser_Parse_TemplateReferences(t *testing.T) {
	parser := NewAzureParser()

	yaml := []byte(`
trigger:
  - main

extends:
  template: templates/pipeline.yml
  parameters:
    serviceConnection: ${{ parameters.connection }}

jobs:
  - template: templates/build.yml
    parameters:
      buildConfig: ${{ parameters.config }}
`)

	wf, err := parser.Parse(yaml)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	pipeline, ok := wf.Raw.(*AzurePipelines)
	if !ok {
		t.Fatalf("Raw = %T, want *AzurePipelines", wf.Raw)
	}

	// Both template references are the cross-repo template-injection surface; a
	// parser that silently dropped either would hide the reachable code.
	extends, ok := pipeline.Extends.(map[string]interface{})
	if !ok {
		t.Fatalf("Extends = %T, want map[string]interface{}", pipeline.Extends)
	}
	if extends["template"] != "templates/pipeline.yml" {
		t.Errorf("extends.template = %v, want %q", extends["template"], "templates/pipeline.yml")
	}

	if len(pipeline.Jobs) != 1 {
		t.Fatalf("len(Jobs) = %d, want 1", len(pipeline.Jobs))
	}
	if pipeline.Jobs[0].Template != "templates/build.yml" {
		t.Errorf("job Template = %q, want %q", pipeline.Jobs[0].Template, "templates/build.yml")
	}
	if got := pipeline.Jobs[0].TemplateParameters["buildConfig"]; got != "${{ parameters.config }}" {
		t.Errorf("job TemplateParameters[buildConfig] = %v, want %q", got, "${{ parameters.config }}")
	}
}

func TestAzureParser_Parse_Variables(t *testing.T) {
	parser := NewAzureParser()

	yaml := []byte(`
variables:
  - name: version
    value: '1.0.0'
  - name: region
    value: 'us-east-1'

jobs:
  - job: Deploy
    variables:
      environment: 'production'
    steps:
      - script: echo $(version)
`)

	wf, err := parser.Parse(yaml)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// parseVariables handles the list-of-{name,value} form here and the plain map
	// form at job level, so both shapes need their values checked, not just counted.
	if wf.Env["version"] != "1.0.0" {
		t.Errorf("Env[version] = %q, want %q", wf.Env["version"], "1.0.0")
	}
	if wf.Env["region"] != "us-east-1" {
		t.Errorf("Env[region] = %q, want %q", wf.Env["region"], "us-east-1")
	}

	job := wf.Jobs["Deploy"]
	if job == nil {
		t.Fatal("Expected job 'Deploy' to exist")
	}
	if job.Env["environment"] != "production" {
		t.Errorf("job Env[environment] = %q, want %q", job.Env["environment"], "production")
	}
}

func TestAzureParser_Parse_Parameters(t *testing.T) {
	parser := NewAzureParser()

	yaml := []byte(`
parameters:
  - name: environment
    type: string
    default: dev
  - name: deployRegion
    type: string

jobs:
  - job: Deploy
    steps:
      - script: echo ${{ parameters.environment }}
`)

	wf, err := parser.Parse(yaml)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	pipeline, ok := wf.Raw.(*AzurePipelines)
	if !ok {
		t.Fatalf("Raw = %T, want *AzurePipelines", wf.Raw)
	}
	if len(pipeline.Parameters) != 2 {
		t.Fatalf("len(Parameters) = %d, want 2", len(pipeline.Parameters))
	}
	if got := pipeline.Parameters[0]; got.Name != "environment" || got.Type != "string" || got.Default != "dev" {
		t.Errorf("Parameters[0] = %+v, want {environment string dev}", got)
	}
	// A parameter with no default must come back empty rather than carrying the
	// previous entry's value.
	if got := pipeline.Parameters[1]; got.Name != "deployRegion" || got.Type != "string" || got.Default != "" {
		t.Errorf("Parameters[1] = %+v, want {deployRegion string }", got)
	}
}

func TestAzureParser_Triggers(t *testing.T) {
	parser := NewAzureParser()

	tests := []struct {
		name     string
		yaml     string
		expected []string
	}{
		{
			name: "absent trigger defaults to CI with wildcard",
			yaml: `
jobs:
  - job: Build
    steps:
      - script: echo hi
`,
			expected: []string{"*", "ci"},
		},
		{
			name: "trigger none disables CI",
			yaml: `
trigger: none
jobs:
  - job: Build
    steps:
      - script: echo hi
`,
			expected: []string{},
		},
		{
			name: "trigger branch list includes branches",
			yaml: `
trigger:
  - main
  - develop
jobs:
  - job: Build
    steps:
      - script: echo hi
`,
			expected: []string{"ci", "develop", "main"},
		},
		{
			name: "trigger map extracts branch patterns",
			yaml: `
trigger:
  branches:
    include:
      - main
jobs:
  - job: Build
    steps:
      - script: echo hi
`,
			expected: []string{"ci", "main"},
		},
		{
			name: "pr trigger adds pr and branch patterns",
			yaml: `
trigger:
  - main
pr:
  - main
jobs:
  - job: Build
    steps:
      - script: echo hi
`,
			expected: []string{"ci", "main", "pr"},
		},
		{
			name: "pr none does not add pr",
			yaml: `
trigger:
  - main
pr: none
jobs:
  - job: Build
    steps:
      - script: echo hi
`,
			expected: []string{"ci", "main"},
		},
		{
			name: "pr map with branches adds pr and patterns",
			yaml: `
trigger:
  - main
pr:
  branches:
    include:
      - main
jobs:
  - job: Build
    steps:
      - script: echo hi
`,
			expected: []string{"ci", "main", "pr"},
		},
		{
			name: "both trigger and pr none",
			yaml: `
trigger: none
pr: none
jobs:
  - job: Build
    steps:
      - script: echo hi
`,
			expected: []string{},
		},
		{
			name: "wildcard branch trigger preserved",
			yaml: `
trigger:
  - '*'
jobs:
  - job: Build
    steps:
      - script: echo hi
`,
			expected: []string{"*", "ci"},
		},
		{
			name: "wildcard in map branch pattern preserved",
			yaml: `
trigger:
  branches:
    include:
      - main
      - feature/*
jobs:
  - job: Build
    steps:
      - script: echo hi
`,
			expected: []string{"ci", "feature/*", "main"},
		},
		{
			name: "batch trigger included",
			yaml: `
trigger:
  batch: true
  branches:
    include:
      - main
jobs:
  - job: Build
    steps:
      - script: echo hi
`,
			expected: []string{"batch", "ci", "main"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wf, err := parser.Parse([]byte(tt.yaml))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			got := wf.Triggers
			if got == nil {
				got = []string{}
			}
			expected := tt.expected
			if expected == nil {
				expected = []string{}
			}

			sort.Strings(got)
			sort.Strings(expected)

			if len(got) != len(expected) {
				t.Errorf("Triggers = %v, want %v", got, expected)
				return
			}
			for i := range got {
				if got[i] != expected[i] {
					t.Errorf("Triggers = %v, want %v", got, expected)
					return
				}
			}
		})
	}
}

// TestAzureParser_CapturesLineNumbers verifies that steps parsed from Azure pipeline
// YAML have non-zero line numbers. Azure uses yaml.Unmarshal to map[string]interface{}
// which discards position info; the parser must use yaml.Node to capture line numbers.
func TestAzureParser_CapturesLineNumbers(t *testing.T) {
	content := []byte(`trigger:
  branches:
    include:
      - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - script: echo hello
    displayName: 'Say Hello'

  - script: echo world
    displayName: 'Say World'
`)

	p := NewAzureParser()
	normalized, err := p.Parse(content)
	require.NoError(t, err)
	require.NotNil(t, normalized)

	mainJob, ok := normalized.Jobs["main"]
	require.True(t, ok, "should have 'main' job for top-level steps")
	require.Len(t, mainJob.Steps, 2, "should have 2 steps")

	firstStep := mainJob.Steps[0]
	assert.Greater(t, firstStep.Line, 0, "first step should have a line number > 0")

	secondStep := mainJob.Steps[1]
	assert.Greater(t, secondStep.Line, 0, "second step should have a line number > 0")
	assert.Greater(t, secondStep.Line, firstStep.Line, "second step should be on a later line than first step")
}

// TestAzureParser_CapturesLineNumbers_FlatJobs verifies line numbers for steps in flat jobs.
func TestAzureParser_CapturesLineNumbers_FlatJobs(t *testing.T) {
	content := []byte(`trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

jobs:
  - job: Build
    steps:
      - script: echo build
        displayName: 'Build step'
      - script: echo test
        displayName: 'Test step'
`)

	p := NewAzureParser()
	normalized, err := p.Parse(content)
	require.NoError(t, err)
	require.NotNil(t, normalized)

	buildJob, ok := normalized.Jobs["Build"]
	require.True(t, ok, "should have 'Build' job")
	require.Len(t, buildJob.Steps, 2, "should have 2 steps")

	firstStep := buildJob.Steps[0]
	assert.Greater(t, firstStep.Line, 0, "first step should have a line number > 0")

	secondStep := buildJob.Steps[1]
	assert.Greater(t, secondStep.Line, 0, "second step should have a line number > 0")
	assert.Greater(t, secondStep.Line, firstStep.Line, "second step should be on a later line than first step")
}

// TestAzureParser_CapturesWithAndEnvLines verifies that steps parsed from Azure pipeline YAML
// have WithLines and EnvLines populated with the exact line numbers of individual input/env keys.
func TestAzureParser_CapturesWithAndEnvLines(t *testing.T) {
	content := []byte(`trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

jobs:
  - job: Deploy
    steps:
      - task: AzureCLI@2
        displayName: 'Deploy with azure subscription'
        inputs:
          azureSubscription: 'my-connection'
          scriptType: bash
        env:
          MY_ENV: some-value
          ANOTHER_ENV: other-value
`)

	p := NewAzureParser()
	normalized, err := p.Parse(content)
	require.NoError(t, err)
	require.NotNil(t, normalized)

	deployJob, ok := normalized.Jobs["Deploy"]
	require.True(t, ok, "should have 'Deploy' job")
	require.Len(t, deployJob.Steps, 1, "should have 1 step")

	step := deployJob.Steps[0]

	// WithLines: azureSubscription should point to its own line, not the step start
	require.NotNil(t, step.WithLines, "WithLines should be populated")
	azureLine, ok := step.WithLines["azureSubscription"]
	require.True(t, ok, "WithLines should contain 'azureSubscription'")
	assert.Greater(t, azureLine, step.Line, "azureSubscription line should be after the step start line")

	scriptTypeLine, ok := step.WithLines["scriptType"]
	require.True(t, ok, "WithLines should contain 'scriptType'")
	assert.Greater(t, scriptTypeLine, azureLine, "scriptType should be on a later line than azureSubscription")

	// EnvLines: MY_ENV should point to its own line, not the step start
	require.NotNil(t, step.EnvLines, "EnvLines should be populated")
	myEnvLine, ok := step.EnvLines["MY_ENV"]
	require.True(t, ok, "EnvLines should contain 'MY_ENV'")
	assert.Greater(t, myEnvLine, step.Line, "MY_ENV line should be after the step start line")

	anotherEnvLine, ok := step.EnvLines["ANOTHER_ENV"]
	require.True(t, ok, "EnvLines should contain 'ANOTHER_ENV'")
	assert.Greater(t, anotherEnvLine, myEnvLine, "ANOTHER_ENV should be on a later line than MY_ENV")
}

// TestAzureParser_CapturesLineNumbers_StagedJobs verifies line numbers for steps in staged jobs.
func TestAzureParser_CapturesLineNumbers_StagedJobs(t *testing.T) {
	content := []byte(`trigger:
  - main

stages:
  - stage: Build
    jobs:
      - job: BuildJob
        steps:
          - script: echo build
            displayName: 'Build step'
          - script: echo test
            displayName: 'Test step'
`)

	p := NewAzureParser()
	normalized, err := p.Parse(content)
	require.NoError(t, err)
	require.NotNil(t, normalized)

	// The job key for staged jobs is "stageName-jobName"
	buildJob, ok := normalized.Jobs["Build-BuildJob"]
	require.True(t, ok, "should have 'Build-BuildJob' job")
	require.Len(t, buildJob.Steps, 2, "should have 2 steps")

	firstStep := buildJob.Steps[0]
	assert.Greater(t, firstStep.Line, 0, "first step should have a line number > 0")

	secondStep := buildJob.Steps[1]
	assert.Greater(t, secondStep.Line, 0, "second step should have a line number > 0")
	assert.Greater(t, secondStep.Line, firstStep.Line, "second step should be on a later line than first step")
}
