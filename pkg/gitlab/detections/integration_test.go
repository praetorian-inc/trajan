package detections

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestAllDetectionsRegistered(t *testing.T) {
	dets := registry.GetDetectionsForPlatform(platforms.PlatformGitLab)
	require.GreaterOrEqual(t, len(dets), 7, "expected at least 7 GitLab detections")

	detectionNames := make(map[string]bool)
	for _, det := range dets {
		detectionNames[det.Name()] = true
	}

	expectedDetections := []string{
		"merge-request-unsafe-checkout",
		"merge-request-secrets-exposure",
		"self-hosted-runner-exposure",
		"script-injection",
		"unpinned-include",
		"include-injection",
		"token-exposure",
	}

	for _, expected := range expectedDetections {
		assert.True(t, detectionNames[expected], "detection %s should be registered", expected)
	}
}

func TestAllDetectionsRunWithoutPanic(t *testing.T) {
	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request"})
	g.AddNode(wf)

	ctx := context.Background()
	dets := registry.GetDetectionsForPlatform(platforms.PlatformGitLab)
	require.NotEmpty(t, dets, "No detections registered for GitLab platform")

	for _, det := range dets {
		t.Run(det.Name(), func(t *testing.T) {
			findings, err := det.Detect(ctx, g)
			assert.NoError(t, err, "Detection %s should not return error", det.Name())
			_ = findings // a minimal graph may legitimately produce none
		})
	}
}

func TestMultipleVulnerabilitiesDetected(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	wf.AddTag(graph.TagMergeRequest)
	// Workflow-level env feeds the secrets-exposure detection.
	wf.Env = map[string]string{
		"API_KEY": "secret_value",
	}
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "")
	job.RunnerTags = []string{"self-hosted"}
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step1 := graph.NewStepNode("step1", "checkout", 10)
	step1.Run = "git checkout $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA"
	step1.SetParent(job.ID())
	g.AddNode(step1)
	g.AddEdge(job.ID(), step1.ID(), graph.EdgeContains)

	step2 := graph.NewStepNode("step2", "install", 11)
	step2.Run = "npm install"
	step2.SetParent(job.ID())
	g.AddNode(step2)
	g.AddEdge(job.ID(), step2.ID(), graph.EdgeContains)

	step3 := graph.NewStepNode("step3", "deploy", 12)
	step3.Run = "echo 'Deploying MR: $CI_MERGE_REQUEST_TITLE'"
	step3.SetParent(job.ID())
	g.AddNode(step3)
	g.AddEdge(job.ID(), step3.ID(), graph.EdgeContains)

	ctx := context.Background()
	dets := registry.GetDetectionsForPlatform(platforms.PlatformGitLab)

	allFindings := []detections.Finding{}
	for _, det := range dets {
		findings, err := det.Detect(ctx, g)
		require.NoError(t, err, "Detection %s should not error", det.Name())
		allFindings = append(allFindings, findings...)
	}

	require.NotEmpty(t, allFindings, "should detect at least one vulnerability")

	findingsByType := make(map[detections.VulnerabilityType][]detections.Finding)
	for _, finding := range allFindings {
		findingsByType[finding.Type] = append(findingsByType[finding.Type], finding)
	}

	assert.NotEmpty(t, findingsByType[detections.VulnMergeRequestUnsafeCheckout],
		"should detect unsafe checkout vulnerability")

	assert.NotEmpty(t, findingsByType[detections.VulnScriptInjection],
		"should detect script injection")

	assert.NotEmpty(t, findingsByType[detections.VulnSelfHostedRunner],
		"should detect self-hosted runner exposure")
}

func TestCriticalFindingPresent(t *testing.T) {
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "test", "")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step1 := graph.NewStepNode("step1", "checkout", 10)
	step1.Run = "git checkout $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA && npm install"
	step1.SetParent(job.ID())
	g.AddNode(step1)
	g.AddEdge(job.ID(), step1.ID(), graph.EdgeContains)

	ctx := context.Background()
	dets := registry.GetDetectionsForPlatform(platforms.PlatformGitLab)

	allFindings := []detections.Finding{}
	for _, det := range dets {
		findings, err := det.Detect(ctx, g)
		require.NoError(t, err)
		allFindings = append(allFindings, findings...)
	}

	hasCritical := false
	for _, finding := range allFindings {
		if finding.Severity == detections.SeverityCritical {
			hasCritical = true
			break
		}
	}

	assert.True(t, hasCritical, "expected at least one CRITICAL severity finding")
}

func TestDetectionWithIncludedWorkflows(t *testing.T) {
	g := graph.NewGraph()

	mainWf := graph.NewWorkflowNode("wf:main", "main", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	mainWf.AddTag(graph.TagMergeRequest)
	g.AddNode(mainWf)

	includedWf := graph.NewWorkflowNode("wf:included:build", "build", ".gitlab/ci/build.yml", "test/repo", []string{"merge_request_event"})
	includedWf.AddTag(graph.TagMergeRequest)
	g.AddNode(includedWf)

	g.AddEdge(mainWf.ID(), includedWf.ID(), graph.EdgeIncludes)

	job := graph.NewJobNode("wf:included:build:job:deploy", "deploy", "")
	job.SetParent(includedWf.ID())
	g.AddNode(job)
	g.AddEdge(includedWf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("wf:included:build:job:deploy:step:0", "deploy", 10)
	step.Run = "echo 'Deploying MR: $CI_MERGE_REQUEST_TITLE'"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	ctx := context.Background()
	dets := registry.GetDetectionsForPlatform(platforms.PlatformGitLab)

	allFindings := []detections.Finding{}
	for _, det := range dets {
		findings, err := det.Detect(ctx, g)
		require.NoError(t, err, "Detection %s should not error", det.Name())
		allFindings = append(allFindings, findings...)
	}

	scriptInjectionFindings := []detections.Finding{}
	for _, finding := range allFindings {
		if finding.Type == detections.VulnScriptInjection {
			scriptInjectionFindings = append(scriptInjectionFindings, finding)
		}
	}

	require.NotEmpty(t, scriptInjectionFindings, "should detect script injection in included workflow")

	foundCorrectSource := false
	for _, finding := range scriptInjectionFindings {
		if finding.Workflow == ".gitlab/ci/build.yml" {
			foundCorrectSource = true
			assert.Equal(t, "test/repo", finding.Repository)
			assert.Equal(t, "deploy", finding.Step)
			assert.Equal(t, 10, finding.Line)
			assert.Contains(t, finding.Evidence, "CI_MERGE_REQUEST_TITLE")
			break
		}
	}

	assert.True(t, foundCorrectSource, "finding should reference the included workflow file path (.gitlab/ci/build.yml)")
}

func TestDetectionWithMultipleIncludes(t *testing.T) {
	g := graph.NewGraph()

	mainWf := graph.NewWorkflowNode("wf:main", "main", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	mainWf.AddTag(graph.TagMergeRequest)
	g.AddNode(mainWf)

	buildWf := graph.NewWorkflowNode("wf:included:build", "build", ".gitlab/ci/build.yml", "test/repo", []string{"merge_request_event"})
	buildWf.AddTag(graph.TagMergeRequest)
	g.AddNode(buildWf)
	g.AddEdge(mainWf.ID(), buildWf.ID(), graph.EdgeIncludes)

	testWf := graph.NewWorkflowNode("wf:included:test", "test", ".gitlab/ci/test.yml", "test/repo", []string{"merge_request_event"})
	testWf.AddTag(graph.TagMergeRequest)
	g.AddNode(testWf)
	g.AddEdge(mainWf.ID(), testWf.ID(), graph.EdgeIncludes)

	buildJob := graph.NewJobNode("wf:included:build:job:build", "build", "")
	buildJob.SetParent(buildWf.ID())
	g.AddNode(buildJob)
	g.AddEdge(buildWf.ID(), buildJob.ID(), graph.EdgeContains)

	buildStep := graph.NewStepNode("wf:included:build:job:build:step:0", "build", 5)
	buildStep.Run = "echo $CI_MERGE_REQUEST_TITLE"
	buildStep.SetParent(buildJob.ID())
	g.AddNode(buildStep)
	g.AddEdge(buildJob.ID(), buildStep.ID(), graph.EdgeContains)

	testJob := graph.NewJobNode("wf:included:test:job:test", "test", "")
	testJob.RunnerTags = []string{"self-hosted"}
	testJob.SetParent(testWf.ID())
	g.AddNode(testJob)
	g.AddEdge(testWf.ID(), testJob.ID(), graph.EdgeContains)

	testStep := graph.NewStepNode("wf:included:test:job:test:step:0", "test", 8)
	testStep.Run = "npm test"
	testStep.SetParent(testJob.ID())
	g.AddNode(testStep)
	g.AddEdge(testJob.ID(), testStep.ID(), graph.EdgeContains)

	ctx := context.Background()
	dets := registry.GetDetectionsForPlatform(platforms.PlatformGitLab)

	allFindings := []detections.Finding{}
	for _, det := range dets {
		findings, err := det.Detect(ctx, g)
		require.NoError(t, err)
		allFindings = append(allFindings, findings...)
	}

	findingsByWorkflow := make(map[string][]detections.Finding)
	for _, finding := range allFindings {
		findingsByWorkflow[finding.Workflow] = append(findingsByWorkflow[finding.Workflow], finding)
	}

	buildFindings := findingsByWorkflow[".gitlab/ci/build.yml"]
	hasScriptInjection := false
	for _, f := range buildFindings {
		if f.Type == detections.VulnScriptInjection {
			hasScriptInjection = true
			assert.Equal(t, 5, f.Line, "should reference correct line in build.yml")
			break
		}
	}
	assert.True(t, hasScriptInjection, "should detect script injection in build.yml")

	testFindings := findingsByWorkflow[".gitlab/ci/test.yml"]
	hasSelfHosted := false
	for _, f := range testFindings {
		if f.Type == detections.VulnSelfHostedRunner {
			hasSelfHosted = true
			assert.Contains(t, f.Evidence, "self-hosted", "should mention self-hosted runner")
			break
		}
	}
	assert.True(t, hasSelfHosted, "should detect self-hosted runner in test.yml")
}

func TestDetectionWithNestedIncludes(t *testing.T) {
	g := graph.NewGraph()

	mainWf := graph.NewWorkflowNode("wf:main", "main", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	mainWf.AddTag(graph.TagMergeRequest)
	g.AddNode(mainWf)

	level1Wf := graph.NewWorkflowNode("wf:included:level1", "level1", ".gitlab/ci/level1.yml", "test/repo", []string{"merge_request_event"})
	level1Wf.AddTag(graph.TagMergeRequest)
	g.AddNode(level1Wf)
	g.AddEdge(mainWf.ID(), level1Wf.ID(), graph.EdgeIncludes)

	level2Wf := graph.NewWorkflowNode("wf:included:level1:included:level2", "level2", ".gitlab/ci/nested/level2.yml", "test/repo", []string{"merge_request_event"})
	level2Wf.AddTag(graph.TagMergeRequest)
	g.AddNode(level2Wf)
	g.AddEdge(level1Wf.ID(), level2Wf.ID(), graph.EdgeIncludes)

	job := graph.NewJobNode("wf:included:level1:included:level2:job:deploy", "deploy", "")
	job.SetParent(level2Wf.ID())
	g.AddNode(job)
	g.AddEdge(level2Wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("wf:included:level1:included:level2:job:deploy:step:0", "deploy", 12)
	step.Run = "deploy.sh $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	ctx := context.Background()
	dets := registry.GetDetectionsForPlatform(platforms.PlatformGitLab)

	allFindings := []detections.Finding{}
	for _, det := range dets {
		findings, err := det.Detect(ctx, g)
		require.NoError(t, err)
		allFindings = append(allFindings, findings...)
	}

	foundInNestedFile := false
	for _, finding := range allFindings {
		if finding.Type == detections.VulnScriptInjection &&
			finding.Workflow == ".gitlab/ci/nested/level2.yml" {
			foundInNestedFile = true
			assert.Equal(t, 12, finding.Line)
			assert.Contains(t, finding.Evidence, "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME")
			break
		}
	}

	assert.True(t, foundInNestedFile, "should detect vulnerability in nested included workflow file")
}

func TestDetectionWithIncludesNoVulnerability(t *testing.T) {
	g := graph.NewGraph()

	mainWf := graph.NewWorkflowNode("wf:main", "main", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	mainWf.AddTag(graph.TagMergeRequest)
	g.AddNode(mainWf)

	includedWf := graph.NewWorkflowNode("wf:included:safe", "safe", ".gitlab/ci/safe.yml", "test/repo", []string{"merge_request_event"})
	includedWf.AddTag(graph.TagMergeRequest)
	g.AddNode(includedWf)
	g.AddEdge(mainWf.ID(), includedWf.ID(), graph.EdgeIncludes)

	job := graph.NewJobNode("wf:included:safe:job:test", "test", "")
	job.SetParent(includedWf.ID())
	g.AddNode(job)
	g.AddEdge(includedWf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("wf:included:safe:job:test:step:0", "test", 5)
	step.Run = "npm test"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	ctx := context.Background()
	dets := registry.GetDetectionsForPlatform(platforms.PlatformGitLab)

	allFindings := []detections.Finding{}
	for _, det := range dets {
		findings, err := det.Detect(ctx, g)
		require.NoError(t, err)
		allFindings = append(allFindings, findings...)
	}

	for _, finding := range allFindings {
		if finding.Workflow == ".gitlab/ci/safe.yml" && finding.Type == detections.VulnScriptInjection {
			t.Errorf("unexpected script injection finding in safe included workflow: %+v", finding)
		}
	}
}
