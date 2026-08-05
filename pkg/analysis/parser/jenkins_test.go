package parser

import (
	"strings"
	"testing"
)

// pipelineXML wraps a Groovy pipeline script in a config.xml flow-definition structure
func pipelineXML(script string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<flow-definition>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition">
    <script>` + script + `</script>
  </definition>
</flow-definition>`)
}

// freestyleXML builds a freestyle config.xml from an agent label and shell commands
func freestyleXML(agentLabel string, commands []string) []byte {
	var shellElems strings.Builder
	for _, cmd := range commands {
		shellElems.WriteString("\n    <hudson.tasks.Shell>\n      <command>")
		shellElems.WriteString(cmd)
		shellElems.WriteString("</command>\n    </hudson.tasks.Shell>")
	}
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<project>
  <assignedNode>` + agentLabel + `</assignedNode>
  <builders>` + shellElems.String() + `
  </builders>
</project>`)
}

// TestJenkinsParser_CanParse verifies CanParse for known and unknown paths
func TestJenkinsParser_CanParse(t *testing.T) {
	p := NewJenkinsParser()
	tests := []struct {
		path string
		want bool
	}{
		{"Jenkinsfile", true},
		{"config.xml", true},
		{"jobs/my-job/config.xml", true},
		{".github/workflows/ci.yml", false},
		{"bitbucket-pipelines.yml", false},
		{".circleci/config.yml", false},
	}
	for _, tc := range tests {
		got := p.CanParse(tc.path)
		if got != tc.want {
			t.Errorf("CanParse(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestJenkinsParser_PipelineConfigXML verifies parsing of a pipeline config.xml with
// two stages and shell commands.
func TestJenkinsParser_PipelineConfigXML(t *testing.T) {
	script := `
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'mvn clean package'
                sh 'echo build done'
            }
        }
        stage('Deploy') {
            steps {
                sh "kubectl apply -f deployment.yaml"
            }
        }
    }
}`
	data := pipelineXML(script)
	p := NewJenkinsParser()
	wf, err := p.Parse(data)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(wf.Jobs) != 2 {
		t.Errorf("expected 2 jobs (one per stage), got %d", len(wf.Jobs))
	}

	// Verify both jobs have agent = "any"
	for _, job := range wf.Jobs {
		if job.RunsOn != "any" {
			t.Errorf("job %q RunsOn = %q, want %q", job.Name, job.RunsOn, "any")
		}
	}

	// Verify sh commands appear in step.Run
	allRuns := collectAllRuns(wf)
	assertContainsRun(t, allRuns, "mvn clean package")
	assertContainsRun(t, allRuns, "echo build done")
	assertContainsRun(t, allRuns, "kubectl apply -f deployment.yaml")
}

// TestJenkinsParser_FreestyleConfigXML verifies parsing of a freestyle config.xml
func TestJenkinsParser_FreestyleConfigXML(t *testing.T) {
	data := freestyleXML("linux-builder", []string{"make clean", "make test"})
	p := NewJenkinsParser()
	wf, err := p.Parse(data)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	job, ok := wf.Jobs["freestyle"]
	if !ok {
		t.Fatal("expected a 'freestyle' job")
	}
	if job.RunsOn != "linux-builder" {
		t.Errorf("RunsOn = %q, want %q", job.RunsOn, "linux-builder")
	}

	allRuns := collectAllRuns(wf)
	assertContainsRun(t, allRuns, "make clean")
	assertContainsRun(t, allRuns, "make test")
}

// TestJenkinsParser_InjectionPattern verifies that interpolation patterns are
// preserved in step.Run so the injection detector can find them.
func TestJenkinsParser_InjectionPattern(t *testing.T) {
	script := `
pipeline {
    agent any
    stages {
        stage('Deploy') {
            steps {
                sh "echo ${params.DEPLOY_TARGET}"
            }
        }
    }
}`
	p := NewJenkinsParser()
	wf, err := p.Parse([]byte(script))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	allRuns := collectAllRuns(wf)
	found := false
	for _, run := range allRuns {
		if strings.Contains(run, "${params.DEPLOY_TARGET}") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected interpolation pattern in step.Run, got runs: %v", allRuns)
	}
}

// TestJenkinsParser_EnvironmentBlock verifies that environment blocks are parsed
// into workflow or job Env maps.
func TestJenkinsParser_EnvironmentBlock(t *testing.T) {
	script := `
pipeline {
    agent any
    environment {
        API_KEY = 'secret123'
        APP_ENV = 'production'
    }
    stages {
        stage('Build') {
            steps {
                sh 'make'
            }
        }
    }
}`
	p := NewJenkinsParser()
	wf, err := p.Parse([]byte(script))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	// Check workflow-level env or job-level env
	apiKey := wf.Env["API_KEY"]
	if apiKey == "" {
		// Fall back to checking job env
		for _, job := range wf.Jobs {
			if job.Env["API_KEY"] != "" {
				apiKey = job.Env["API_KEY"]
				break
			}
		}
	}
	if apiKey != "secret123" {
		t.Errorf("expected API_KEY = 'secret123', got %q (workflow env: %v)", apiKey, wf.Env)
	}
}

// TestJenkinsParser_MultiStage verifies that 3 stages produce 3 jobs with correct names.
func TestJenkinsParser_MultiStage(t *testing.T) {
	script := `
pipeline {
    agent any
    stages {
        stage('Compile') {
            steps { sh 'javac Main.java' }
        }
        stage('Test') {
            steps { sh 'java -cp . MainTest' }
        }
        stage('Package') {
            steps { sh 'jar cf app.jar *.class' }
        }
    }
}`
	p := NewJenkinsParser()
	wf, err := p.Parse([]byte(script))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(wf.Jobs) != 3 {
		t.Errorf("expected 3 jobs, got %d", len(wf.Jobs))
	}

	stageNames := map[string]bool{}
	for _, job := range wf.Jobs {
		stageNames[job.Name] = true
	}
	for _, want := range []string{"Compile", "Test", "Package"} {
		if !stageNames[want] {
			t.Errorf("expected stage %q in jobs, got names: %v", want, stageNames)
		}
	}
}

// TestJenkinsParser_RawJenkinsfile verifies parsing of a raw Groovy Jenkinsfile
// (not XML-wrapped).
func TestJenkinsParser_RawJenkinsfile(t *testing.T) {
	script := `pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'go build ./...'
            }
        }
    }
}`
	p := NewJenkinsParser()
	wf, err := p.Parse([]byte(script))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(wf.Jobs) == 0 {
		t.Fatal("expected at least one job from raw Jenkinsfile")
	}

	allRuns := collectAllRuns(wf)
	assertContainsRun(t, allRuns, "go build ./...")
}

// TestJenkinsParser_EmptyConfig verifies that empty input returns an error.
func TestJenkinsParser_EmptyConfig(t *testing.T) {
	p := NewJenkinsParser()
	_, err := p.Parse([]byte{})
	if err == nil {
		t.Error("expected error for empty input, got nil")
	}
}

// TestJenkinsParser_ScriptedPipeline verifies scripted pipeline parsing:
// node('linux') { sh 'make' }
func TestJenkinsParser_ScriptedPipeline(t *testing.T) {
	script := `
node('linux') {
    sh 'make'
    sh 'make test'
}`
	p := NewJenkinsParser()
	wf, err := p.Parse([]byte(script))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	job, ok := wf.Jobs["scripted"]
	if !ok {
		t.Fatal("expected a 'scripted' job for scripted pipeline")
	}
	if job.RunsOn != "linux" {
		t.Errorf("RunsOn = %q, want %q", job.RunsOn, "linux")
	}

	allRuns := collectAllRuns(wf)
	assertContainsRun(t, allRuns, "make")
	assertContainsRun(t, allRuns, "make test")
}

// TestJenkinsParser_AgentLabel verifies that agent { label 'my-agent' } is
// correctly parsed into RunsOn.
func TestJenkinsParser_AgentLabel(t *testing.T) {
	script := `
pipeline {
    agent {
        label 'my-agent'
    }
    stages {
        stage('Build') {
            steps {
                sh 'make'
            }
        }
    }
}`
	p := NewJenkinsParser()
	wf, err := p.Parse([]byte(script))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(wf.Jobs) == 0 {
		t.Fatal("expected at least one job")
	}
	for _, job := range wf.Jobs {
		if job.RunsOn != "my-agent" {
			t.Errorf("RunsOn = %q, want %q", job.RunsOn, "my-agent")
		}
	}
}

// TestJenkinsParser_StageAgentOverride verifies that a stage-level agent overrides
// the global agent.
func TestJenkinsParser_StageAgentOverride(t *testing.T) {
	script := `
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'make'
            }
        }
        stage('DockerBuild') {
            agent {
                label 'docker'
            }
            steps {
                sh 'docker build .'
            }
        }
    }
}`
	p := NewJenkinsParser()
	wf, err := p.Parse([]byte(script))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(wf.Jobs) != 2 {
		t.Fatalf("expected 2 jobs, got %d", len(wf.Jobs))
	}

	for _, job := range wf.Jobs {
		switch job.Name {
		case "Build":
			if job.RunsOn != "any" {
				t.Errorf("Build stage RunsOn = %q, want %q", job.RunsOn, "any")
			}
		case "DockerBuild":
			if job.RunsOn != "docker" {
				t.Errorf("DockerBuild stage RunsOn = %q, want %q", job.RunsOn, "docker")
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// collectAllRuns gathers all step.Run values across all jobs in a workflow.
func collectAllRuns(wf *NormalizedWorkflow) []string {
	var runs []string
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run != "" {
				runs = append(runs, step.Run)
			}
		}
	}
	return runs
}

// assertContainsRun fails the test if none of the run strings contain the expected value.
func assertContainsRun(t *testing.T, runs []string, want string) {
	t.Helper()
	for _, r := range runs {
		if strings.Contains(r, want) {
			return
		}
	}
	t.Errorf("expected step.Run containing %q, got: %v", want, runs)
}
