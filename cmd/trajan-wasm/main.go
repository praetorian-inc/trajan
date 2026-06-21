//go:build js && wasm
// +build js,wasm

package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"syscall/js"

	"gopkg.in/yaml.v3"
)

// Build-time version information (injected via -ldflags)
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// WorkflowSimple represents a simplified GitHub Actions workflow
type WorkflowSimple struct {
	Name string               `yaml:"name"`
	On   interface{}          `yaml:"on"`
	Jobs map[string]JobSimple `yaml:"jobs"`
}

// JobSimple represents a simplified job
type JobSimple struct {
	Name   string       `yaml:"name"`
	RunsOn string       `yaml:"runs-on"`
	Steps  []StepSimple `yaml:"steps"`
}

// StepSimple represents a simplified step
type StepSimple struct {
	Name string `yaml:"name"`
	Run  string `yaml:"run"`
}

// Finding represents a security finding
type Finding struct {
	Type              string `json:"type"`
	Title             string `json:"title"`
	Description       string `json:"description"`
	Severity          string `json:"severity"`
	Workflow          string `json:"workflow"`
	Step              string `json:"step"`
	Evidence          string `json:"evidence"`
	InjectableContext string `json:"injectable_context"`
	IsZeroClick       bool   `json:"is_zero_click"`
	Remediation       string `json:"remediation"`
}

var injectableContexts = []string{
	"github.event.issue.title",
	"github.event.issue.body",
	"github.event.comment.body",
	"github.event.pull_request.title",
	"github.event.pull_request.body",
	"github.event.pull_request.head.ref",
	"github.event.pull_request.head.label",
	"github.event.discussion.title",
	"github.event.discussion.body",
	"github.event.review.body",
	"github.event.review_comment.body",
	"github.event.pages.*.page_name",
	"github.event.commits.*.message",
	"github.event.commits.*.author.email",
	"github.event.commits.*.author.name",
	"github.event.head_commit.message",
	"github.event.head_commit.author.email",
	"github.event.head_commit.author.name",
	"github.head_ref",
}

var zeroClickTriggers = map[string]bool{
	"issues":              true,
	"issue_comment":       true,
	"pull_request":        true,
	"pull_request_target": true,
	"discussion":          true,
	"fork":                true,
}

var expressionRegex = regexp.MustCompile(`\$\{\{.+?\}\}`)

func analyzeWorkflow(yamlInput string) (string, error) {
	var workflow WorkflowSimple
	if err := yaml.Unmarshal([]byte(yamlInput), &workflow); err != nil {
		return "", fmt.Errorf("failed to parse YAML: %w", err)
	}

	findings := detectInjection(workflow)

	jsonResult, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal findings: %w", err)
	}

	return string(jsonResult), nil
}

func detectInjection(workflow WorkflowSimple) []Finding {
	var findings []Finding

	isZeroClick := checkZeroClickTriggers(workflow.On)

	for jobName, job := range workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			injectables := findInjectableContexts(step.Run)
			for _, injectable := range injectables {
				stepName := step.Name
				if stepName == "" {
					stepName = fmt.Sprintf("Step %d in %s", stepIdx+1, jobName)
				}

				title := "GitHub Actions Injection Vulnerability"
				if isZeroClick {
					title = "Zero-Click GitHub Actions Injection"
				}

				description := fmt.Sprintf("Detected unsafe usage of user-controllable context '%s' in workflow '%s' at step '%s'. This allows external attackers to inject arbitrary commands.", injectable, workflow.Name, stepName)

				finding := Finding{
					Type:              "actions-injection",
					Title:             title,
					Description:       description,
					Severity:          "high",
					Workflow:          workflow.Name,
					Step:              stepName,
					Evidence:          step.Run,
					InjectableContext: injectable,
					IsZeroClick:       isZeroClick,
					Remediation:       fmt.Sprintf("Avoid using ${{ %s }} directly in run commands. Use an environment variable or action input instead.", injectable),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func checkZeroClickTriggers(on interface{}) bool {
	switch v := on.(type) {
	case string:
		return zeroClickTriggers[v]
	case []interface{}:
		for _, trigger := range v {
			if triggerStr, ok := trigger.(string); ok && zeroClickTriggers[triggerStr] {
				return true
			}
		}
	case map[string]interface{}:
		for trigger := range v {
			if zeroClickTriggers[trigger] {
				return true
			}
		}
	}
	return false
}

func findInjectableContexts(s string) []string {
	var found []string
	matches := expressionRegex.FindAllString(s, -1)
	for _, match := range matches {
		for _, ctx := range injectableContexts {
			if strings.Contains(match, ctx) {
				found = append(found, ctx)
				break
			}
		}
	}
	return found
}

func analyzeWorkflowJS(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return map[string]interface{}{
			"error": "Expected 1 argument: YAML string",
		}
	}

	yamlInput := args[0].String()
	result, err := analyzeWorkflow(yamlInput)
	if err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}

	return result
}

func getVersionJS(this js.Value, args []js.Value) interface{} {
	return map[string]interface{}{
		"version":   Version,
		"buildTime": BuildTime,
		"gitCommit": GitCommit,
	}
}

func main() {
	c := make(chan struct{})

	js.Global().Set("analyzeWorkflow", js.FuncOf(analyzeWorkflowJS))
	registerFunctions()
	js.Global().Set("trajanGetVersion", js.FuncOf(getVersionJS))
	fmt.Printf("Trajan WASM v%s (commit: %s, built: %s)\n", Version, GitCommit, BuildTime)
	<-c
}
