// Package parser provides workflow parsing for multiple CI/CD platforms
package parser

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// GitHubParser implements WorkflowParser for GitHub Actions
type GitHubParser struct{}

// NewGitHubParser creates a new GitHub Actions parser
func NewGitHubParser() *GitHubParser {
	return &GitHubParser{}
}

// Platform returns the platform identifier
func (p *GitHubParser) Platform() string {
	return "github"
}

// CanParse returns true if this parser can handle the given file path
func (p *GitHubParser) CanParse(path string) bool {
	// GitHub Actions workflows are in .github/workflows/
	return strings.Contains(path, ".github/workflows/") &&
		(strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml"))
}

// Parse parses GitHub Actions workflow content
func (p *GitHubParser) Parse(data []byte) (*NormalizedWorkflow, error) {
	// Parse into yaml.Node to get line numbers
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("parsing YAML node: %w", err)
	}

	// Parse into GitHubWorkflow for structure
	var ghWf GitHubWorkflow
	if err := yaml.Unmarshal(data, &ghWf); err != nil {
		return nil, fmt.Errorf("parsing GitHub Actions workflow: %w", err)
	}

	// Extract line numbers from yaml.Node
	lineMap := p.extractLineNumbers(&node)

	return p.convertWithLineNumbers(&ghWf, lineMap), nil
}

// extractLineNumbers walks the yaml.Node tree and builds a map of keys to line numbers
func (p *GitHubParser) extractLineNumbers(node *yaml.Node) map[string]int {
	lineMap := make(map[string]int)
	p.walkNode(node, "", lineMap)
	return lineMap
}

// walkNode recursively walks the YAML node tree to extract line numbers
func (p *GitHubParser) walkNode(node *yaml.Node, path string, lineMap map[string]int) {
	if node == nil {
		return
	}

	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			p.walkNode(child, path, lineMap)
		}
	case yaml.MappingNode:
		// Iterate over key-value pairs
		for i := 0; i < len(node.Content); i += 2 {
			if i+1 >= len(node.Content) {
				break
			}
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]

			key := keyNode.Value
			newPath := key
			if path != "" {
				newPath = path + "." + key
			}

			// Store line number for this key (use key's line, not value's)
			lineMap[newPath] = keyNode.Line

			// Recurse into value
			p.walkNode(valueNode, newPath, lineMap)
		}
	case yaml.SequenceNode:
		for idx, child := range node.Content {
			indexPath := fmt.Sprintf("%s[%d]", path, idx)
			lineMap[indexPath] = child.Line
			p.walkNode(child, indexPath, lineMap)
		}
	}
}

// convertWithLineNumbers transforms a GitHubWorkflow to generic NormalizedWorkflow with line numbers
func (p *GitHubParser) convertWithLineNumbers(ghWf *GitHubWorkflow, lineMap map[string]int) *NormalizedWorkflow {
	wf := &NormalizedWorkflow{
		Platform: "github",
		Name:     ghWf.Name,
		Triggers: ghWf.GetTriggers(),
		Jobs:     make(map[string]*NormalizedJob),
		Env:      ghWf.Env,
		Raw:      ghWf,
	}

	// Convert permissions
	wf.Permissions = convertGitHubPermissions(ghWf.Permissions)

	// Convert jobs
	for jobID, ghJob := range ghWf.Jobs {
		jobPerms := convertGitHubPermissions(ghJob.Permissions)
		// GitHub Actions: jobs inherit workflow-level permissions when not explicitly set.
		if jobPerms == nil && wf.Permissions != nil {
			jobPerms = wf.Permissions.Clone()
		}

		job := &NormalizedJob{
			ID:          jobID,
			Name:        ghJob.Name,
			Uses:        ghJob.Uses,
			RunsOn:      ghJob.GetRunsOn(),
			SelfHosted:  ghJob.IsSelfHostedRunner(),
			Needs:       ghJob.GetNeeds(),
			Condition:   ghJob.If,
			Steps:       make([]*NormalizedStep, 0, len(ghJob.Steps)),
			Permissions: jobPerms,
			Environment: extractEnvironmentName(ghJob.Environment),
			Env:         ghJob.Env,
			Outputs:     ghJob.Outputs,
			Services:    make(map[string]*NormalizedService),
			Line:        lineMap["jobs."+jobID],
		}

		// Convert steps
		for stepIdx, ghStep := range ghJob.Steps {
			stepPath := fmt.Sprintf("jobs.%s.steps[%d]", jobID, stepIdx)
			step := &NormalizedStep{
				ID:               ghStep.ID,
				Name:             ghStep.Name,
				Uses:             ghStep.Uses,
				Run:              ghStep.Run,
				With:             ghStep.With,
				Env:              ghStep.Env,
				Condition:        ghStep.If,
				WorkingDirectory: ghStep.WorkingDirectory,
				Shell:            ghStep.Shell,
				ContinueOnError:  convertContinueOnError(ghStep.ContinueOnError),
				Line:             lineMap[stepPath], // Set step line number
			}
			job.Steps = append(job.Steps, step)
		}

		// Convert services
		for svcName, ghSvc := range ghJob.Services {
			job.Services[svcName] = &NormalizedService{
				Image:   ghSvc.Image,
				Env:     ghSvc.Env,
				Ports:   ghSvc.Ports,
				Options: ghSvc.Options,
			}
		}

		wf.Jobs[jobID] = job
	}

	return wf
}

// convertGitHubPermissions converts GitHub permissions to generic format
func convertGitHubPermissions(perms interface{}) *NormalizedPermissions {
	if perms == nil {
		return nil
	}

	p := &NormalizedPermissions{
		Scopes: make(map[string]string),
	}

	switch v := perms.(type) {
	case string:
		switch v {
		case "read-all":
			p.ReadAll = true
		case "write-all":
			p.WriteAll = true
		}
	case map[string]interface{}:
		for scope, access := range v {
			if accessStr, ok := access.(string); ok {
				p.Scopes[scope] = accessStr
			}
		}
	}

	return p
}

// convertContinueOnError handles the various forms of continue-on-error
func convertContinueOnError(v interface{}) bool {
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return val == "true"
	default:
		return false
	}
}

// extractEnvironmentName extracts environment name from environment field
// which can be string "production" or object {name: "production", url: "..."}
func extractEnvironmentName(env interface{}) string {
	if env == nil {
		return ""
	}

	switch v := env.(type) {
	case string:
		return v
	case map[string]interface{}:
		if name, ok := v["name"]; ok {
			if nameStr, ok := name.(string); ok {
				return nameStr
			}
		}
	}

	return ""
}

// GitHubWorkflow represents a parsed GitHub Actions workflow
type GitHubWorkflow struct {
	Name        string               `yaml:"name"`
	On          interface{}          `yaml:"on"` // Can be string, []string, or map
	Jobs        map[string]GitHubJob `yaml:"jobs"`
	Permissions interface{}          `yaml:"permissions,omitempty"`
	Env         map[string]string    `yaml:"env,omitempty"`
	Defaults    *GitHubDefaults      `yaml:"defaults,omitempty"`
}

// GitHubJob represents a GitHub Actions job
type GitHubJob struct {
	Name        string                   `yaml:"name,omitempty"`
	Uses        string                   `yaml:"uses,omitempty"`    // Reusable workflow reference
	RunsOn      interface{}              `yaml:"runs-on,omitempty"` // Can be string or []string
	Needs       interface{}              `yaml:"needs,omitempty"`   // Can be string or []string
	If          string                   `yaml:"if,omitempty"`
	Steps       []GitHubStep             `yaml:"steps,omitempty"`
	Permissions interface{}              `yaml:"permissions,omitempty"`
	Environment interface{}              `yaml:"environment,omitempty"` // Can be string or object {name, url}
	Env         map[string]string        `yaml:"env,omitempty"`
	Outputs     map[string]string        `yaml:"outputs,omitempty"`
	Strategy    *GitHubStrategy          `yaml:"strategy,omitempty"`
	Services    map[string]GitHubService `yaml:"services,omitempty"`
}

// GitHubStep represents a GitHub Actions step
type GitHubStep struct {
	ID               string            `yaml:"id,omitempty"`
	Name             string            `yaml:"name,omitempty"`
	Uses             string            `yaml:"uses,omitempty"`
	Run              string            `yaml:"run,omitempty"`
	With             map[string]string `yaml:"with,omitempty"`
	Env              map[string]string `yaml:"env,omitempty"`
	If               string            `yaml:"if,omitempty"`
	WorkingDirectory string            `yaml:"working-directory,omitempty"`
	Shell            string            `yaml:"shell,omitempty"`
	ContinueOnError  interface{}       `yaml:"continue-on-error,omitempty"`
}

// GitHubDefaults represents GitHub workflow defaults
type GitHubDefaults struct {
	Run *GitHubRunDefaults `yaml:"run,omitempty"`
}

// GitHubRunDefaults represents run defaults
type GitHubRunDefaults struct {
	Shell            string `yaml:"shell,omitempty"`
	WorkingDirectory string `yaml:"working-directory,omitempty"`
}

// GitHubStrategy represents job strategy
type GitHubStrategy struct {
	Matrix      map[string]interface{} `yaml:"matrix,omitempty"`
	FailFast    *bool                  `yaml:"fail-fast,omitempty"`
	MaxParallel int                    `yaml:"max-parallel,omitempty"`
}

// GitHubService represents a service container
type GitHubService struct {
	Image   string            `yaml:"image"`
	Env     map[string]string `yaml:"env,omitempty"`
	Ports   []string          `yaml:"ports,omitempty"`
	Options string            `yaml:"options,omitempty"`
}

// GetTriggers returns the list of trigger event names
func (w *GitHubWorkflow) GetTriggers() []string {
	switch on := w.On.(type) {
	case string:
		return []string{on}
	case []interface{}:
		triggers := make([]string, 0, len(on))
		for _, t := range on {
			if s, ok := t.(string); ok {
				triggers = append(triggers, s)
			}
		}
		return triggers
	case map[string]interface{}:
		triggers := make([]string, 0, len(on))
		for k := range on {
			triggers = append(triggers, k)
		}
		return triggers
	default:
		return nil
	}
}

// GetRunsOn returns the runs-on value as a string
func (j GitHubJob) GetRunsOn() string {
	switch ro := j.RunsOn.(type) {
	case string:
		return ro
	case []interface{}:
		if len(ro) > 0 {
			if s, ok := ro[0].(string); ok {
				return s
			}
		}
		return ""
	default:
		return ""
	}
}

// GetNeeds returns the needs value as a string slice
func (j GitHubJob) GetNeeds() []string {
	switch n := j.Needs.(type) {
	case string:
		return []string{n}
	case []interface{}:
		needs := make([]string, 0, len(n))
		for _, item := range n {
			if s, ok := item.(string); ok {
				needs = append(needs, s)
			}
		}
		return needs
	default:
		return nil
	}
}

// GitHubHostedRunners is the set of known GitHub-hosted runner labels.
// Covers standard, ARM, larger (xlarge/large), and legacy labels.
// https://docs.github.com/en/actions/using-github-hosted-runners
var GitHubHostedRunners = map[string]bool{
	// Linux x64
	"ubuntu-latest": true, "ubuntu-24.04": true, "ubuntu-22.04": true, "ubuntu-20.04": true,
	"ubuntu-slim": true,
	// Linux ARM
	"ubuntu-24.04-arm": true, "ubuntu-22.04-arm": true,
	// Windows x64
	"windows-latest": true, "windows-2025": true, "windows-2025-vs2026": true, "windows-2022": true, "windows-2019": true,
	// Windows ARM
	"windows-11-arm": true,
	// macOS ARM (Apple Silicon)
	"macos-latest": true, "macos-26": true, "macos-15": true, "macos-14": true, "macos-13": true, "macos-12": true,
	// macOS Intel
	"macos-26-intel": true, "macos-15-intel": true,
	// macOS larger runners
	"macos-latest-large": true, "macos-26-large": true, "macos-15-large": true, "macos-14-large": true,
	"macos-latest-xlarge": true, "macos-26-xlarge": true, "macos-15-xlarge": true, "macos-14-xlarge": true,
}

// IsSelfHostedRunner checks whether the job targets a self-hosted runner.
// For matrix expressions like ${{ matrix.os }}, resolves the variable against
// the strategy matrix. Unresolvable expressions are treated as self-hosted.
func (j GitHubJob) IsSelfHostedRunner() bool {
	// Reusable workflow callers delegate runs-on to the callee.
	// They have no runner of their own, so an empty runs-on is not self-hosted.
	if j.Uses != "" {
		return false
	}

	runsOn := j.GetRunsOn()
	if runsOn == "self-hosted" {
		return true
	}
	if len(runsOn) == 0 || runsOn[0] != '$' {
		return !GitHubHostedRunners[runsOn]
	}
	if j.Strategy != nil && j.Strategy.Matrix != nil {
		if varName := extractMatrixVar(runsOn); varName != "" {
			if values, ok := j.Strategy.Matrix[varName]; ok {
				return !allGitHubHosted(values)
			}
		}
	}
	return true
}

// extractMatrixVar extracts "os" from "${{ matrix.os }}".
func extractMatrixVar(expr string) string {
	start := strings.Index(expr, "{{")
	end := strings.Index(expr, "}}")
	if start < 0 || end < 0 {
		return ""
	}
	inner := strings.TrimSpace(expr[start+2 : end])
	const prefix = "matrix."
	if strings.HasPrefix(inner, prefix) {
		return inner[len(prefix):]
	}
	return ""
}

func allGitHubHosted(v interface{}) bool {
	switch vals := v.(type) {
	case []interface{}:
		for _, item := range vals {
			if s, ok := item.(string); ok {
				if !GitHubHostedRunners[s] {
					return false
				}
			} else {
				return false
			}
		}
		return len(vals) > 0
	case string:
		return GitHubHostedRunners[vals]
	default:
		return false
	}
}

// init registers the GitHub parser
func init() {
	RegisterParser(NewGitHubParser())
}
