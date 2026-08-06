// Package parser provides workflow parsing for multiple CI/CD platforms
package parser

import (
	"fmt"
	"sync"
)

type WorkflowParser interface {
	// One of "github", "gitlab", "bitbucket", "azure".
	Platform() string

	CanParse(path string) bool

	Parse(data []byte) (*NormalizedWorkflow, error)
}

type NormalizedWorkflow struct {
	Platform string

	Name string

	Path string

	Triggers []string

	// Keyed by the YAML key as authored ("trigger", "pr"), not the normalized trigger name.
	TriggerLines map[string]int

	Jobs map[string]*NormalizedJob

	Permissions *NormalizedPermissions

	Env map[string]string

	// The platform's own parsed struct (*GitLabCI, *GitHubWorkflow, ...); type-asserted by callers.
	Raw interface{}
}

type NormalizedJob struct {
	ID string

	Name string

	RunsOn string

	Needs []string

	Condition string

	Uses string

	Steps []*NormalizedStep

	Permissions *NormalizedPermissions

	Env map[string]string

	Outputs map[string]string

	Services map[string]*NormalizedService

	// GitHub deployment environment name (protection gate).
	Environment string

	Line int

	// GitLab's job-level tags field.
	RunnerTags []string

	SelfHosted bool
}

type NormalizedStep struct {
	ID string

	Name string

	// A GitHub action reference or an Azure task.
	Uses string

	Run string

	With map[string]string

	Env map[string]string

	Line int

	WithLines map[string]int
	EnvLines  map[string]int

	Condition string

	WorkingDirectory string

	Shell string

	ContinueOnError bool
}

type NormalizedPermissions struct {
	ReadAll bool

	WriteAll bool

	// Scope name to "read", "write" or "none".
	Scopes map[string]string
}

func (p *NormalizedPermissions) Clone() *NormalizedPermissions {
	c := &NormalizedPermissions{
		ReadAll:  p.ReadAll,
		WriteAll: p.WriteAll,
		Scopes:   make(map[string]string, len(p.Scopes)),
	}
	for k, v := range p.Scopes {
		c.Scopes[k] = v
	}
	return c
}

type NormalizedService struct {
	Image string

	Env map[string]string

	Ports []string

	Options string
}

var (
	mu             sync.RWMutex
	parserRegistry = make(map[string]WorkflowParser)
)

func RegisterParser(parser WorkflowParser) {
	mu.Lock()
	defer mu.Unlock()
	parserRegistry[parser.Platform()] = parser
}

func GetParser(platform string) WorkflowParser {
	mu.RLock()
	defer mu.RUnlock()
	return parserRegistry[platform]
}

func DetectParser(path string) WorkflowParser {
	mu.RLock()
	defer mu.RUnlock()
	for _, parser := range parserRegistry {
		if parser.CanParse(path) {
			return parser
		}
	}
	return nil
}

func interfaceSliceToStringSlice(slice []interface{}) []string {
	result := make([]string, 0, len(slice))
	for _, item := range slice {
		if str, ok := item.(string); ok {
			result = append(result, str)
		}
	}
	return result
}

func interfaceMapToStringMap(m map[string]interface{}) map[string]string {
	result := make(map[string]string)
	for k, v := range m {
		result[k] = fmt.Sprintf("%v", v)
	}
	return result
}
