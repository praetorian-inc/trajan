// Package parser provides workflow parsing for multiple CI/CD platforms
package parser

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// GitLabParser implements WorkflowParser for GitLab CI
type GitLabParser struct{}

// NewGitLabParser creates a new GitLab CI parser
func NewGitLabParser() *GitLabParser {
	return &GitLabParser{}
}

// Platform returns the platform identifier
func (p *GitLabParser) Platform() string {
	return "gitlab"
}

// CanParse returns true if this parser can handle the given file path
func (p *GitLabParser) CanParse(path string) bool {
	// GitLab CI files are .gitlab-ci.yml or .gitlab-ci.yaml
	return strings.HasSuffix(path, ".gitlab-ci.yml") ||
		strings.HasSuffix(path, ".gitlab-ci.yaml")
}

// Parse parses GitLab CI workflow content with line number extraction
func (p *GitLabParser) Parse(data []byte) (*NormalizedWorkflow, error) {
	// Pass 1: Parse into yaml.Node to get line numbers
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("parsing YAML node: %w", err)
	}

	// Pass 2: Parse into map for structure
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing GitLab CI: %w", err)
	}

	// Extract line numbers from yaml.Node
	lineMap := p.extractLineNumbers(&node)

	glCI := p.parseGitLabCI(raw)
	return p.convertWithLineNumbers(glCI, lineMap), nil
}

// extractLineNumbers walks the yaml.Node tree and builds a map of keys to line numbers
func (p *GitLabParser) extractLineNumbers(node *yaml.Node) map[string]int {
	lineMap := make(map[string]int)
	p.walkNode(node, "", lineMap)
	return lineMap
}

// walkNode recursively walks the YAML node tree to extract line numbers
func (p *GitLabParser) walkNode(node *yaml.Node, path string, lineMap map[string]int) {
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

			// Store line number for this key
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

// parseGitLabCI extracts GitLab CI structure from raw YAML
func (p *GitLabParser) parseGitLabCI(raw map[string]interface{}) *GitLabCI {
	glCI := &GitLabCI{
		Jobs: make(map[string]GitLabJob),
	}

	// Reserved keywords that are not jobs
	reserved := map[string]bool{
		"stages":        true,
		"variables":     true,
		"default":       true,
		"include":       true,
		"image":         true,
		"services":      true,
		"before_script": true,
		"after_script":  true,
		"cache":         true,
		"workflow":      true,
	}

	for key, value := range raw {
		switch key {
		case "stages":
			if stages, ok := value.([]interface{}); ok {
				glCI.Stages = interfaceSliceToStringSlice(stages)
			}
		case "variables":
			if vars, ok := value.(map[string]interface{}); ok {
				glCI.Variables = interfaceMapToStringMap(vars)
			}
		case "default":
			if defMap, ok := value.(map[string]interface{}); ok {
				glCI.Default = p.parseDefault(defMap)
			}
		case "include":
			glCI.Includes = p.parseIncludes(value)
		case "workflow":
			if workflowMap, ok := value.(map[string]interface{}); ok {
				glCI.WorkflowRules = p.parseWorkflowRules(workflowMap)
			}
		default:
			// Any non-reserved keyword is a job
			if !reserved[key] {
				if jobMap, ok := value.(map[string]interface{}); ok {
					glCI.Jobs[key] = p.parseJob(jobMap)
				}
			}
		}
	}

	resolveExtends(glCI)
	return glCI
}

// parseJob parses a GitLab job definition
func (p *GitLabParser) parseJob(jobMap map[string]interface{}) GitLabJob {
	job := GitLabJob{
		Variables: make(map[string]string),
	}

	for key, value := range jobMap {
		switch key {
		case "stage":
			if s, ok := value.(string); ok {
				job.Stage = s
			}
		case "image":
			if s, ok := value.(string); ok {
				job.Image = s
			}
		case "script":
			if scripts, ok := value.([]interface{}); ok {
				job.Script = interfaceSliceToStringSlice(scripts)
			}
		case "before_script":
			if scripts, ok := value.([]interface{}); ok {
				job.BeforeScript = interfaceSliceToStringSlice(scripts)
			}
		case "after_script":
			if scripts, ok := value.([]interface{}); ok {
				job.AfterScript = interfaceSliceToStringSlice(scripts)
			}
		case "variables":
			if vars, ok := value.(map[string]interface{}); ok {
				job.Variables = interfaceMapToStringMap(vars)
			}
		case "needs":
			job.Needs = value
		case "rules":
			if rules, ok := value.([]interface{}); ok {
				job.Rules = p.parseRules(rules)
			}
		case "only":
			job.Only = value
		case "except":
			job.Except = value
		case "environment":
			job.Environment = value
		case "artifacts":
			if artifacts, ok := value.(map[string]interface{}); ok {
				job.Artifacts = p.parseArtifacts(artifacts)
			}
		case "services":
			if services, ok := value.([]interface{}); ok {
				job.Services = p.parseServices(services)
			}
		case "tags":
			if tags, ok := value.([]interface{}); ok {
				job.Tags = interfaceSliceToStringSlice(tags)
			}
		case "extends":
			switch ext := value.(type) {
			case string:
				job.Extends = []string{ext}
			case []interface{}:
				job.Extends = interfaceSliceToStringSlice(ext)
			}
		}
	}

	return job
}

// resolveExtends resolves the extends inheritance chain for all jobs.
// Iterative resolution with max depth to prevent infinite loops.
func resolveExtends(ci *GitLabCI) {
	const maxDepth = 10
	resolved := make(map[string]bool)

	for name := range ci.Jobs {
		resolveJobExtends(ci, name, resolved, 0, maxDepth)
	}
}

// resolveJobExtends resolves extends for a single job recursively.
func resolveJobExtends(ci *GitLabCI, name string, resolved map[string]bool, depth, maxDepth int) {
	if resolved[name] || depth >= maxDepth {
		return
	}

	job := ci.Jobs[name]
	if len(job.Extends) == 0 {
		resolved[name] = true
		return
	}

	// Resolve parents first
	for _, parentName := range job.Extends {
		if _, ok := ci.Jobs[parentName]; ok {
			resolveJobExtends(ci, parentName, resolved, depth+1, maxDepth)
		}
	}

	// Merge parent fields into this job (child overrides parent)
	for _, parentName := range job.Extends {
		parent, ok := ci.Jobs[parentName]
		if !ok {
			continue
		}
		job = mergeJob(parent, job)
	}

	// Clear extends after resolution
	job.Extends = nil
	ci.Jobs[name] = job
	resolved[name] = true
}

// mergeJob merges parent job fields into child. Child fields take precedence.
func mergeJob(parent, child GitLabJob) GitLabJob {
	if child.Stage == "" {
		child.Stage = parent.Stage
	}
	if child.Image == "" {
		child.Image = parent.Image
	}
	if len(child.Script) == 0 {
		child.Script = parent.Script
	}
	if len(child.BeforeScript) == 0 {
		child.BeforeScript = parent.BeforeScript
	}
	if len(child.AfterScript) == 0 {
		child.AfterScript = parent.AfterScript
	}
	// Variables: merge (parent values, then child overrides)
	if len(parent.Variables) > 0 {
		merged := make(map[string]string)
		for k, v := range parent.Variables {
			merged[k] = v
		}
		for k, v := range child.Variables {
			merged[k] = v
		}
		child.Variables = merged
	}
	if child.Needs == nil {
		child.Needs = parent.Needs
	}
	if len(child.Rules) == 0 {
		child.Rules = parent.Rules
	}
	if child.Only == nil {
		child.Only = parent.Only
	}
	if child.Except == nil {
		child.Except = parent.Except
	}
	if child.Environment == nil {
		child.Environment = parent.Environment
	}
	if child.Artifacts == nil {
		child.Artifacts = parent.Artifacts
	}
	if len(child.Services) == 0 {
		child.Services = parent.Services
	}
	if len(child.Tags) == 0 {
		child.Tags = parent.Tags
	}
	return child
}

// parseDefault parses GitLab default section
func (p *GitLabParser) parseDefault(defMap map[string]interface{}) *GitLabDefault {
	def := &GitLabDefault{}

	for key, value := range defMap {
		switch key {
		case "image":
			if s, ok := value.(string); ok {
				def.Image = s
			}
		case "before_script":
			if scripts, ok := value.([]interface{}); ok {
				def.BeforeScript = interfaceSliceToStringSlice(scripts)
			}
		case "after_script":
			if scripts, ok := value.([]interface{}); ok {
				def.AfterScript = interfaceSliceToStringSlice(scripts)
			}
		}
	}

	return def
}

// parseWorkflowRules parses the workflow block for workflow-level rules
func (p *GitLabParser) parseWorkflowRules(workflowMap map[string]interface{}) []GitLabRule {
	if rules, ok := workflowMap["rules"].([]interface{}); ok {
		return p.parseRules(rules)
	}
	return nil
}

// extractTriggers converts workflow rules to trigger strings
func (p *GitLabParser) extractTriggers(rules []GitLabRule) []string {
	if len(rules) == 0 {
		return nil
	}

	var triggers []string
	seen := make(map[string]bool)

	// Map GitLab pipeline sources to trigger strings
	sourceMap := map[string]string{
		"merge_request_event":         "merge_request",
		"external_pull_request_event": "external_pull_request",
		"push":                        "push",
		"schedule":                    "schedule",
	}

	for _, rule := range rules {
		if rule.If == "" {
			continue
		}

		// Extract pipeline source from if condition
		// Look for patterns like: $CI_PIPELINE_SOURCE == "merge_request_event"
		for source, trigger := range sourceMap {
			if strings.Contains(rule.If, `"`+source+`"`) || strings.Contains(rule.If, `'`+source+`'`) {
				if !seen[trigger] {
					triggers = append(triggers, trigger)
					seen[trigger] = true
				}
			}
		}
	}

	return triggers
}

// parseRules parses GitLab rules array
func (p *GitLabParser) parseRules(rules []interface{}) []GitLabRule {
	result := make([]GitLabRule, 0, len(rules))

	for _, r := range rules {
		if ruleMap, ok := r.(map[string]interface{}); ok {
			rule := GitLabRule{}

			if ifVal, ok := ruleMap["if"].(string); ok {
				rule.If = ifVal
			}
			if whenVal, ok := ruleMap["when"].(string); ok {
				rule.When = whenVal
			}
			if changes, ok := ruleMap["changes"].([]interface{}); ok {
				rule.Changes = interfaceSliceToStringSlice(changes)
			}

			result = append(result, rule)
		}
	}

	return result
}

// parseArtifacts parses GitLab artifacts section
func (p *GitLabParser) parseArtifacts(artifacts map[string]interface{}) *GitLabArtifacts {
	art := &GitLabArtifacts{}

	if paths, ok := artifacts["paths"].([]interface{}); ok {
		art.Paths = interfaceSliceToStringSlice(paths)
	}

	return art
}

// parseServices parses GitLab services array
func (p *GitLabParser) parseServices(services []interface{}) []GitLabService {
	result := make([]GitLabService, 0, len(services))

	for _, s := range services {
		svc := GitLabService{}

		switch v := s.(type) {
		case string:
			// Simple string format: "postgres:14"
			svc.Name = v
		case map[string]interface{}:
			// Complex format with name, alias, etc.
			if name, ok := v["name"].(string); ok {
				svc.Name = name
			}
			if alias, ok := v["alias"].(string); ok {
				svc.Alias = alias
			}
		}

		result = append(result, svc)
	}

	return result
}

// parseIncludes parses the include field into typed GitLabInclude structures
func (p *GitLabParser) parseIncludes(raw interface{}) []GitLabInclude {
	if raw == nil {
		return nil
	}

	var includes []GitLabInclude

	switch v := raw.(type) {
	case string:
		// Simple string format: include: '/path/to/file.yml'
		includes = append(includes, GitLabInclude{
			Type: IncludeTypeLocal,
			Path: v,
		})
	case []interface{}:
		// Array format: include: [...]
		for _, item := range v {
			switch inc := item.(type) {
			case string:
				// Array of strings: include: ['/path1.yml', '/path2.yml']
				includes = append(includes, GitLabInclude{
					Type: IncludeTypeLocal,
					Path: inc,
				})
			case map[string]interface{}:
				// Array of objects: include: [{local: ...}, {remote: ...}]
				includes = append(includes, p.parseIncludeMap(inc)...)
			}
		}
	case map[string]interface{}:
		// Single object format: include: {local: '/path.yml'}
		includes = append(includes, p.parseIncludeMap(v)...)
	}

	return includes
}

// parseIncludeMap parses a single include map into typed GitLabInclude entries.
// Returns a slice because project includes with a file list expand into multiple entries.
func (p *GitLabParser) parseIncludeMap(m map[string]interface{}) []GitLabInclude {
	if local, ok := m["local"].(string); ok {
		return []GitLabInclude{{Type: IncludeTypeLocal, Path: local}}
	}

	if remote, ok := m["remote"].(string); ok {
		return []GitLabInclude{{Type: IncludeTypeRemote, Remote: remote}}
	}

	if project, ok := m["project"].(string); ok {
		ref, _ := m["ref"].(string)

		// file can be a string or a list of strings
		switch file := m["file"].(type) {
		case string:
			return []GitLabInclude{{
				Type:    IncludeTypeProject,
				Project: project,
				Path:    file,
				Ref:     ref,
			}}
		case []interface{}:
			var includes []GitLabInclude
			for _, f := range file {
				if path, ok := f.(string); ok {
					includes = append(includes, GitLabInclude{
						Type:    IncludeTypeProject,
						Project: project,
						Path:    path,
						Ref:     ref,
					})
				}
			}
			return includes
		default:
			// No file specified
			return []GitLabInclude{{
				Type:    IncludeTypeProject,
				Project: project,
				Ref:     ref,
			}}
		}
	}

	if template, ok := m["template"].(string); ok {
		return []GitLabInclude{{Type: IncludeTypeTemplate, Template: template}}
	}

	return nil
}

// convert transforms a GitLabCI to generic NormalizedWorkflow
func (p *GitLabParser) convertWithLineNumbers(glCI *GitLabCI, lineMap map[string]int) *NormalizedWorkflow {
	wf := &NormalizedWorkflow{
		Platform: "gitlab",
		Jobs:     make(map[string]*NormalizedJob),
		Env:      glCI.Variables,
		Triggers: p.extractTriggers(glCI.WorkflowRules),
		Raw:      glCI,
	}

	// Convert jobs
	for jobID, glJob := range glCI.Jobs {
		job := &NormalizedJob{
			ID:         jobID,
			Name:       jobID,
			RunsOn:     p.getImage(glJob, glCI),
			Needs:      p.extractNeeds(glJob.Needs),
			Steps:      p.convertScriptsToSteps(jobID, glJob, lineMap),
			Env:        glJob.Variables,
			Services:   make(map[string]*NormalizedService),
			Line:       lineMap[jobID],
			RunnerTags: glJob.Tags, // Transfer GitLab runner tags
		}

		// Convert rules to condition
		if len(glJob.Rules) > 0 {
			var conditions []string
			for _, rule := range glJob.Rules {
				if rule.If != "" {
					conditions = append(conditions, rule.If)
				}
			}
			if len(conditions) > 0 {
				job.Condition = strings.Join(conditions, " || ")
			}
		} else if glJob.Only != nil {
			// Handle only/except (simplified - just record that there's a condition)
			job.Condition = formatOnly(glJob.Only)
		}

		// Convert services
		for _, glSvc := range glJob.Services {
			serviceKey := glSvc.Alias
			if serviceKey == "" {
				// Use name without tag as key if no alias
				parts := strings.Split(glSvc.Name, ":")
				serviceKey = parts[0]
			}

			job.Services[serviceKey] = &NormalizedService{
				Image: glSvc.Name,
			}
		}

		wf.Jobs[jobID] = job
	}

	return wf
}

// getImage returns the image for a job (job-level image or default image)
func (p *GitLabParser) getImage(job GitLabJob, ci *GitLabCI) string {
	if job.Image != "" {
		return job.Image
	}
	if ci.Default != nil && ci.Default.Image != "" {
		return ci.Default.Image
	}
	return ""
}

// extractNeeds extracts job dependencies from needs field
func (p *GitLabParser) extractNeeds(needs interface{}) []string {
	if needs == nil {
		return nil
	}

	switch n := needs.(type) {
	case string:
		return []string{n}
	case []interface{}:
		result := make([]string, 0, len(n))
		for _, item := range n {
			switch v := item.(type) {
			case string:
				result = append(result, v)
			case map[string]interface{}:
				// Complex needs with { job: "name" }
				if job, ok := v["job"].(string); ok {
					result = append(result, job)
				}
			}
		}
		return result
	default:
		return nil
	}
}

// convertScriptsToSteps converts GitLab script arrays to NormalizedStep
func (p *GitLabParser) convertScriptsToSteps(jobID string, job GitLabJob, lineMap map[string]int) []*NormalizedStep {
	steps := make([]*NormalizedStep, 0)

	// Combine all scripts into a single step
	// This matches GitLab's execution model where before_script, script, and after_script
	// run in sequence but are part of the same execution context
	var allScripts []string

	if len(job.BeforeScript) > 0 {
		allScripts = append(allScripts, job.BeforeScript...)
	}
	if len(job.Script) > 0 {
		allScripts = append(allScripts, job.Script...)
	}
	if len(job.AfterScript) > 0 {
		allScripts = append(allScripts, job.AfterScript...)
	}

	if len(allScripts) > 0 {
		// Combine scripts with newlines
		scriptContent := strings.Join(allScripts, "\n")

		// Get line number for job's script section
		scriptLine := lineMap[jobID+".script"]
		if scriptLine == 0 {
			scriptLine = lineMap[jobID+".before_script"]
		}

		step := &NormalizedStep{
			Name: "script",
			Run:  scriptContent,
			Line: scriptLine,
		}

		// Note: Don't copy job condition to step
		// GitLab steps inherit job context (no independent if: like GitHub)

		steps = append(steps, step)
	}

	return steps
}

// formatOnly formats the only field as a condition string
func formatOnly(only interface{}) string {
	switch o := only.(type) {
	case string:
		return fmt.Sprintf("branch: %s", o)
	case []interface{}:
		branches := interfaceSliceToStringSlice(o)
		return fmt.Sprintf("branches: %v", branches)
	default:
		return "has-only-constraint"
	}
}

// GitLabIncludeType represents the type of GitLab include
type GitLabIncludeType string

const (
	// IncludeTypeLocal represents a local file include (same repository)
	IncludeTypeLocal GitLabIncludeType = "local"
	// IncludeTypeRemote represents a remote URL include (external resource - security risk)
	IncludeTypeRemote GitLabIncludeType = "remote"
	// IncludeTypeProject represents a cross-project include
	IncludeTypeProject GitLabIncludeType = "project"
	// IncludeTypeTemplate represents a GitLab official template include
	IncludeTypeTemplate GitLabIncludeType = "template"
)

// GitLabInclude represents a parsed GitLab include with its type
type GitLabInclude struct {
	Type     GitLabIncludeType `json:"type"`
	Path     string            `json:"path"`     // File path (for local/project types)
	Remote   string            `json:"remote"`   // Remote URL (for remote type)
	Project  string            `json:"project"`  // Project path (for project type)
	Ref      string            `json:"ref"`      // Branch/tag (for project type)
	Template string            `json:"template"` // Template name (for template type)
}

// GitLabCI represents a parsed GitLab CI configuration
type GitLabCI struct {
	Stages        []string             `yaml:"stages"`
	Variables     map[string]string    `yaml:"variables"`
	Default       *GitLabDefault       `yaml:"default"`
	Includes      []GitLabInclude      `yaml:"-"` // Parsed includes (typed)
	WorkflowRules []GitLabRule         `yaml:"-"` // Workflow-level rules
	Jobs          map[string]GitLabJob `yaml:"-"` // Parsed separately (any non-keyword key)
}

// GitLabJob represents a GitLab CI job
type GitLabJob struct {
	Stage        string            `yaml:"stage"`
	Image        string            `yaml:"image"`
	Script       []string          `yaml:"script"`
	BeforeScript []string          `yaml:"before_script"`
	AfterScript  []string          `yaml:"after_script"`
	Variables    map[string]string `yaml:"variables"`
	Needs        interface{}       `yaml:"needs"` // string, []string, or []map
	Rules        []GitLabRule      `yaml:"rules"`
	Only         interface{}       `yaml:"only"`
	Except       interface{}       `yaml:"except"`
	Environment  interface{}       `yaml:"environment"`
	Artifacts    *GitLabArtifacts  `yaml:"artifacts"`
	Services     []GitLabService   `yaml:"services"`
	Tags         []string          `yaml:"tags"`
	Extends      []string          `yaml:"extends"` // Parent job names to inherit from
}

// GitLabRule represents a GitLab CI rule
type GitLabRule struct {
	If      string   `yaml:"if"`
	When    string   `yaml:"when"`
	Changes []string `yaml:"changes"`
}

// GitLabArtifacts represents GitLab CI artifacts configuration
type GitLabArtifacts struct {
	Paths []string `yaml:"paths"`
}

// GitLabService represents a GitLab CI service container
type GitLabService struct {
	Name  string `yaml:"name"`
	Alias string `yaml:"alias"`
}

// GitLabDefault represents GitLab CI default configuration
type GitLabDefault struct {
	Image        string   `yaml:"image"`
	BeforeScript []string `yaml:"before_script"`
	AfterScript  []string `yaml:"after_script"`
}

// init registers the GitLab parser
func init() {
	RegisterParser(NewGitLabParser())
}
