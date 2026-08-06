package parser

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type GitLabParser struct{}

func NewGitLabParser() *GitLabParser {
	return &GitLabParser{}
}

func (p *GitLabParser) Platform() string {
	return "gitlab"
}

func (p *GitLabParser) CanParse(path string) bool {
	return strings.HasSuffix(path, ".gitlab-ci.yml") ||
		strings.HasSuffix(path, ".gitlab-ci.yaml")
}

func (p *GitLabParser) Parse(data []byte) (*NormalizedWorkflow, error) {
	// Unmarshalled twice: yaml.Node carries line numbers, the map carries structure.
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("parsing YAML node: %w", err)
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing GitLab CI: %w", err)
	}

	lineMap := p.extractLineNumbers(&node)

	glCI := p.parseGitLabCI(raw)
	return p.convertWithLineNumbers(glCI, lineMap), nil
}

func (p *GitLabParser) extractLineNumbers(node *yaml.Node) map[string]int {
	lineMap := make(map[string]int)
	p.walkNode(node, "", lineMap)
	return lineMap
}

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
		// A MappingNode's Content is a flat key,value,key,value list.
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

			lineMap[newPath] = keyNode.Line

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

func (p *GitLabParser) parseGitLabCI(raw map[string]interface{}) *GitLabCI {
	glCI := &GitLabCI{
		Jobs: make(map[string]GitLabJob),
	}

	// GitLab treats every top-level key that is not a reserved keyword as a job.
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

// Depth-capped because an extends chain can be cyclic.
func resolveExtends(ci *GitLabCI) {
	const maxDepth = 10
	resolved := make(map[string]bool)

	for name := range ci.Jobs {
		resolveJobExtends(ci, name, resolved, 0, maxDepth)
	}
}

func resolveJobExtends(ci *GitLabCI, name string, resolved map[string]bool, depth, maxDepth int) {
	if resolved[name] || depth >= maxDepth {
		return
	}

	job := ci.Jobs[name]
	if len(job.Extends) == 0 {
		resolved[name] = true
		return
	}

	// Parents must be fully resolved before any merge, hence two passes.
	for _, parentName := range job.Extends {
		if _, ok := ci.Jobs[parentName]; ok {
			resolveJobExtends(ci, parentName, resolved, depth+1, maxDepth)
		}
	}

	for _, parentName := range job.Extends {
		parent, ok := ci.Jobs[parentName]
		if !ok {
			continue
		}
		job = mergeJob(parent, job)
	}

	job.Extends = nil
	ci.Jobs[name] = job
	resolved[name] = true
}

// Child fields take precedence over parent.
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
	// Variables merge key by key; every other field is all-or-nothing.
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

func (p *GitLabParser) parseWorkflowRules(workflowMap map[string]interface{}) []GitLabRule {
	if rules, ok := workflowMap["rules"].([]interface{}); ok {
		return p.parseRules(rules)
	}
	return nil
}

func (p *GitLabParser) extractTriggers(rules []GitLabRule) []string {
	if len(rules) == 0 {
		return nil
	}

	var triggers []string
	seen := make(map[string]bool)

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

		// Matches the quoted source in $CI_PIPELINE_SOURCE == "merge_request_event".
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

func (p *GitLabParser) parseArtifacts(artifacts map[string]interface{}) *GitLabArtifacts {
	art := &GitLabArtifacts{}

	if paths, ok := artifacts["paths"].([]interface{}); ok {
		art.Paths = interfaceSliceToStringSlice(paths)
	}

	return art
}

func (p *GitLabParser) parseServices(services []interface{}) []GitLabService {
	result := make([]GitLabService, 0, len(services))

	for _, s := range services {
		svc := GitLabService{}

		switch v := s.(type) {
		case string:
			// The string form is image:tag.
			svc.Name = v
		case map[string]interface{}:
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

// include: is a path string, a list of strings or objects, or a single object.
func (p *GitLabParser) parseIncludes(raw interface{}) []GitLabInclude {
	if raw == nil {
		return nil
	}

	var includes []GitLabInclude

	switch v := raw.(type) {
	case string:
		includes = append(includes, GitLabInclude{
			Type: IncludeTypeLocal,
			Path: v,
		})
	case []interface{}:
		for _, item := range v {
			switch inc := item.(type) {
			case string:
				includes = append(includes, GitLabInclude{
					Type: IncludeTypeLocal,
					Path: inc,
				})
			case map[string]interface{}:
				includes = append(includes, p.parseIncludeMap(inc)...)
			}
		}
	case map[string]interface{}:
		includes = append(includes, p.parseIncludeMap(v)...)
	}

	return includes
}

// Returns a slice: a project include with a file list expands to one entry per file.
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

func (p *GitLabParser) convertWithLineNumbers(glCI *GitLabCI, lineMap map[string]int) *NormalizedWorkflow {
	wf := &NormalizedWorkflow{
		Platform: "gitlab",
		Jobs:     make(map[string]*NormalizedJob),
		Env:      glCI.Variables,
		Triggers: p.extractTriggers(glCI.WorkflowRules),
		Raw:      glCI,
	}

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
			RunnerTags: glJob.Tags,
		}

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
			// only/except is recorded as a condition, not evaluated.
			job.Condition = formatOnly(glJob.Only)
		}

		for _, glSvc := range glJob.Services {
			serviceKey := glSvc.Alias
			if serviceKey == "" {
				// GitLab defaults a service hostname to the image name without its tag.
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

func (p *GitLabParser) getImage(job GitLabJob, ci *GitLabCI) string {
	if job.Image != "" {
		return job.Image
	}
	if ci.Default != nil && ci.Default.Image != "" {
		return ci.Default.Image
	}
	return ""
}

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

func (p *GitLabParser) convertScriptsToSteps(jobID string, job GitLabJob, lineMap map[string]int) []*NormalizedStep {
	steps := make([]*NormalizedStep, 0)

	// before_script, script and after_script share one execution context in GitLab,
	// so they normalize to a single step.
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
		scriptContent := strings.Join(allScripts, "\n")

		scriptLine := lineMap[jobID+".script"]
		if scriptLine == 0 {
			scriptLine = lineMap[jobID+".before_script"]
		}

		step := &NormalizedStep{
			Name: "script",
			Run:  scriptContent,
			Line: scriptLine,
		}

		// GitLab script lines have no independent if:, so the job condition is not copied down.

		steps = append(steps, step)
	}

	return steps
}

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

type GitLabIncludeType string

const (
	IncludeTypeLocal    GitLabIncludeType = "local"
	IncludeTypeRemote   GitLabIncludeType = "remote"
	IncludeTypeProject  GitLabIncludeType = "project"
	IncludeTypeTemplate GitLabIncludeType = "template"
)

type GitLabInclude struct {
	Type     GitLabIncludeType `json:"type"`
	Path     string            `json:"path"`
	Remote   string            `json:"remote"`
	Project  string            `json:"project"`
	Ref      string            `json:"ref"`
	Template string            `json:"template"`
}

type GitLabCI struct {
	Stages        []string             `yaml:"stages"`
	Variables     map[string]string    `yaml:"variables"`
	Default       *GitLabDefault       `yaml:"default"`
	Includes      []GitLabInclude      `yaml:"-"`
	WorkflowRules []GitLabRule         `yaml:"-"`
	Jobs          map[string]GitLabJob `yaml:"-"` // Arbitrary keys; filled by parseGitLabCI, not by yaml.
}

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

type GitLabRule struct {
	If      string   `yaml:"if"`
	When    string   `yaml:"when"`
	Changes []string `yaml:"changes"`
}

type GitLabArtifacts struct {
	Paths []string `yaml:"paths"`
}

type GitLabService struct {
	Name  string `yaml:"name"`
	Alias string `yaml:"alias"`
}

type GitLabDefault struct {
	Image        string   `yaml:"image"`
	BeforeScript []string `yaml:"before_script"`
	AfterScript  []string `yaml:"after_script"`
}

func init() {
	RegisterParser(NewGitLabParser())
}
