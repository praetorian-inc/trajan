package parser

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type AzureParser struct{}

func NewAzureParser() *AzureParser {
	return &AzureParser{}
}

func (p *AzureParser) Platform() string {
	return "azure"
}

func (p *AzureParser) CanParse(path string) bool {
	return strings.Contains(path, "azure-pipelines.yml") ||
		strings.Contains(path, "azure-pipelines.yaml") ||
		strings.Contains(path, ".azure-pipelines/")
}

func (p *AzureParser) Parse(data []byte) (*NormalizedWorkflow, error) {
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("parsing Azure Pipelines: %w", err)
	}
	lineMap := extractLineNumbers(&node)

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing Azure Pipelines: %w", err)
	}

	azPipeline := p.parseAzurePipelines(raw)
	return p.convertWithLines(azPipeline, lineMap), nil
}

func extractLineNumbers(node *yaml.Node) map[string]int {
	lineMap := make(map[string]int)
	walkNode(node, "", lineMap)
	return lineMap
}

func walkNode(node *yaml.Node, path string, lineMap map[string]int) {
	if node == nil {
		return
	}

	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			walkNode(child, path, lineMap)
		}
	case yaml.MappingNode:
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
			walkNode(valueNode, newPath, lineMap)
		}
	case yaml.SequenceNode:
		for idx, child := range node.Content {
			indexPath := fmt.Sprintf("%s[%d]", path, idx)
			lineMap[indexPath] = child.Line
			walkNode(child, indexPath, lineMap)
		}
	}
}

func (p *AzureParser) parseAzurePipelines(raw map[string]interface{}) *AzurePipelines {
	pipeline := &AzurePipelines{
		Jobs:       make([]AzureJob, 0),
		Stages:     make([]AzureStage, 0),
		Variables:  make(map[string]string),
		Parameters: make([]AzureParameter, 0),
	}

	for key, value := range raw {
		switch key {
		case "trigger":
			pipeline.Trigger = value
		case "pr":
			pipeline.PR = value
		case "pool":
			switch v := value.(type) {
			case map[string]interface{}:
				pipeline.Pool = p.parsePool(v)
			case string:
				// String shorthand: pool: 'my-pool-name'
				pipeline.Pool = &AzurePool{Name: v}
			}
		case "variables":
			pipeline.Variables = p.parseVariables(value)
		case "parameters":
			if params, ok := value.([]interface{}); ok {
				pipeline.Parameters = p.parseParameters(params)
			}
		case "stages":
			if stages, ok := value.([]interface{}); ok {
				pipeline.Stages = p.parseStages(stages)
			}
		case "jobs":
			if jobs, ok := value.([]interface{}); ok {
				pipeline.Jobs = p.parseJobs(jobs)
			}
		case "steps":
			// Top-level steps are legal: they form a single implicit job.
			if steps, ok := value.([]interface{}); ok {
				pipeline.Steps = p.parseSteps(steps)
			}
		case "extends":
			pipeline.Extends = value
		case "resources":
			pipeline.Resources = value
		}
	}

	return pipeline
}

func (p *AzureParser) parsePool(poolMap map[string]interface{}) *AzurePool {
	pool := &AzurePool{}

	if vmImage, ok := poolMap["vmImage"].(string); ok {
		pool.VMImage = vmImage
	}
	if name, ok := poolMap["name"].(string); ok {
		pool.Name = name
	}
	if demands, ok := poolMap["demands"].([]interface{}); ok {
		pool.Demands = interfaceSliceToStringSlice(demands)
	}

	return pool
}

func (p *AzureParser) parseVariables(raw interface{}) map[string]string {
	vars := make(map[string]string)

	switch v := raw.(type) {
	case map[string]interface{}:
		vars = interfaceMapToStringMap(v)
	case []interface{}:
		// variables: as an array of {name,value}, {group} or {template}; only name/value is read.
		for _, item := range v {
			if varMap, ok := item.(map[string]interface{}); ok {
				if name, ok := varMap["name"].(string); ok {
					if value, ok := varMap["value"].(string); ok {
						vars[name] = value
					}
				}
			}
		}
	}

	return vars
}

func (p *AzureParser) parseParameters(params []interface{}) []AzureParameter {
	result := make([]AzureParameter, 0, len(params))

	for _, p := range params {
		if paramMap, ok := p.(map[string]interface{}); ok {
			param := AzureParameter{}

			if name, ok := paramMap["name"].(string); ok {
				param.Name = name
			}
			if paramType, ok := paramMap["type"].(string); ok {
				param.Type = paramType
			}
			if defaultVal, ok := paramMap["default"]; ok {
				param.Default = fmt.Sprintf("%v", defaultVal)
			}

			result = append(result, param)
		}
	}

	return result
}

func (p *AzureParser) parseStages(stages []interface{}) []AzureStage {
	result := make([]AzureStage, 0, len(stages))

	for _, s := range stages {
		if stageMap, ok := s.(map[string]interface{}); ok {
			stage := AzureStage{
				Jobs: make([]AzureJob, 0),
			}

			if name, ok := stageMap["stage"].(string); ok {
				stage.Name = name
			}
			if displayName, ok := stageMap["displayName"].(string); ok {
				stage.DisplayName = displayName
			}
			if jobs, ok := stageMap["jobs"].([]interface{}); ok {
				stage.Jobs = p.parseJobs(jobs)
			}
			if condition, ok := stageMap["condition"].(string); ok {
				stage.Condition = condition
			}

			result = append(result, stage)
		}
	}

	return result
}

func (p *AzureParser) parseJobs(jobs []interface{}) []AzureJob {
	result := make([]AzureJob, 0, len(jobs))

	for _, j := range jobs {
		if jobMap, ok := j.(map[string]interface{}); ok {
			job := AzureJob{
				Steps:     make([]AzureStep, 0),
				Variables: make(map[string]string),
			}

			if template, ok := jobMap["template"].(string); ok {
				job.Template = template
				if params, ok := jobMap["parameters"].(map[string]interface{}); ok {
					job.TemplateParameters = params
				}
				result = append(result, job)
				continue
			}

			if name, ok := jobMap["job"].(string); ok {
				job.Name = name
			} else if name, ok := jobMap["deployment"].(string); ok {
				job.Name = name
				// A deployment job keeps its steps under strategy, not steps.
				if strategy, ok := jobMap["strategy"].(map[string]interface{}); ok {
					job.Steps = append(job.Steps, p.parseDeploymentStrategy(strategy)...)
				}
			}
			if displayName, ok := jobMap["displayName"].(string); ok {
				job.DisplayName = displayName
			}
			switch pool := jobMap["pool"].(type) {
			case map[string]interface{}:
				job.Pool = p.parsePool(pool)
			case string:
				job.Pool = &AzurePool{Name: pool}
			}
			if steps, ok := jobMap["steps"].([]interface{}); ok {
				job.Steps = p.parseSteps(steps)
			}
			if variables := jobMap["variables"]; variables != nil {
				job.Variables = p.parseVariables(variables)
			}
			if dependsOn, ok := jobMap["dependsOn"]; ok {
				job.DependsOn = p.parseDependsOn(dependsOn)
			}
			if condition, ok := jobMap["condition"].(string); ok {
				job.Condition = condition
			}

			result = append(result, job)
		}
	}

	return result
}

func (p *AzureParser) parseSteps(steps []interface{}) []AzureStep {
	result := make([]AzureStep, 0, len(steps))

	for _, s := range steps {
		if stepMap, ok := s.(map[string]interface{}); ok {
			step := AzureStep{
				Inputs: make(map[string]string),
				Env:    make(map[string]string),
			}

			if template, ok := stepMap["template"].(string); ok {
				step.Template = template
				if params, ok := stepMap["parameters"].(map[string]interface{}); ok {
					step.TemplateParameters = params
				}
				result = append(result, step)
				continue
			}

			if displayName, ok := stepMap["displayName"].(string); ok {
				step.DisplayName = displayName
			}
			if script, ok := stepMap["script"].(string); ok {
				step.Script = script
			}
			if bash, ok := stepMap["bash"].(string); ok {
				step.Bash = bash
			}
			if ps, ok := stepMap["powershell"].(string); ok {
				step.PowerShell = ps
			}
			if pwsh, ok := stepMap["pwsh"].(string); ok {
				step.Pwsh = pwsh
			}
			if task, ok := stepMap["task"].(string); ok {
				step.Task = task
			}
			if checkout, ok := stepMap["checkout"].(string); ok {
				step.Checkout = checkout
			}
			if inputs, ok := stepMap["inputs"].(map[string]interface{}); ok {
				step.Inputs = interfaceMapToStringMap(inputs)
			}
			if env, ok := stepMap["env"].(map[string]interface{}); ok {
				step.Env = interfaceMapToStringMap(env)
			}
			if condition, ok := stepMap["condition"].(string); ok {
				step.Condition = condition
			}

			result = append(result, step)
		}
	}

	return result
}

// Nesting is runOnce|rolling|canary -> preDeploy|deploy|routeTraffic|postRouteTraffic|on -> steps.
func (p *AzureParser) parseDeploymentStrategy(strategy map[string]interface{}) []AzureStep {
	var steps []AzureStep
	for _, strategyType := range []string{"runOnce", "rolling", "canary"} {
		strategyMap, ok := strategy[strategyType].(map[string]interface{})
		if !ok {
			continue
		}
		hooks := []string{"preDeploy", "deploy", "routeTraffic", "postRouteTraffic", "on"}
		for _, hook := range hooks {
			hookMap, ok := strategyMap[hook].(map[string]interface{})
			if !ok {
				continue
			}
			if hook == "on" {
				for _, subHook := range []string{"failure", "success"} {
					subMap, ok := hookMap[subHook].(map[string]interface{})
					if !ok {
						continue
					}
					if hookSteps, ok := subMap["steps"].([]interface{}); ok {
						steps = append(steps, p.parseSteps(hookSteps)...)
					}
				}
				continue
			}
			if hookSteps, ok := hookMap["steps"].([]interface{}); ok {
				steps = append(steps, p.parseSteps(hookSteps)...)
			}
		}
	}
	return steps
}

func (p *AzureParser) parseDependsOn(raw interface{}) []string {
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []interface{}:
		return interfaceSliceToStringSlice(v)
	default:
		return nil
	}
}

// Azure defaults: an absent trigger means CI on every branch; "none" disables CI.
// Raw branch patterns are returned alongside the "ci"/"pr" names so detections
// can test for wildcards.
func (p *AzureParser) getTriggers(pipeline *AzurePipelines) []string {
	seen := make(map[string]bool)
	var triggers []string
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			triggers = append(triggers, s)
		}
	}

	switch v := pipeline.Trigger.(type) {
	case nil:
		add("ci")
		add("*")
	case string:
		if !strings.EqualFold(v, "none") {
			add("ci")
		}
	case []interface{}:
		// Branch list shorthand: trigger: [main, develop, *]
		add("ci")
		for _, item := range v {
			if branch, ok := item.(string); ok {
				add(branch)
			}
		}
	case map[string]interface{}:
		add("ci")
		for _, pattern := range p.extractBranchPatterns(v) {
			add(pattern)
		}
		if batch, ok := v["batch"].(bool); ok && batch {
			add("batch")
		}
	default:
		add("ci")
	}

	if pipeline.PR != nil {
		switch v := pipeline.PR.(type) {
		case string:
			if !strings.EqualFold(v, "none") {
				add("pr")
			}
		case []interface{}:
			add("pr")
			for _, item := range v {
				if branch, ok := item.(string); ok {
					add(branch)
				}
			}
		case map[string]interface{}:
			add("pr")
			for _, pattern := range p.extractBranchPatterns(v) {
				add(pattern)
			}
		default:
			add("pr")
		}
	}

	return triggers
}

func (p *AzureParser) extractBranchPatterns(triggerMap map[string]interface{}) []string {
	var patterns []string
	if branches, ok := triggerMap["branches"].(map[string]interface{}); ok {
		if includes, ok := branches["include"].([]interface{}); ok {
			for _, item := range includes {
				if branch, ok := item.(string); ok {
					patterns = append(patterns, branch)
				}
			}
		}
	}
	return patterns
}

func (p *AzureParser) convertWithLines(azPipeline *AzurePipelines, lineMap map[string]int) *NormalizedWorkflow {
	wf := &NormalizedWorkflow{
		Platform: "azure",
		Jobs:     make(map[string]*NormalizedJob),
		Env:      azPipeline.Variables,
		Triggers: p.getTriggers(azPipeline),
		Raw:      azPipeline,
	}

	if len(lineMap) > 0 {
		wf.TriggerLines = make(map[string]int)
		if line, ok := lineMap["trigger"]; ok {
			wf.TriggerLines["trigger"] = line
		}
		if line, ok := lineMap["pr"]; ok {
			wf.TriggerLines["pr"] = line
		}
	}

	for stageIdx := range azPipeline.Stages {
		stage := &azPipeline.Stages[stageIdx]
		for jobIdx, azJob := range stage.Jobs {
			jobID := stage.Name + "-" + azJob.Name
			job := p.convertJob(azJob, jobID, azPipeline)
			if stage.Condition != "" {
				job.Condition = stage.Condition
			}
			if line, ok := lineMap[fmt.Sprintf("stages[%d].jobs[%d]", stageIdx, jobIdx)]; ok {
				job.Line = line
			}
			for stepIdx, step := range job.Steps {
				pathKey := fmt.Sprintf("stages[%d].jobs[%d].steps[%d]", stageIdx, jobIdx, stepIdx)
				if line, ok := lineMap[pathKey]; ok {
					step.Line = line
				}
				if len(lineMap) > 0 {
					step.WithLines = make(map[string]int)
					for key := range step.With {
						fieldKey := fmt.Sprintf("stages[%d].jobs[%d].steps[%d].inputs.%s", stageIdx, jobIdx, stepIdx, key)
						if line, ok := lineMap[fieldKey]; ok {
							step.WithLines[key] = line
						}
					}
					step.EnvLines = make(map[string]int)
					for key := range step.Env {
						fieldKey := fmt.Sprintf("stages[%d].jobs[%d].steps[%d].env.%s", stageIdx, jobIdx, stepIdx, key)
						if line, ok := lineMap[fieldKey]; ok {
							step.EnvLines[key] = line
						}
					}
				}
			}
			wf.Jobs[jobID] = job
		}
	}

	for jobIdx := range azPipeline.Jobs {
		azJob := &azPipeline.Jobs[jobIdx]
		jobID := azJob.Name
		if jobID == "" {
			jobID = fmt.Sprintf("job-%d", len(wf.Jobs))
		}
		job := p.convertJob(*azJob, jobID, azPipeline)
		if line, ok := lineMap[fmt.Sprintf("jobs[%d]", jobIdx)]; ok {
			job.Line = line
		}
		for stepIdx, step := range job.Steps {
			pathKey := fmt.Sprintf("jobs[%d].steps[%d]", jobIdx, stepIdx)
			if line, ok := lineMap[pathKey]; ok {
				step.Line = line
			}
			if len(lineMap) > 0 {
				step.WithLines = make(map[string]int)
				for key := range step.With {
					fieldKey := fmt.Sprintf("jobs[%d].steps[%d].inputs.%s", jobIdx, stepIdx, key)
					if line, ok := lineMap[fieldKey]; ok {
						step.WithLines[key] = line
					}
				}
				step.EnvLines = make(map[string]int)
				for key := range step.Env {
					fieldKey := fmt.Sprintf("jobs[%d].steps[%d].env.%s", jobIdx, stepIdx, key)
					if line, ok := lineMap[fieldKey]; ok {
						step.EnvLines[key] = line
					}
				}
			}
		}
		wf.Jobs[jobID] = job
	}

	if len(azPipeline.Steps) > 0 {
		steps := p.convertSteps(azPipeline.Steps)
		for stepIdx, step := range steps {
			pathKey := fmt.Sprintf("steps[%d]", stepIdx)
			if line, ok := lineMap[pathKey]; ok {
				step.Line = line
			}
			if len(lineMap) > 0 {
				step.WithLines = make(map[string]int)
				for key := range step.With {
					fieldKey := fmt.Sprintf("steps[%d].inputs.%s", stepIdx, key)
					if line, ok := lineMap[fieldKey]; ok {
						step.WithLines[key] = line
					}
				}
				step.EnvLines = make(map[string]int)
				for key := range step.Env {
					fieldKey := fmt.Sprintf("steps[%d].env.%s", stepIdx, key)
					if line, ok := lineMap[fieldKey]; ok {
						step.EnvLines[key] = line
					}
				}
			}
		}
		job := &NormalizedJob{
			ID:     "main",
			Name:   "main",
			Steps:  steps,
			RunsOn: p.getPoolName(azPipeline.Pool, nil),
		}
		wf.Jobs["main"] = job
	}

	return wf
}

func (p *AzureParser) convertJob(azJob AzureJob, jobID string, pipeline *AzurePipelines) *NormalizedJob {
	job := &NormalizedJob{
		ID:        jobID,
		Name:      azJob.DisplayName,
		RunsOn:    p.getPoolName(azJob.Pool, pipeline.Pool),
		Needs:     azJob.DependsOn,
		Condition: azJob.Condition,
		Steps:     p.convertSteps(azJob.Steps),
		Env:       azJob.Variables,
		Services:  make(map[string]*NormalizedService),
	}

	if job.Name == "" {
		job.Name = azJob.Name
	}

	return job
}

func (p *AzureParser) convertSteps(azSteps []AzureStep) []*NormalizedStep {
	steps := make([]*NormalizedStep, 0, len(azSteps))

	for i := range azSteps {
		azStep := &azSteps[i]
		step := &NormalizedStep{
			Name:      azStep.DisplayName,
			Condition: azStep.Condition,
			Env:       azStep.Env,
			With:      azStep.Inputs,
		}

		if azStep.Script != "" {
			step.Run = azStep.Script
		} else if azStep.Bash != "" {
			step.Run = azStep.Bash
		} else if azStep.PowerShell != "" {
			step.Run = azStep.PowerShell
		} else if azStep.Pwsh != "" {
			step.Run = azStep.Pwsh
		} else if azStep.Task != "" {
			step.Uses = azStep.Task
		} else if azStep.Checkout != "" {
			step.Uses = "checkout:" + azStep.Checkout
		} else if azStep.Template != "" {
			// Detections match on this synthesized prefix.
			step.Uses = "template:" + azStep.Template
		}

		steps = append(steps, step)
	}

	return steps
}

func (p *AzureParser) getPoolName(jobPool, pipelinePool *AzurePool) string {
	if jobPool != nil {
		if jobPool.VMImage != "" {
			return jobPool.VMImage
		}
		if jobPool.Name != "" {
			return jobPool.Name
		}
	}

	if pipelinePool != nil {
		if pipelinePool.VMImage != "" {
			return pipelinePool.VMImage
		}
		if pipelinePool.Name != "" {
			return pipelinePool.Name
		}
	}

	return ""
}

type AzurePipelines struct {
	Trigger    interface{}       `yaml:"trigger"`
	PR         interface{}       `yaml:"pr"`
	Pool       *AzurePool        `yaml:"pool"`
	Variables  map[string]string `yaml:"-"`
	Parameters []AzureParameter  `yaml:"-"`
	Stages     []AzureStage      `yaml:"-"`
	Jobs       []AzureJob        `yaml:"-"`
	Steps      []AzureStep       `yaml:"-"`
	Extends    interface{}       `yaml:"extends"`
	Resources  interface{}       `yaml:"resources"`
}

type AzurePool struct {
	VMImage string   `yaml:"vmImage"`
	Name    string   `yaml:"name"`
	Demands []string `yaml:"demands"`
}

type AzureParameter struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type"`
	Default string `yaml:"default"`
}

type AzureStage struct {
	Name        string     `yaml:"stage"`
	DisplayName string     `yaml:"displayName"`
	Condition   string     `yaml:"condition"`
	Jobs        []AzureJob `yaml:"-"`
}

type AzureJob struct {
	Name               string                 `yaml:"job"`
	DisplayName        string                 `yaml:"displayName"`
	Pool               *AzurePool             `yaml:"pool"`
	DependsOn          []string               `yaml:"-"`
	Condition          string                 `yaml:"condition"`
	Steps              []AzureStep            `yaml:"-"`
	Variables          map[string]string      `yaml:"-"`
	Template           string                 `yaml:"template"`
	TemplateParameters map[string]interface{} `yaml:"parameters,omitempty"`
}

type AzureStep struct {
	DisplayName        string                 `yaml:"displayName"`
	Script             string                 `yaml:"script"`
	Bash               string                 `yaml:"bash"`
	PowerShell         string                 `yaml:"powershell"`
	Pwsh               string                 `yaml:"pwsh"`
	Task               string                 `yaml:"task"`
	Checkout           string                 `yaml:"checkout"`
	Inputs             map[string]string      `yaml:"-"`
	Env                map[string]string      `yaml:"-"`
	Condition          string                 `yaml:"condition"`
	Template           string                 `yaml:"template"`
	TemplateParameters map[string]interface{} `yaml:"parameters,omitempty"`
}

func init() {
	RegisterParser(NewAzureParser())
}
