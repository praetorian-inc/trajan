package pipelineinjection

import (
	"context"
	"regexp"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/azuredevops/detections/common"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func init() {
	registry.RegisterDetection(platforms.PlatformAzureDevOps, "pipeline-injection", func() detections.Detection {
		return New()
	})
}

// ${{ }}: compile-time template expression
var exprRegex = regexp.MustCompile(`\$\{\{\s*(.+?)\s*\}\}`)

// $[ ]: runtime expression
var runtimeExprRegex = regexp.MustCompile(`\$\[\s*(.+?)\s*\]`)

// $(Var): macro expression
var macroRefRegex = regexp.MustCompile(`\$\(([^)]+)\)`)

type Detection struct {
	base.BaseDetection
}

func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("pipeline-injection", platforms.PlatformAzureDevOps, detections.SeverityCritical),
	}
}

func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding
	for _, node := range g.GetNodesByType(graph.NodeTypeWorkflow) {
		wf, ok := node.(*graph.WorkflowNode)
		if !ok {
			continue
		}
		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			if node.Type() == graph.NodeTypeStep {
				step, ok := node.(*graph.StepNode)
				if !ok {
					return true
				}
				if step.Run != "" {
					if finding := checkScriptInjection(wf, step); finding != nil {
						findings = append(findings, *finding)
					}
				}
				if step.Uses != "" && strings.HasPrefix(step.Uses, "template:") {
					if finding := checkTemplateReference(wf, step); finding != nil {
						findings = append(findings, *finding)
					}
				}
			}
			return true
		})
		findings = append(findings, checkTriggerPatterns(wf)...)
	}
	return findings, nil
}

func checkScriptInjection(wf *graph.WorkflowNode, step *graph.StepNode) *detections.Finding {
	compileTimeMatches := exprRegex.FindAllStringSubmatch(step.Run, -1)
	for _, match := range compileTimeMatches {
		if len(match) < 2 {
			continue
		}
		expr := strings.TrimSpace(match[1])

		if strings.HasPrefix(expr, "parameters.") {
			injLine := common.ScriptLineForPattern(step, match[0], false)
			return &detections.Finding{
				Type:       detections.VulnScriptInjection,
				Platform:   platforms.PlatformAzureDevOps,
				Class:      detections.GetVulnerabilityClass(detections.VulnScriptInjection),
				Severity:   detections.SeverityHigh,
				Confidence: detections.ConfidenceHigh,
				Complexity: detections.ComplexityLow,
				Repository: wf.RepoSlug,
				Workflow:   wf.Name,
				Step:       step.Name,
				Line:       injLine,
				Evidence:   match[0],
				Remediation: "Use an environment variable instead of direct parameter interpolation in scripts. " +
					"Set the parameter as an env var and reference it safely: env: PARAM: ${{ parameters.x }}",
				Details: &detections.FindingDetails{
					LineRanges: []detections.LineRange{{
						Start: injLine,
						End:   injLine,
						Label: "injection point",
					}},
					InjectableContexts: []string{match[0]},
					Metadata: map[string]interface{}{
						"sink": "script (compile-time template expression)",
					},
				},
			}
		}

		if strings.HasPrefix(expr, "variables.") {
			varName := strings.TrimPrefix(expr, "variables.")

			if common.SafeSystemVariablesTemplateExpr[varName] {
				continue
			}

			// Variables can come from PR context, which is untrusted
			injLine := common.ScriptLineForPattern(step, match[0], false)
			return &detections.Finding{
				Type:       detections.VulnScriptInjection,
				Platform:   platforms.PlatformAzureDevOps,
				Class:      detections.GetVulnerabilityClass(detections.VulnScriptInjection),
				Severity:   detections.SeverityHigh,
				Confidence: detections.ConfidenceMedium,
				Complexity: detections.ComplexityLow,
				Repository: wf.RepoSlug,
				Workflow:   wf.Name,
				Step:       step.Name,
				Line:       injLine,
				Evidence:   match[0],
				Remediation: "Avoid using variables directly in scripts as they may come from PR context. " +
					"Use environment variables with validation instead.",
				Details: &detections.FindingDetails{
					LineRanges: []detections.LineRange{{
						Start: injLine,
						End:   injLine,
						Label: "injection point",
					}},
					InjectableContexts: []string{match[0]},
					Metadata: map[string]interface{}{
						"sink": "script (compile-time template expression)",
					},
				},
			}
		}
	}

	runtimeMatches := runtimeExprRegex.FindAllStringSubmatch(step.Run, -1)
	for _, match := range runtimeMatches {
		if len(match) < 2 {
			continue
		}
		expr := strings.TrimSpace(match[1])

		if strings.HasPrefix(expr, "parameters.") || strings.HasPrefix(expr, "variables.") {
			injLine := common.ScriptLineForPattern(step, match[0], false)
			return &detections.Finding{
				Type:       detections.VulnScriptInjection,
				Platform:   platforms.PlatformAzureDevOps,
				Class:      detections.GetVulnerabilityClass(detections.VulnScriptInjection),
				Severity:   detections.SeverityHigh,
				Confidence: detections.ConfidenceHigh,
				Complexity: detections.ComplexityLow,
				Repository: wf.RepoSlug,
				Workflow:   wf.Name,
				Step:       step.Name,
				Line:       injLine,
				Evidence:   match[0],
				Remediation: "Runtime expressions with parameters or variables can be exploited. " +
					"Use environment variables with validation instead of runtime expressions in scripts.",
				Details: &detections.FindingDetails{
					LineRanges: []detections.LineRange{{
						Start: injLine,
						End:   injLine,
						Label: "injection point",
					}},
					InjectableContexts: []string{match[0]},
					Metadata: map[string]interface{}{
						"sink": "script (runtime expression)",
					},
				},
			}
		}
	}

	macroMatches := macroRefRegex.FindAllStringSubmatch(step.Run, -1)
	for _, match := range macroMatches {
		if len(match) < 2 {
			continue
		}
		varName := strings.TrimSpace(match[1])

		if common.SafeSystemVariablesMacro[varName] {
			continue
		}

		for _, injectable := range common.InjectableContexts {
			if varName == injectable {
				injLine := common.ScriptLineForPattern(step, match[0], false)
				return &detections.Finding{
					Type:       detections.VulnScriptInjection,
					Platform:   platforms.PlatformAzureDevOps,
					Class:      detections.GetVulnerabilityClass(detections.VulnScriptInjection),
					Severity:   detections.SeverityHigh,
					Confidence: detections.ConfidenceHigh,
					Complexity: detections.ComplexityLow,
					Repository: wf.RepoSlug,
					Workflow:   wf.Name,
					Step:       step.Name,
					Line:       injLine,
					Evidence:   match[0],
					Remediation: "Macro expression references an injectable variable. " +
						"Use an environment variable instead of direct macro interpolation in scripts.",
					Details: &detections.FindingDetails{
						LineRanges: []detections.LineRange{{
							Start: injLine,
							End:   injLine,
							Label: "injection point",
						}},
						InjectableContexts: []string{match[0]},
						Metadata: map[string]interface{}{
							"sink": "script (macro expression)",
						},
					},
				}
			}
		}
	}

	return nil
}

func checkTemplateReference(wf *graph.WorkflowNode, step *graph.StepNode) *detections.Finding {
	templatePath := strings.TrimPrefix(step.Uses, "template:")

	compileTimeMatches := exprRegex.FindAllStringSubmatch(templatePath, -1)
	for _, match := range compileTimeMatches {
		if len(match) < 2 {
			continue
		}
		expr := strings.TrimSpace(match[1])

		if strings.HasPrefix(expr, "parameters.") || strings.HasPrefix(expr, "variables.") {
			return &detections.Finding{
				Type:       detections.VulnDynamicTemplateInjection,
				Platform:   platforms.PlatformAzureDevOps,
				Class:      detections.GetVulnerabilityClass(detections.VulnDynamicTemplateInjection),
				Severity:   detections.SeverityCritical,
				Confidence: detections.ConfidenceHigh,
				Complexity: detections.ComplexityLow,
				Repository: wf.RepoSlug,
				Workflow:   wf.Name,
				Step:       step.Name,
				Line:       step.Line,
				Evidence:   "Dynamic template reference: " + step.Uses,
				Remediation: "Never use parameters or variables in template references. " +
					"Hardcode the template path to prevent arbitrary code execution. " +
					"Consider using template validation to ensure only approved templates can be loaded.",
				Details: &detections.FindingDetails{
					LineRanges: []detections.LineRange{{
						Start: step.Line,
						End:   step.Line,
						Label: "dynamic template reference",
					}},
					InjectableContexts: []string{match[0]},
					Metadata: map[string]interface{}{
						"sink": "template reference (compile-time expression)",
					},
				},
			}
		}
	}

	runtimeMatches := runtimeExprRegex.FindAllStringSubmatch(templatePath, -1)
	for _, match := range runtimeMatches {
		if len(match) < 2 {
			continue
		}
		expr := strings.TrimSpace(match[1])

		if strings.HasPrefix(expr, "parameters.") || strings.HasPrefix(expr, "variables.") {
			return &detections.Finding{
				Type:       detections.VulnDynamicTemplateInjection,
				Platform:   platforms.PlatformAzureDevOps,
				Class:      detections.GetVulnerabilityClass(detections.VulnDynamicTemplateInjection),
				Severity:   detections.SeverityCritical,
				Confidence: detections.ConfidenceHigh,
				Complexity: detections.ComplexityLow,
				Repository: wf.RepoSlug,
				Workflow:   wf.Name,
				Step:       step.Name,
				Line:       step.Line,
				Evidence:   "Dynamic template reference with runtime expression: " + step.Uses,
				Remediation: "Never use runtime expressions with parameters or variables in template references. " +
					"Hardcode the template path to prevent arbitrary code execution. " +
					"Consider using template validation to ensure only approved templates can be loaded.",
				Details: &detections.FindingDetails{
					LineRanges: []detections.LineRange{{
						Start: step.Line,
						End:   step.Line,
						Label: "dynamic template reference",
					}},
					InjectableContexts: []string{match[0]},
					Metadata: map[string]interface{}{
						"sink": "template reference (runtime expression)",
					},
				},
			}
		}
	}

	return nil
}

// Triggers containing "pr" map to the "pr:" YAML key; all others map to "trigger:".
func triggerLine(wf *graph.WorkflowNode, trigger string) int {
	if wf.TriggerLines == nil {
		return 0
	}
	triggerLower := strings.ToLower(trigger)
	if triggerLower == "pr" || strings.HasPrefix(triggerLower, "pr") {
		return wf.TriggerLines["pr"]
	}
	return wf.TriggerLines["trigger"]
}

func checkTriggerPatterns(wf *graph.WorkflowNode) []detections.Finding {
	var findings []detections.Finding

	for _, trigger := range wf.Triggers {
		triggerLower := strings.ToLower(trigger)

		if strings.Contains(trigger, "*") {
			severity := detections.SeverityHigh
			evidence := "Wildcard branch trigger: " + trigger

			if strings.Contains(triggerLower, "refs/heads/*") ||
				strings.Contains(triggerLower, "users/*") ||
				strings.Contains(triggerLower, "feature/*") {
				severity = detections.SeverityHigh
				evidence = "User-controlled branch pattern: " + trigger
			}

			tLine := triggerLine(wf, trigger)
			findings = append(findings, detections.Finding{
				Type:        detections.VulnTriggerExploitation,
				Severity:    severity,
				Confidence:  detections.ConfidenceHigh,
				Complexity:  detections.ComplexityLow,
				Platform:    platforms.PlatformAzureDevOps,
				Class:       detections.ClassInjection,
				Repository:  wf.RepoSlug,
				Workflow:    wf.Name,
				Trigger:     trigger,
				Line:        tLine,
				Evidence:    evidence,
				Remediation: "Avoid wildcard branch triggers. Use explicit branch lists or protected branch patterns. Apply branch policies to prevent unauthorized branch creation.",
				Details: &detections.FindingDetails{
					LineRanges: []detections.LineRange{{
						Start: tLine,
						End:   tLine,
						Label: "wildcard trigger",
					}},
				},
			})
		}

		if strings.Contains(triggerLower, "ci") || strings.Contains(triggerLower, "batch") {
			tLine := triggerLine(wf, trigger)
			findings = append(findings, detections.Finding{
				Type:        detections.VulnTriggerExploitation,
				Severity:    detections.SeverityMedium,
				Confidence:  detections.ConfidenceMedium,
				Complexity:  detections.ComplexityLow,
				Platform:    platforms.PlatformAzureDevOps,
				Class:       detections.ClassInjection,
				Repository:  wf.RepoSlug,
				Workflow:    wf.Name,
				Trigger:     trigger,
				Line:        tLine,
				Evidence:    "CI trigger without apparent path filters: " + trigger,
				Remediation: "Add path filters to CI triggers to prevent unnecessary builds. Use 'paths' to specify which file changes should trigger the pipeline.",
				Details: &detections.FindingDetails{
					LineRanges: []detections.LineRange{{
						Start: tLine,
						End:   tLine,
						Label: "CI trigger without path filters",
					}},
				},
			})
		}
	}

	return findings
}
