package secretsexposure

import (
	"context"
	"fmt"
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
	registry.RegisterDetection(platforms.PlatformAzureDevOps, "secrets-exposure", func() detections.Detection {
		return New()
	})
}

// varRefPattern matches Azure DevOps variable references like $(VarName)
var varRefPattern = regexp.MustCompile(`\$\(([^)]+)\)`)

// secretKeywordPattern matches variable names containing secret-related keywords
var secretKeywordPattern = regexp.MustCompile(`(?i)(secret|password|token|key|credential|pat|apikey)`)

// extractVariableRefs extracts all $(...) variable references from a string.
func extractVariableRefs(s string) []string {
	matches := varRefPattern.FindAllStringSubmatch(s, -1)
	refs := make([]string, 0, len(matches))
	for _, m := range matches {
		refs = append(refs, m[1])
	}
	return refs
}

// allRefsSafe returns true if every variable reference is in the safe system variables list.
func allRefsSafe(refs []string) bool {
	if len(refs) == 0 {
		return false
	}
	for _, ref := range refs {
		if !common.SafeSystemVariablesMacro[ref] {
			return false
		}
	}
	return true
}

// Detection detects secrets exposure vulnerabilities in pipeline steps
type Detection struct {
	base.BaseDetection
}

// New creates a new secrets-exposure detection
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("secrets-exposure", platforms.PlatformAzureDevOps, detections.SeverityHigh),
	}
}

// Detect analyzes the graph for secrets exposure vulnerabilities
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	for _, wfNode := range g.GetNodesByType(graph.NodeTypeWorkflow) {
		wf, ok := wfNode.(*graph.WorkflowNode)
		if !ok {
			continue
		}

		// insecure-secrets checks
		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			if node.Type() == graph.NodeTypeStep {
				step := node.(*graph.StepNode)

				if step.Run != "" {
					if finding := checkInsecureSecrets(wf, step); finding != nil {
						findings = append(findings, *finding)
						return true
					}
				}

				if len(step.With) > 0 {
					if finding := checkTaskInputSecrets(wf, step); finding != nil {
						findings = append(findings, *finding)
					}
				}
			}
			return true
		})

		// fork-security check
		findings = append(findings, checkForkBuildSettings(wf, g)...)
	}

	return findings, nil
}

// contentLineForPattern returns the absolute line number where keyword first appears in script.
// baseLine is the YAML key line (e.g. the "script:" input key line).
// For multi-line block scalars, content starts at baseLine+1.
// For single-line scripts, content is on baseLine.
func contentLineForPattern(baseLine int, script, keyword string) int {
	if script == "" {
		return baseLine
	}
	lines := strings.Split(script, "\n")
	keywordLower := strings.ToLower(keyword)
	for i, line := range lines {
		if strings.Contains(strings.ToLower(line), keywordLower) {
			if len(lines) == 1 {
				return baseLine
			}
			return baseLine + 1 + i
		}
	}
	return baseLine
}

// checkInsecureSecrets checks for insecure secret handling patterns.
// It checks all patterns independently so that e.g. a safe echo doesn't
// prevent printenv from being detected in the same script block.
func checkInsecureSecrets(wf *graph.WorkflowNode, step *graph.StepNode) *detections.Finding {
	runLower := strings.ToLower(step.Run)

	// Check for echo with variable expansion: echo $(...) or echo ${...}
	if strings.Contains(runLower, "echo") && (strings.Contains(step.Run, "$(") || strings.Contains(step.Run, "${")) {
		refs := extractVariableRefs(step.Run)
		if !allRefsSafe(refs) {
			echoLine := common.ScriptLineForPattern(step, "echo", true)
			return &detections.Finding{
				Type:        detections.VulnUnredactedSecrets,
				Platform:    platforms.PlatformAzureDevOps,
				Class:       detections.ClassSecretsExposure,
				Severity:    detections.SeverityHigh,
				Confidence:  detections.ConfidenceHigh,
				Complexity:  detections.ComplexityLow,
				Repository:  wf.RepoSlug,
				Workflow:    wf.Name,
				Step:        step.Name,
				Line:        echoLine,
				Evidence:    "Echo command with variable expansion: " + step.Run,
				Remediation: "Never echo secrets or variables that might contain secrets. Use secure logging mechanisms and mask secrets in CI/CD output.",
				Details: &detections.FindingDetails{
					LineRanges: []detections.LineRange{{
						Start: echoLine,
						End:   echoLine,
						Label: "secret echo",
					}},
				},
			}
		}
		// Safe refs — fall through to check other patterns
	}

	// Check for curl/wget with variable expansion (sending secrets via HTTP)
	if (strings.Contains(runLower, "curl") || strings.Contains(runLower, "wget")) && (strings.Contains(step.Run, "$(") || strings.Contains(step.Run, "${")) {
		refs := extractVariableRefs(step.Run)
		if !allRefsSafe(refs) {
			curlKeyword := "curl"
			if !strings.Contains(runLower, "curl") {
				curlKeyword = "wget"
			}
			cmdLine := common.ScriptLineForPattern(step, curlKeyword, true)
			return &detections.Finding{
				Type:        detections.VulnTokenExposure,
				Platform:    platforms.PlatformAzureDevOps,
				Class:       detections.ClassSecretsExposure,
				Severity:    detections.SeverityHigh,
				Confidence:  detections.ConfidenceHigh,
				Complexity:  detections.ComplexityLow,
				Repository:  wf.RepoSlug,
				Workflow:    wf.Name,
				Step:        step.Name,
				Line:        cmdLine,
				Evidence:    "HTTP request with variable expansion: " + step.Run,
				Remediation: "Never include secrets in HTTP URLs. Secrets in URLs may be logged by proxies, servers, and browsers. Use headers or POST body instead.",
				Details: &detections.FindingDetails{
					LineRanges: []detections.LineRange{{
						Start: cmdLine,
						End:   cmdLine,
						Label: "secret in HTTP request",
					}},
				},
			}
		}
		// Safe refs — fall through to check other patterns
	}

	// Check for printenv (dumps all environment variables) — always flagged
	if strings.Contains(runLower, "printenv") {
		peLine := common.ScriptLineForPattern(step, "printenv", true)
		return &detections.Finding{
			Type:        detections.VulnUnredactedSecrets,
			Platform:    platforms.PlatformAzureDevOps,
			Class:       detections.ClassSecretsExposure,
			Severity:    detections.SeverityHigh,
			Confidence:  detections.ConfidenceHigh,
			Complexity:  detections.ComplexityLow,
			Repository:  wf.RepoSlug,
			Workflow:    wf.Name,
			Step:        step.Name,
			Line:        peLine,
			Evidence:    "printenv dumps all environment variables: " + step.Run,
			Remediation: "Do not use printenv as it exposes all environment variables including secrets. If debugging is needed, print only specific non-secret variables.",
			Details: &detections.FindingDetails{
				LineRanges: []detections.LineRange{{
					Start: peLine,
					End:   peLine,
					Label: "environment dump",
				}},
			},
		}
	}

	// Check for env | or set | (dumps all environment variables)
	if strings.Contains(runLower, "env |") || strings.Contains(runLower, "set |") {
		envKeyword := "env |"
		if !strings.Contains(runLower, "env |") {
			envKeyword = "set |"
		}
		envLine := common.ScriptLineForPattern(step, envKeyword, true)
		return &detections.Finding{
			Type:        detections.VulnUnredactedSecrets,
			Platform:    platforms.PlatformAzureDevOps,
			Class:       detections.ClassSecretsExposure,
			Severity:    detections.SeverityHigh,
			Confidence:  detections.ConfidenceHigh,
			Complexity:  detections.ComplexityLow,
			Repository:  wf.RepoSlug,
			Workflow:    wf.Name,
			Step:        step.Name,
			Line:        envLine,
			Evidence:    "Environment variable dump command: " + step.Run,
			Remediation: "Do not dump all environment variables as they may contain secrets. If debugging is needed, print only specific non-secret variables.",
			Details: &detections.FindingDetails{
				LineRanges: []detections.LineRange{{
					Start: envLine,
					End:   envLine,
					Label: "environment dump",
				}},
			},
		}
	}

	return nil
}

// checkTaskInputSecrets checks task inputs (step.With) for insecure secret handling.
// Azure Pipelines primarily use tasks with inputs rather than inline scripts,
// so we need to scan task input values for secret variable references and
// check "script"/"inline" inputs for the same patterns as Run commands.
func checkTaskInputSecrets(wf *graph.WorkflowNode, step *graph.StepNode) *detections.Finding {
	for inputKey, inputVal := range step.With {
		// Check "script" and "inline" inputs for Run-like patterns (echo, curl, printenv)
		keyLower := strings.ToLower(inputKey)
		if keyLower == "script" || keyLower == "inline" {
			finding := checkScriptContent(wf, step, inputKey, inputVal)
			if finding != nil {
				return finding
			}
			continue
		}

		// For other inputs, check if they reference non-safe variables with secret-like names
		refs := extractVariableRefs(inputVal)
		for _, ref := range refs {
			if common.SafeSystemVariablesMacro[ref] {
				continue
			}
			if secretKeywordPattern.MatchString(ref) {
				inputLine := common.LineForKey(step.WithLines, inputKey, step.Line)
				return &detections.Finding{
					Type:        detections.VulnTokenExposure,
					Platform:    platforms.PlatformAzureDevOps,
					Class:       detections.ClassSecretsExposure,
					Severity:    detections.SeverityHigh,
					Confidence:  detections.ConfidenceMedium,
					Complexity:  detections.ComplexityLow,
					Repository:  wf.RepoSlug,
					Workflow:    wf.Name,
					Step:        step.Name,
					Line:        inputLine,
					Evidence:    fmt.Sprintf("Task input %q references secret-like variable: %s", inputKey, inputVal),
					Remediation: "Avoid passing secrets directly in task inputs. Use secure pipeline variable references or secret-type variables that are automatically masked.",
					Details: &detections.FindingDetails{
						LineRanges: []detections.LineRange{{
							Start: inputLine,
							End:   inputLine,
							Label: "secret in task input",
						}},
					},
				}
			}
		}
	}

	return nil
}

// checkScriptContent checks inline script content (from task inputs like "script" or "inline")
// for the same insecure patterns as Run commands. Checks all patterns independently so that
// e.g. a safe echo doesn't prevent printenv from being detected.
func checkScriptContent(wf *graph.WorkflowNode, step *graph.StepNode, inputKey, script string) *detections.Finding {
	scriptLower := strings.ToLower(script)
	baseLine := common.LineForKey(step.WithLines, inputKey, step.Line)

	// Check for echo with variable expansion
	if strings.Contains(scriptLower, "echo") && (strings.Contains(script, "$(") || strings.Contains(script, "${")) {
		refs := extractVariableRefs(script)
		if !allRefsSafe(refs) {
			echoLine := contentLineForPattern(baseLine, script, "echo")
			return &detections.Finding{
				Type:        detections.VulnUnredactedSecrets,
				Platform:    platforms.PlatformAzureDevOps,
				Class:       detections.ClassSecretsExposure,
				Severity:    detections.SeverityHigh,
				Confidence:  detections.ConfidenceHigh,
				Complexity:  detections.ComplexityLow,
				Repository:  wf.RepoSlug,
				Workflow:    wf.Name,
				Step:        step.Name,
				Line:        echoLine,
				Evidence:    "Task input script with variable expansion: " + script,
				Remediation: "Never echo secrets in task script inputs. Use secure logging mechanisms and mask secrets in CI/CD output.",
				Details: &detections.FindingDetails{
					LineRanges: []detections.LineRange{{
						Start: echoLine,
						End:   echoLine,
						Label: "secret echo in task input",
					}},
				},
			}
		}
		// Safe refs — fall through to check other patterns
	}

	// Check for curl/wget with variable expansion
	if (strings.Contains(scriptLower, "curl") || strings.Contains(scriptLower, "wget")) && (strings.Contains(script, "$(") || strings.Contains(script, "${")) {
		refs := extractVariableRefs(script)
		if !allRefsSafe(refs) {
			curlKeyword := "curl"
			if !strings.Contains(scriptLower, "curl") {
				curlKeyword = "wget"
			}
			cmdLine := contentLineForPattern(baseLine, script, curlKeyword)
			return &detections.Finding{
				Type:        detections.VulnTokenExposure,
				Platform:    platforms.PlatformAzureDevOps,
				Class:       detections.ClassSecretsExposure,
				Severity:    detections.SeverityHigh,
				Confidence:  detections.ConfidenceHigh,
				Complexity:  detections.ComplexityLow,
				Repository:  wf.RepoSlug,
				Workflow:    wf.Name,
				Step:        step.Name,
				Line:        cmdLine,
				Evidence:    "Task input script with HTTP request and variable expansion: " + script,
				Remediation: "Never include secrets in HTTP URLs within task script inputs.",
				Details: &detections.FindingDetails{
					LineRanges: []detections.LineRange{{
						Start: cmdLine,
						End:   cmdLine,
						Label: "secret in HTTP request",
					}},
				},
			}
		}
		// Safe refs — fall through to check other patterns
	}

	// Check for printenv
	if strings.Contains(scriptLower, "printenv") {
		peLine := contentLineForPattern(baseLine, script, "printenv")
		return &detections.Finding{
			Type:        detections.VulnUnredactedSecrets,
			Platform:    platforms.PlatformAzureDevOps,
			Class:       detections.ClassSecretsExposure,
			Severity:    detections.SeverityHigh,
			Confidence:  detections.ConfidenceHigh,
			Complexity:  detections.ComplexityLow,
			Repository:  wf.RepoSlug,
			Workflow:    wf.Name,
			Step:        step.Name,
			Line:        peLine,
			Evidence:    "Task input script dumps environment variables: " + script,
			Remediation: "Do not use printenv in task script inputs as it exposes all environment variables including secrets.",
			Details: &detections.FindingDetails{
				LineRanges: []detections.LineRange{{
					Start: peLine,
					End:   peLine,
					Label: "environment dump in task input",
				}},
			},
		}
	}

	return nil
}

// checkForkBuildSettings checks for insecure fork build configurations
func checkForkBuildSettings(wf *graph.WorkflowNode, g *graph.Graph) []detections.Finding {
	var findings []detections.Finding

	// Check if workflow is triggered by pull_request
	hasPRTrigger := false
	for _, trigger := range wf.Triggers {
		triggerLower := strings.ToLower(trigger)
		if strings.Contains(triggerLower, "pullrequest") || strings.Contains(triggerLower, "pr") {
			hasPRTrigger = true
			break
		}
	}

	if !hasPRTrigger {
		return findings
	}

	// Walk steps to check for secrets being passed to fork builds
	hasSecretsExposure := false
	var evidenceStep string
	var evidenceLine int

	graph.DFS(g, wf.ID(), func(node graph.Node) bool {
		if node.Type() == graph.NodeTypeStep {
			step := node.(*graph.StepNode)

			// Check environment variables for secrets
			for envKey, envValue := range step.Env {
				envKeyLower := strings.ToLower(envKey)
				envValueLower := strings.ToLower(envValue)

				if strings.Contains(envKeyLower, "secret") ||
					strings.Contains(envKeyLower, "token") ||
					strings.Contains(envKeyLower, "password") ||
					strings.Contains(envKeyLower, "key") {
					hasSecretsExposure = true
					evidenceStep = step.Name
					evidenceLine = common.LineForKey(step.EnvLines, envKey, step.Line)
					return false
				}

				if strings.Contains(envValueLower, "secret") ||
					strings.Contains(envValueLower, "variables.") {
					hasSecretsExposure = true
					evidenceStep = step.Name
					evidenceLine = common.LineForKey(step.EnvLines, envKey, step.Line)
					return false
				}
			}

			// Check task inputs for secret references
			for paramKey, paramValue := range step.With {
				paramValueLower := strings.ToLower(paramValue)
				if strings.Contains(paramValueLower, "secret") ||
					strings.Contains(paramValueLower, "variables.") {
					hasSecretsExposure = true
					evidenceStep = step.Name
					evidenceLine = common.LineForKey(step.WithLines, paramKey, step.Line)
					return false
				}
			}
		}
		return true
	})

	if hasSecretsExposure {
		findings = append(findings, detections.Finding{
			Type:        detections.VulnPullRequestSecretsExposure,
			Severity:    detections.SeverityHigh,
			Confidence:  detections.ConfidenceHigh,
			Complexity:  detections.ComplexityLow,
			Platform:    platforms.PlatformAzureDevOps,
			Class:       detections.ClassSecretsExposure,
			Repository:  wf.RepoSlug,
			Workflow:    wf.Name,
			Step:        evidenceStep,
			Line:        evidenceLine,
			Evidence:    "Fork builds enabled with access to secrets in step: " + evidenceStep,
			Remediation: "Disable fork builds or ensure secrets are not passed to fork PRs. Add 'Comment requirements' policy for external contributions. Use 'Build.Reason' condition to restrict secret access: condition: ne(variables['Build.Reason'], 'PullRequest')",
			Details: &detections.FindingDetails{
				LineRanges: []detections.LineRange{{
					Start: evidenceLine,
					End:   evidenceLine,
					Label: "secret exposed to fork builds",
				}},
			},
		})
	}

	return findings
}
