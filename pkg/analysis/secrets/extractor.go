package secrets

import (
	"fmt"

	"github.com/praetorian-inc/trajan/pkg/analysis/expression"
	"github.com/praetorian-inc/trajan/pkg/analysis/parser"
)

// SecretReference represents a secret found in workflow content
type SecretReference struct {
	Name       string     // e.g., "GITHUB_TOKEN", "DEPLOY_KEY"
	Expression string     // e.g., "${{ secrets.GITHUB_TOKEN }}"
	Locations  []Location // All places this secret is referenced
}

// Location identifies where a secret is referenced
type Location struct {
	Workflow string // workflow file name
	Job      string // job name
	Step     string // step name (if applicable)
	Field    string // "env", "with", "run", "if"
	Line     int    // line number (if available)
}

// ExtractSecrets finds all secret references in workflow content
func ExtractSecrets(workflowPath string, content []byte) ([]SecretReference, error) {
	wf, err := parser.ParseWorkflow(content) //nolint:staticcheck // SA1019: secret extraction intentionally uses the GitHub-only parser
	if err != nil {
		return nil, fmt.Errorf("parsing workflow: %w", err)
	}

	secretsMap := make(map[string]*SecretReference)

	// Extract from workflow-level env
	extractFromMap(secretsMap, wf.Env, workflowPath, "", "", "env")

	// Extract from jobs
	for jobName, job := range wf.Jobs {
		// Job-level env
		extractFromMap(secretsMap, job.Env, workflowPath, jobName, "", "env")

		// Steps
		for i, step := range job.Steps {
			stepName := step.Name
			if stepName == "" {
				stepName = step.ID
			}

			// Step env
			extractFromMap(secretsMap, step.Env, workflowPath, jobName, stepName, "env")

			// Step with
			extractFromMap(secretsMap, step.With, workflowPath, jobName, stepName, "with")

			// Step run command
			if step.Run != "" {
				extractFromString(secretsMap, step.Run, workflowPath, jobName, stepName, "run", i)
			}

			// Step if condition
			if step.If != "" {
				extractFromString(secretsMap, step.If, workflowPath, jobName, stepName, "if", i)
			}
		}
	}

	// Convert map to slice
	result := make([]SecretReference, 0, len(secretsMap))
	for _, ref := range secretsMap {
		result = append(result, *ref)
	}

	return result, nil
}

func extractFromMap(secretsMap map[string]*SecretReference, m map[string]string,
	workflow, job, step, field string) {
	for _, val := range m {
		extractFromString(secretsMap, val, workflow, job, step, field, 0)
	}
}

func extractFromString(secretsMap map[string]*SecretReference, s string,
	workflow, job, step, field string, line int) {
	// Use the expression package's AST parser to extract secrets
	evaluator := expression.NewEvaluator()
	expressions, err := evaluator.ExtractAll(s)
	if err != nil {
		// If parsing fails, silently continue (log error if needed)
		return
	}

	// Extract secrets from each parsed expression
	for _, expr := range expressions {
		for _, ref := range expr.References {
			// Only process context references to "secrets"
			if ref.Context == "secrets" && len(ref.Path) > 0 {
				name := ref.Path[0]
				expressionText := expr.Raw

				loc := Location{
					Workflow: workflow,
					Job:      job,
					Step:     step,
					Field:    field,
					Line:     line,
				}

				if existing, exists := secretsMap[name]; exists {
					existing.Locations = append(existing.Locations, loc)
				} else {
					secretsMap[name] = &SecretReference{
						Name:       name,
						Expression: expressionText,
						Locations:  []Location{loc},
					}
				}
			}
		}
	}
}
