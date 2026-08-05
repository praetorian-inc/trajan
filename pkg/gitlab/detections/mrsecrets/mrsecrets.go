package mrsecrets

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/gitlab/detections/common"
)

func init() {
	registry.RegisterDetection("gitlab", "merge-request-secrets-exposure", func() detections.Detection {
		return New()
	})
}

type Detection struct {
	base.BaseDetection
	secretKeywords []string
	varPattern     *regexp.Regexp
}

func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection(
			"merge-request-secrets-exposure",
			"gitlab",
			detections.SeverityHigh,
		),
		secretKeywords: []string{
			"token",
			"key",
			"secret",
			"password",
			"api_key",
			"apikey",
			"credentials",
			"credential",
		},
		varPattern: regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`),
	}
}

func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)

	for _, wfNode := range workflows {
		wf, ok := wfNode.(*graph.WorkflowNode)
		if !ok {
			continue
		}

		// Only DFS from root workflows to avoid duplicates
		if !common.IsRootWorkflow(g, wf) {
			continue
		}

		if !common.HasMergeRequestTrigger(wf, g) {
			continue
		}

		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			job, ok := node.(*graph.JobNode)
			if !ok {
				return true
			}

			if common.IsProtectedBranchOnly(job) {
				return true
			}

			if !common.JobRunsOnMR(job, wf, g) {
				return true
			}

			var allSensitiveVars []string
			var firstStep *graph.StepNode
			seen := make(map[string]bool)

			graph.DFS(g, job.ID(), func(stepNode graph.Node) bool {
				step, ok := stepNode.(*graph.StepNode)
				if !ok {
					return true
				}

				if step.Run == "" {
					return true
				}

				if firstStep == nil {
					firstStep = step
				}

				sensitiveVars := d.findSensitiveVariables(step.Run)
				for _, varName := range sensitiveVars {
					if !seen[varName] {
						allSensitiveVars = append(allSensitiveVars, varName)
						seen[varName] = true
					}
				}

				return true
			})

			// One finding per job, not per step.
			if len(allSensitiveVars) > 0 && firstStep != nil {
				finding := d.createFinding(g, job, firstStep, allSensitiveVars)
				findings = append(findings, finding)
			}

			return true
		})
	}

	return findings, nil
}

func (d *Detection) findSensitiveVariables(script string) []string {
	var sensitiveVars []string
	seen := make(map[string]bool)

	matches := d.varPattern.FindAllStringSubmatch(script, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		varName := match[1]
		if seen[varName] {
			continue
		}

		if d.isSensitiveVariable(varName) {
			sensitiveVars = append(sensitiveVars, varName)
			seen[varName] = true
		}
	}

	return sensitiveVars
}

func (d *Detection) isSensitiveVariable(varName string) bool {
	varLower := strings.ToLower(varName)

	for _, keyword := range d.secretKeywords {
		if strings.Contains(varLower, keyword) {
			return true
		}
	}

	return false
}

func (d *Detection) createFinding(g *graph.Graph, job *graph.JobNode, step *graph.StepNode, exposedVars []string) detections.Finding {
	wf := common.GetJobParentWorkflow(g, job)
	if wf == nil {
		wf = &graph.WorkflowNode{}
	}
	varList := strings.Join(exposedVars, ", ")
	evidence := fmt.Sprintf("Job '%s' runs on merge_request trigger and accesses sensitive variables (%s) without protected branch restrictions. ", job.Name, varList)
	evidence += fmt.Sprintf("External attackers can submit malicious merge requests that modify this job to exfiltrate %d secrets.", len(exposedVars))

	attackChain := detections.BuildChainFromNodes(wf, job, step)

	var lineRanges []detections.LineRange
	if job.Line > 0 {
		lineRanges = append(lineRanges, detections.LineRange{
			Start: job.Line,
			End:   job.Line + 3,
			Label: "MR-triggered job with secrets",
		})
	}
	if step.Line > 0 && step.Line != job.Line {
		lineRanges = append(lineRanges, detections.LineRange{
			Start: step.Line,
			End:   step.Line,
			Label: "secret usage",
		})
	}

	metadata := make(map[string]interface{})
	metadata["exposedSecrets"] = exposedVars
	metadata["secretCount"] = len(exposedVars)
	metadata["trigger"] = "merge_request"

	return detections.Finding{
		Type:         detections.VulnMergeRequestSecretsExposure,
		Severity:     detections.SeverityHigh,
		Confidence:   detections.ConfidenceHigh,
		Complexity:   detections.ComplexityZeroClick,
		Platform:     "gitlab",
		Class:        detections.GetVulnerabilityClass(detections.VulnMergeRequestSecretsExposure),
		Repository:   wf.RepoSlug,
		Workflow:     wf.Path,
		WorkflowFile: wf.Path,
		Job:          job.Name,
		Step:         step.Name,
		Line:         step.Line,
		Evidence:     evidence,
		Remediation:  "Restrict this job to protected branches using rules: [{if: \"$CI_COMMIT_BRANCH == 'main'\"}], or mark variables as protected in Settings → CI/CD → Variables (protected variables are only available on protected branches).",
		Details: &detections.FindingDetails{
			LineRanges:  lineRanges,
			AttackChain: attackChain,
			Metadata:    metadata,
		},
	}
}
