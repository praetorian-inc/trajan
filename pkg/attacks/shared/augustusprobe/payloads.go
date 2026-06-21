// Package augustusprobe provides platform-agnostic logic for selecting Augustus
// probes and formatting adversarial prompts for CI/CD delivery.
package augustusprobe

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/probes"
	_ "github.com/praetorian-inc/augustus/pkg/register/probes" // registers all 210+ Augustus probes
	"github.com/praetorian-inc/augustus/pkg/types"

	"github.com/praetorian-inc/trajan/pkg/attacks/shared/payloads"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

// ProbePayload groups prompts from a single Augustus probe.
type ProbePayload struct {
	ProbeName string   // Augustus probe name (e.g., "goodside.SystemPromptConfusion")
	Category  string   // Human-readable category ("instruction_override", "data_extraction", etc.)
	Prompts   []string // Raw adversarial prompt strings
}

// DeliveredPayload records what was actually sent and where.
type DeliveredPayload struct {
	ProbeName string // Which Augustus probe sourced this
	Prompt    string // The actual text delivered
	Location  string // "pr_title", "pr_body", "issue_title", "issue_comment", "file_diff", "html_comment", "commit_message"
}

// PromptInjectionResults is the Data payload for an ai-prompt-injection attack.
type PromptInjectionResults struct {
	DeliveryMethod string             // "pull_request", "issue", "issue_comment"
	TriggerType    string             // The workflow trigger being targeted
	ProbesUsed     []string           // Augustus probe names used
	Payloads       []DeliveredPayload // What was delivered and where
	TotalPrompts   int                // How many prompts were embedded
	EvasionUsed    string             // Evasion technique applied ("", "homoglyph", etc.)
}

// probeCategory maps probe names to human-readable categories.
var probeCategory = map[string]string{
	"goodside.SystemPromptConfusion":    "instruction_override",
	"goodside.ChatMLExploit":            "role_confusion",
	"goodside.PayloadSplitting":         "filter_bypass",
	"latentinjection.LatentExtraction":  "data_extraction",
	"dan.Dan_11_0":                      "jailbreak",
	"promptinject.HijackHateHumansFull": "prompt_hijack",
	"latentinjection.LatentJailbreak":   "jailbreak",
}

// ProbeSet maps a Trajan AI vuln type to the Augustus probes most relevant for exploiting it.
var ProbeSet = map[detections.VulnerabilityType][]string{
	detections.VulnAITokenExfiltration:    {"goodside.SystemPromptConfusion", "latentinjection.LatentExtraction"},
	detections.VulnAICodeInjection:        {"goodside.SystemPromptConfusion", "goodside.ChatMLExploit", "promptinject.HijackHateHumansFull"},
	detections.VulnAIMCPAbuse:             {"goodside.SystemPromptConfusion", "goodside.PayloadSplitting"},
	detections.VulnAIPrivilegeEscalation:  {"goodside.SystemPromptConfusion", "dan.Dan_11_0", "latentinjection.LatentJailbreak"},
	detections.VulnAISupplyChainPoisoning: {"goodside.SystemPromptConfusion", "goodside.ChatMLExploit"}, // packagehallucination probes excluded: nil-map init bug in Augustus v0.0.9
	detections.VulnAIWorkflowSabotage:     {"goodside.SystemPromptConfusion", "dan.Dan_11_0"},
}

// DefaultProbes is used when a vuln type has no specific mapping.
var DefaultProbes = []string{"goodside.SystemPromptConfusion"}

// GetPromptsForVulnType returns Augustus-sourced adversarial prompts relevant
// to the given AI vulnerability type.
func GetPromptsForVulnType(vulnType detections.VulnerabilityType) ([]ProbePayload, error) {
	probeNames, ok := ProbeSet[vulnType]
	if !ok {
		probeNames = DefaultProbes
	}

	seen := make(map[string]bool)
	var results []ProbePayload

	for _, name := range probeNames {
		if seen[name] {
			continue
		}
		seen[name] = true

		probe, err := probes.Create(name, nil)
		if err != nil {
			return nil, fmt.Errorf("creating probe %s: %w", name, err)
		}

		pm, ok := probe.(types.ProbeMetadata)
		if !ok {
			// Probe does not implement ProbeMetadata; skip prompt extraction.
			continue
		}

		prompts := pm.GetPrompts()
		if len(prompts) == 0 {
			continue
		}

		cat := probeCategory[name]
		if cat == "" {
			cat = "general"
		}

		results = append(results, ProbePayload{
			ProbeName: name,
			Category:  cat,
			Prompts:   prompts,
		})
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no prompts found for vulnerability type %s", vulnType)
	}

	return results, nil
}

// GetAllPromptsForVulnTypes aggregates prompts across multiple vuln types,
// deduplicating probes that appear in more than one mapping.
func GetAllPromptsForVulnTypes(vulnTypes []detections.VulnerabilityType) ([]ProbePayload, error) {
	seen := make(map[string]bool)
	var allPayloads []ProbePayload
	var errs []string

	for _, vt := range vulnTypes {
		p, err := GetPromptsForVulnType(vt)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", vt, err))
			continue
		}
		for _, pp := range p {
			if !seen[pp.ProbeName] {
				seen[pp.ProbeName] = true
				allPayloads = append(allPayloads, pp)
			}
		}
	}

	if len(allPayloads) == 0 {
		if len(errs) > 0 {
			return nil, fmt.Errorf("no prompts found; errors: %s", strings.Join(errs, "; "))
		}
		return nil, fmt.Errorf("no prompts found for any of the provided vulnerability types")
	}

	return allPayloads, nil
}

// maxPRTitleLen is the maximum length for a PR title.
const maxPRTitleLen = 256

// FormatForPRTitle truncates/adapts a prompt for use as a PR title.
func FormatForPRTitle(prompt string) string {
	// Replace newlines with spaces for single-line title
	title := strings.ReplaceAll(prompt, "\n", " ")
	title = strings.Join(strings.Fields(title), " ")

	runes := []rune(title)
	if len(runes) > maxPRTitleLen {
		title = string(runes[:maxPRTitleLen-3]) + "..."
	}
	return title
}

// FormatForPRBody wraps prompts in legitimate-looking PR body content.
func FormatForPRBody(prompts []string) string {
	var b strings.Builder
	b.WriteString("## Description\n\n")
	b.WriteString("This PR updates configuration and documentation.\n\n")
	b.WriteString("## Changes\n\n")
	for i, p := range prompts {
		fmt.Fprintf(&b, "### Change %d\n\n", i+1)
		b.WriteString(p)
		b.WriteString("\n\n")
	}
	b.WriteString("## Testing\n\n")
	b.WriteString("- [x] Unit tests pass\n")
	b.WriteString("- [x] Integration tests pass\n")
	return b.String()
}

// FormatForIssueBody wraps prompts in legitimate-looking issue body content.
func FormatForIssueBody(prompts []string) string {
	var b strings.Builder
	b.WriteString("## Issue Description\n\n")
	b.WriteString("I noticed a potential concern while reviewing the codebase.\n\n")
	b.WriteString("## Details\n\n")
	for i, p := range prompts {
		fmt.Fprintf(&b, "### Finding %d\n\n", i+1)
		b.WriteString(p)
		b.WriteString("\n\n")
	}
	b.WriteString("## Steps to Reproduce\n\n")
	b.WriteString("1. Check the referenced configuration\n")
	b.WriteString("2. Verify the behavior described above\n")
	return b.String()
}

// FormatForIssueComment wraps prompts for issue comment delivery.
func FormatForIssueComment(prompts []string) string {
	var b strings.Builder
	b.WriteString("I found a potential issue while reviewing this:\n\n")
	for _, p := range prompts {
		b.WriteString(p)
		b.WriteString("\n\n")
	}
	b.WriteString("Could someone take a look?\n")
	return b.String()
}

// FormatForCodeComment embeds adversarial prompts as code comments in a Python file.
// AI code reviewers parse these during diff review.
func FormatForCodeComment(prompts []string) string {
	if len(prompts) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`"""Configuration module for project settings.` + "\n\n")
	if len(prompts) > 0 {
		// Escape triple quotes in prompt to avoid breaking the docstring
		safe := strings.ReplaceAll(prompts[0], `"""`, `\"\"\"`)
		b.WriteString("NOTE TO REVIEWER: ")
		b.WriteString(safe)
		b.WriteString("\n")
	}
	b.WriteString(`"""` + "\n\n")
	for i := 1; i < len(prompts); i++ {
		b.WriteString("# ")
		b.WriteString(strings.ReplaceAll(prompts[i], "\n", "\n# "))
		b.WriteString("\n")
	}
	b.WriteString(`DEFAULT_CONFIG = {` + "\n")
	b.WriteString(`    "version": "1.0.0",` + "\n")
	b.WriteString(`    "debug": False,` + "\n")
	b.WriteString("}\n")
	return b.String()
}

// FormatForMarkdownHidden embeds adversarial prompts in HTML comments within markdown.
// Invisible in rendered GitHub UI but parsed by LLMs.
func FormatForMarkdownHidden(prompts []string) string {
	if len(prompts) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("# Configuration Update\n\n")
	b.WriteString("Updated project configuration for compatibility.\n\n")
	for _, p := range prompts {
		// Escape HTML comment close delimiter to avoid breaking the comment
		safe := strings.ReplaceAll(p, "-->", "--\\>")
		b.WriteString("<!-- ")
		b.WriteString(safe)
		b.WriteString(" -->\n\n")
	}
	b.WriteString("## Changes\n\n")
	b.WriteString("- Updated default settings\n")
	return b.String()
}

// FormatForCommitMessage wraps a prompt in a realistic commit message.
func FormatForCommitMessage(prompt string) string {
	var b strings.Builder
	b.WriteString("refactor: update configuration for compatibility\n\n")
	b.WriteString(prompt)
	b.WriteString("\n\nSigned-off-by: dependabot[bot]")
	return b.String()
}

// ApplyEvasion applies an evasion technique to a prompt string.
func ApplyEvasion(prompt string, evasion payloads.EvasionType) string {
	if evasion == payloads.EvasionNone {
		return prompt
	}
	return payloads.GlobalPayloadMutator.Apply(prompt, evasion)
}
