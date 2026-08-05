package report

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/finding"
)

type reportMeta struct {
	RunID        string
	Platform     string
	Scope        string
	Org          string
	Generated    time.Time
	Total        int
	BySeverity   map[string]int
	ByConfidence map[string]int
}

var (
	severityOrder   = []string{"critical", "high", "medium", "low", "info"}
	confidenceOrder = []string{"high", "medium", "low"}
)

// present returns the levels in `order` that actually occur, preserving order.
func present(counts map[string]int, order []string) []string {
	var out []string
	for _, lvl := range order {
		if counts[lvl] > 0 {
			out = append(out, lvl)
		}
	}
	return out
}

func headerLine(m reportMeta) string {
	var parts []string
	if m.Org != "" {
		parts = append(parts, m.Org)
	}
	return strings.Join(append(parts, "generated "+engine.IsoformatUTC(m.Generated)), " · ")
}

func scopeLine(f finding.Finding) string {
	var parts []string
	if f.Repo != "" {
		parts = append(parts, "repo "+f.Repo)
	}
	if f.File != "" {
		parts = append(parts, "file "+f.File)
	}
	return strings.Join(parts, " · ")
}

func provString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if b, err := json.Marshal(v); err == nil {
		return string(b)
	}
	return fmt.Sprintf("%v", v)
}

func sortedKeys(m map[string]any) []string {
	return slices.Sorted(maps.Keys(m))
}

func codeCaption(f finding.Finding) string {
	if len(f.Code.LineRange) == 2 {
		return fmt.Sprintf("%s (lines %d-%d)", f.File, f.Code.LineRange[0], f.Code.LineRange[1])
	}
	return f.File
}

// ----- Markdown -----

func renderMarkdown(meta reportMeta, findings []finding.Finding) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# trajan findings — %s\n\n", meta.RunID)
	fmt.Fprintf(&b, "%s\n\n", headerLine(meta))

	b.WriteString("## Summary\n\n")
	b.WriteString("| Severity | Count |\n| :-- | --: |\n")
	for _, s := range present(meta.BySeverity, severityOrder) {
		fmt.Fprintf(&b, "| %s | %d |\n", s, meta.BySeverity[s])
	}
	fmt.Fprintf(&b, "| **Total** | **%d** |\n\n", meta.Total)
	if conf := present(meta.ByConfidence, confidenceOrder); len(conf) > 0 {
		var cp []string
		for _, c := range conf {
			cp = append(cp, fmt.Sprintf("%s %d", c, meta.ByConfidence[c]))
		}
		fmt.Fprintf(&b, "Confidence: %s\n\n", strings.Join(cp, " · "))
	}

	if len(findings) == 0 {
		b.WriteString("---\n\n_No findings at the selected thresholds._\n")
		return []byte(b.String())
	}

	for _, f := range findings {
		b.WriteString("---\n\n")
		fmt.Fprintf(&b, "## %s · %s\n\n", f.FindingID, f.Title)
		fmt.Fprintf(&b, "**%s** · confidence %s · %s\n\n", strings.ToUpper(f.Severity), f.Confidence, f.Provider)

		if f.Subject.Display != "" {
			fmt.Fprintf(&b, "- **Subject:** %s (`%s`)\n", f.Subject.Display, f.Subject.Kind)
		}
		if s := scopeLine(f); s != "" {
			fmt.Fprintf(&b, "- **Scope:** %s\n", s)
		}
		b.WriteString("\n")

		if f.Description != "" {
			fmt.Fprintf(&b, "%s\n\n", strings.TrimSpace(f.Description))
		}
		if len(f.Evidence) > 0 {
			b.WriteString("**Evidence**\n\n")
			for _, e := range f.Evidence {
				fmt.Fprintf(&b, "- %s\n", e)
			}
			b.WriteString("\n")
		}
		if f.Code != nil {
			fmt.Fprintf(&b, "**Code** — %s\n\n```\n%s\n```\n\n", codeCaption(f), f.Code.Snippet)
		}
		if len(f.Provenance) > 0 {
			b.WriteString("**Provenance**\n\n")
			for _, k := range sortedKeys(f.Provenance) {
				fmt.Fprintf(&b, "- `%s`: %s\n", k, provString(f.Provenance[k]))
			}
			b.WriteString("\n")
		}
		if f.Remediation != nil && f.Remediation.Hint != "" {
			fmt.Fprintf(&b, "**Remediation:** %s\n\n", strings.TrimSpace(f.Remediation.Hint))
		}
		if f.AINotes != nil && f.AINotes.Text != "" {
			fmt.Fprintf(&b, "**AI notes:** %s\n\n", strings.TrimSpace(f.AINotes.Text))
		}
		if f.Rule != nil {
			fmt.Fprintf(&b, "%s\n\n", ruleLineMD(f.Rule))
		}
	}
	return []byte(b.String())
}

func ruleLineMD(r *finding.Rule) string {
	id := "`" + r.ID + "`"
	if r.URL != "" {
		id = "[" + id + "](" + r.URL + ")"
	}
	line := "Rule: " + id
	if r.ScenarioID != "" {
		line += " · scenario " + r.ScenarioID
	}
	return line
}
