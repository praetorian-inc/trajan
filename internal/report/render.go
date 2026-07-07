package report

import (
	"encoding/json"
	"fmt"
	"html"
	"maps"
	"slices"
	"strings"

	"github.com/praetorian-inc/trajan/internal/finding"
)

type reportMeta struct {
	RunID        string
	Org          string
	GeneratedAt  string
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
	return strings.Join(append(parts, "generated "+m.GeneratedAt), " · ")
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

// ----- HTML -----

const cssBlock = `
:root { font-family: -apple-system, system-ui, sans-serif; line-height: 1.5; }
body { max-width: 980px; margin: 1.5rem auto; padding: 0 1rem; color: #1b1f23; }
h1 { font-size: 1.6rem; margin-bottom: 0.2rem; } h1 .run { color: #6a737d; font-weight: 400; font-size: 1rem; }
.summary-line { color: #444; margin-top: 0; }
table.summary { border-collapse: collapse; margin: 0.6rem 0 1rem; }
table.summary th, table.summary td { border: 1px solid #e1e4e8; padding: 0.25rem 0.8rem; }
table.summary th { background: #f6f8fa; text-align: left; }
table.summary td.num { text-align: right; font-variant-numeric: tabular-nums; }
.filters { display: flex; flex-wrap: wrap; gap: 1rem; align-items: flex-start;
           background: #f6f8fa; border: 1px solid #e1e4e8; border-radius: 8px;
           padding: 0.7rem 1rem; margin-bottom: 1.2rem; position: sticky; top: 0; z-index: 5; }
.filters fieldset { border: 1px solid #d0d7de; border-radius: 6px; padding: 0.3rem 0.7rem 0.5rem; margin: 0; }
.filters legend { font-size: 0.7rem; text-transform: uppercase; color: #6a737d; padding: 0 0.3rem; }
.filters label { display: block; font-size: 0.85rem; white-space: nowrap; }
.filters .n { color: #6a737d; font-size: 0.78rem; }
.filters select { display: block; min-width: 250px; font-family: ui-monospace, monospace; font-size: 0.76rem; }
.filters #ruleQuery { width: 250px; margin-bottom: 0.3rem; font-size: 0.8rem; padding: 0.15rem 0.3rem; }
.filters button { font-size: 0.75rem; margin-top: 0.3rem; cursor: pointer; }
.filters .count { margin-left: auto; font-size: 0.9rem; align-self: center; color: #444; }
.finding { border: 1px solid #e1e4e8; border-radius: 8px; padding: 1rem 1.25rem; margin: 1rem 0; border-left-width: 5px; }
.finding h2 { font-size: 1.1rem; margin: 0 0 0.5rem; }
.fid { color: #6a737d; font-weight: 600; margin-right: 0.4rem; }
.badges { margin-bottom: 0.5rem; }
.badge { display: inline-block; font-size: 0.72rem; font-weight: 700; text-transform: uppercase;
         padding: 0.1rem 0.5rem; border-radius: 999px; margin-right: 0.4rem; letter-spacing: 0.03em; }
.badge.sev { color: #fff; } .badge.meta { background: #eef1f4; color: #444; }
.sev-critical { border-left-color: #b31d28; } .sev-critical .badge.sev { background: #b31d28; }
.sev-high { border-left-color: #d73a49; } .sev-high .badge.sev { background: #d73a49; }
.sev-medium { border-left-color: #e36209; } .sev-medium .badge.sev { background: #e36209; }
.sev-low { border-left-color: #dbab09; } .sev-low .badge.sev { background: #b08800; }
.sev-info { border-left-color: #6a737d; } .sev-info .badge.sev { background: #6a737d; }
.subject { color: #444; font-size: 0.92rem; margin: 0.25rem 0; }
.desc { margin: 0.6rem 0; }
.label { font-weight: 600; font-size: 0.8rem; text-transform: uppercase; color: #6a737d; margin-top: 0.8rem; }
ul.evidence { margin: 0.3rem 0; } ul.evidence li { margin: 0.15rem 0; }
pre { background: #f6f8fa; border-radius: 6px; padding: 0.8rem; overflow-x: auto; font-size: 0.82rem; }
table.prov { border-collapse: collapse; font-size: 0.85rem; width: 100%; }
table.prov td { border: 1px solid #e1e4e8; padding: 0.25rem 0.5rem; vertical-align: top; }
table.prov td.k { font-family: ui-monospace, monospace; color: #6a737d; white-space: nowrap; width: 1%; }
.remediation { background: #f2fbf3; border-radius: 6px; padding: 0.5rem 0.75rem; margin-top: 0.6rem; }
.rule { color: #6a737d; font-size: 0.78rem; margin-top: 0.6rem; }
.rule a { color: #0366d6; text-decoration: none; } .rule a:hover { text-decoration: underline; }
#empty { display: none; color: #6a737d; font-style: italic; }
`

const jsBlock = `
function vals(name){return Array.from(document.querySelectorAll('input[name="'+name+'"]:checked')).map(e=>e.value);}
function apply(){
  var sev=vals('sev'), conf=vals('conf');
  var sel=Array.from(document.getElementById('ruleSelect').selectedOptions).map(function(o){return o.value;});
  var shown=0;
  document.querySelectorAll('section.finding').forEach(function(s){
    var ok = sev.indexOf(s.dataset.severity)>=0
          && conf.indexOf(s.dataset.confidence)>=0
          && (sel.length===0 || sel.indexOf(s.dataset.rule)>=0);
    s.style.display = ok ? '' : 'none';
    if(ok) shown++;
  });
  document.getElementById('shown').textContent = shown;
  document.getElementById('empty').style.display = shown ? 'none' : 'block';
}
function ruleSearch(){
  var q=document.getElementById('ruleQuery').value.toLowerCase();
  Array.from(document.getElementById('ruleSelect').options).forEach(function(o){
    o.hidden = q && o.value.toLowerCase().indexOf(q)<0;
  });
}
function clearRules(){
  Array.from(document.getElementById('ruleSelect').options).forEach(function(o){o.selected=false;});
  apply();
}
document.addEventListener('DOMContentLoaded', apply);
`

func renderHTML(meta reportMeta, findings []finding.Finding) []byte {
	ruleCounts := countBy(findings, func(f finding.Finding) string { return ruleID(f) })

	var b strings.Builder
	b.WriteString("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	fmt.Fprintf(&b, "<title>trajan findings — %s</title>\n", he(meta.RunID))
	b.WriteString("<style>" + cssBlock + "</style></head><body>\n")
	fmt.Fprintf(&b, "<h1>trajan findings <span class=\"run\">%s</span></h1>\n", he(meta.RunID))
	fmt.Fprintf(&b, "<p class=\"summary-line\">%s</p>\n", he(headerLine(meta)))

	writeSummaryTable(&b, meta)
	writeFilters(&b, meta, ruleCounts)

	fmt.Fprintf(&b, "<p id=\"empty\">No findings match the current filters.</p>\n")
	for _, f := range findings {
		writeFindingHTML(&b, f)
	}

	b.WriteString("<script>" + jsBlock + "</script>\n")
	b.WriteString("</body></html>\n")
	return []byte(b.String())
}

func writeSummaryTable(b *strings.Builder, meta reportMeta) {
	b.WriteString("<table class=\"summary\"><tr><th>Severity</th><th>Count</th></tr>\n")
	for _, s := range present(meta.BySeverity, severityOrder) {
		fmt.Fprintf(b, "<tr><td>%s</td><td class=\"num\">%d</td></tr>\n", he(s), meta.BySeverity[s])
	}
	fmt.Fprintf(b, "<tr><td><strong>Total</strong></td><td class=\"num\"><strong>%d</strong></td></tr>\n", meta.Total)
	b.WriteString("</table>\n")
}

func writeFilters(b *strings.Builder, meta reportMeta, ruleCounts map[string]int) {
	b.WriteString("<div class=\"filters\">\n")

	b.WriteString("<fieldset><legend>Severity</legend>\n")
	for _, s := range present(meta.BySeverity, severityOrder) {
		fmt.Fprintf(b, "<label><input type=\"checkbox\" name=\"sev\" value=\"%s\" checked onchange=\"apply()\"> %s <span class=\"n\">%d</span></label>\n", he(s), he(s), meta.BySeverity[s])
	}
	b.WriteString("</fieldset>\n")

	b.WriteString("<fieldset><legend>Confidence</legend>\n")
	for _, c := range present(meta.ByConfidence, confidenceOrder) {
		fmt.Fprintf(b, "<label><input type=\"checkbox\" name=\"conf\" value=\"%s\" checked onchange=\"apply()\"> %s <span class=\"n\">%d</span></label>\n", he(c), he(c), meta.ByConfidence[c])
	}
	b.WriteString("</fieldset>\n")

	b.WriteString("<fieldset><legend>Rule (none selected = all)</legend>\n")
	b.WriteString("<input id=\"ruleQuery\" type=\"text\" placeholder=\"filter rules…\" autocomplete=\"off\" oninput=\"ruleSearch()\">\n")
	b.WriteString("<select id=\"ruleSelect\" multiple size=\"6\" onchange=\"apply()\">\n")
	for _, id := range slices.Sorted(maps.Keys(ruleCounts)) {
		if id == "" {
			continue
		}
		fmt.Fprintf(b, "<option value=\"%s\">%s (%d)</option>\n", he(id), he(id), ruleCounts[id])
	}
	b.WriteString("</select>\n<button type=\"button\" onclick=\"clearRules()\">clear rule selection</button>\n</fieldset>\n")

	fmt.Fprintf(b, "<div class=\"count\">Showing <strong id=\"shown\">%d</strong> of %d</div>\n", meta.Total, meta.Total)
	b.WriteString("</div>\n")
}

func writeFindingHTML(b *strings.Builder, f finding.Finding) {
	fmt.Fprintf(b, "<section class=\"finding sev-%s\" data-severity=\"%s\" data-confidence=\"%s\" data-rule=\"%s\">\n",
		he(f.Severity), he(f.Severity), he(f.Confidence), he(ruleID(f)))
	fmt.Fprintf(b, "<h2><span class=\"fid\">%s</span>%s</h2>\n", he(f.FindingID), he(f.Title))

	b.WriteString("<div class=\"badges\">")
	fmt.Fprintf(b, "<span class=\"badge sev\">%s</span>", he(f.Severity))
	fmt.Fprintf(b, "<span class=\"badge meta\">confidence %s</span>", he(f.Confidence))
	fmt.Fprintf(b, "<span class=\"badge meta\">%s</span>", he(f.Provider))
	b.WriteString("</div>\n")

	if f.Subject.Display != "" {
		fmt.Fprintf(b, "<div class=\"subject\">%s <em>(%s)</em></div>\n", he(f.Subject.Display), he(f.Subject.Kind))
	}
	if s := scopeLine(f); s != "" {
		fmt.Fprintf(b, "<div class=\"subject\">%s</div>\n", he(s))
	}
	if f.Description != "" {
		fmt.Fprintf(b, "<p class=\"desc\">%s</p>\n", he(strings.TrimSpace(f.Description)))
	}
	if len(f.Evidence) > 0 {
		b.WriteString("<div class=\"label\">Evidence</div>\n<ul class=\"evidence\">\n")
		for _, e := range f.Evidence {
			fmt.Fprintf(b, "<li>%s</li>\n", he(e))
		}
		b.WriteString("</ul>\n")
	}
	if f.Code != nil {
		fmt.Fprintf(b, "<div class=\"label\">Code — %s</div>\n<pre>%s</pre>\n", he(codeCaption(f)), he(f.Code.Snippet))
	}
	if len(f.Provenance) > 0 {
		b.WriteString("<div class=\"label\">Provenance</div>\n<table class=\"prov\">\n")
		for _, k := range sortedKeys(f.Provenance) {
			fmt.Fprintf(b, "<tr><td class=\"k\">%s</td><td>%s</td></tr>\n", he(k), he(provString(f.Provenance[k])))
		}
		b.WriteString("</table>\n")
	}
	if f.Remediation != nil && f.Remediation.Hint != "" {
		fmt.Fprintf(b, "<div class=\"remediation\"><strong>Remediation.</strong> %s</div>\n", he(strings.TrimSpace(f.Remediation.Hint)))
	}
	if f.AINotes != nil && f.AINotes.Text != "" {
		fmt.Fprintf(b, "<div class=\"remediation\"><strong>AI notes.</strong> %s</div>\n", he(strings.TrimSpace(f.AINotes.Text)))
	}
	if f.Rule != nil {
		fmt.Fprintf(b, "<div class=\"rule\">%s</div>\n", ruleLineHTML(f.Rule))
	}
	b.WriteString("</section>\n")
}

func ruleLineHTML(r *finding.Rule) string {
	id := "<code>" + he(r.ID) + "</code>"
	if r.URL != "" {
		id = fmt.Sprintf("<a href=\"%s\">%s</a>", he(r.URL), id)
	}
	line := "Rule: " + id
	if r.ScenarioID != "" {
		line += " · scenario " + he(r.ScenarioID)
	}
	return line
}

func he(s string) string { return html.EscapeString(s) }
