package report

import (
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/trajan/internal/finding"
)

func renderOne(t *testing.T, meta reportMeta, findings []finding.Finding) string {
	t.Helper()
	meta.Total = len(findings)
	meta.BySeverity = countBy(findings, func(f finding.Finding) string { return f.Severity })
	meta.ByConfidence = countBy(findings, func(f finding.Finding) string { return f.Confidence })
	b, err := renderHTML(meta, findings)
	if err != nil {
		t.Fatalf("renderHTML: %v", err)
	}
	out := string(b)
	// CSS and JS are inlined and both name the markup they drive, so an assertion
	// against the whole document would match an asset rather than the report.
	if !strings.Contains(out, "<style>") {
		t.Fatal("no inline stylesheet: the assertions below would be meaningless")
	}
	return emptyInline(emptyInline(out, "style"), "script")
}

func emptyInline(doc, tag string) string {
	head, rest, found := strings.Cut(doc, "<"+tag+">")
	if !found {
		return doc
	}
	_, tail, _ := strings.Cut(rest, "</"+tag+">")
	return head + "<" + tag + "></" + tag + ">" + tail
}

// Every pointer field on a finding is nullable and scan emits findings with all
// of them nil; a template that dereferences one fails at execute time.
func TestRenderHTMLTolerAtesEveryNilField(t *testing.T) {
	f := finding.Finding{
		FindingID: "F-001", Provider: "github", Severity: "high", Confidence: "low",
		Title:   "Bare finding",
		Subject: finding.Subject{Kind: "job"},
	}
	out := renderOne(t, reportMeta{Generated: time.Now()}, []finding.Finding{f})

	if !strings.Contains(out, "Bare finding") {
		t.Error("title missing")
	}
	if strings.Contains(out, "<details") {
		t.Error("no description and no provenance should mean no Details block")
	}
	if strings.Contains(out, "meta-line") {
		t.Error("a nil rule should not render a rule line")
	}
}

// The rule id belongs behind the Details toggle, not in the card header.
func TestRenderHTMLKeepsRuleOutOfTheCardHeader(t *testing.T) {
	f := finding.Finding{
		Severity: "high", Confidence: "high", Title: "T",
		Rule: &finding.Rule{ID: "cat-01/x", URL: "https://example.test/x.yaml"},
	}
	out := renderOne(t, reportMeta{Generated: time.Now()}, []finding.Finding{f})

	// data-rule on the article is the filter hook, not rendered text, so only the
	// visible header block is checked.
	_, rest, _ := strings.Cut(out, `<div class="f-head">`)
	head, _, _ := strings.Cut(rest, "</div>")
	if strings.Contains(head, "cat-01/x") {
		t.Errorf("rule id must not appear in the card header:\n%s", head)
	}
	if !strings.Contains(out, `<p class="meta-line">`) || !strings.Contains(out, "cat-01/x") {
		t.Error("the rule still has to be reachable inside Details")
	}
}

func TestRenderHTMLShowsDetailsForDescriptionAlone(t *testing.T) {
	f := finding.Finding{Severity: "low", Confidence: "low", Description: "why it matters"}
	out := renderOne(t, reportMeta{Generated: time.Now()}, []finding.Finding{f})

	if !strings.Contains(out, "<details") || !strings.Contains(out, "why it matters") {
		t.Errorf("a description with no provenance still needs a Details block:\n%s", out)
	}
}

// Rule.URL reaches an href, where HTML-escaping alone still lets a javascript:
// scheme through to the browser intact.
func TestRenderHTMLNeutersNonHTTPRuleURL(t *testing.T) {
	f := finding.Finding{
		Severity: "high", Confidence: "high",
		Rule: &finding.Rule{ID: "cat-01/x", URL: "javascript:alert(1)"},
	}
	out := renderOne(t, reportMeta{Generated: time.Now()}, []finding.Finding{f})

	if strings.Contains(out, "javascript:alert") {
		t.Errorf("hostile rule URL survived into the document:\n%s", out)
	}
	if !strings.Contains(out, "cat-01/x") {
		t.Error("the rule id itself should still render")
	}
}

// The script always ships so the theme toggle works on an empty report; its
// filter half early-returns on a missing #q, which the empty report must omit.
func TestRenderHTMLEmptyReportKeepsThemeButNotFilters(t *testing.T) {
	out := renderOne(t, reportMeta{Generated: time.Now()}, nil)

	for _, want := range []string{"<script", `id="theme"`, "Nothing to report"} {
		if !strings.Contains(out, want) {
			t.Errorf("empty report is missing %s", want)
		}
	}
	for _, unwanted := range []string{`id="q"`, `id="reset"`, `id="shown"`, "sidebar"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("empty report should not render %s", unwanted)
		}
	}
}

// A rule id is "cat-NN/rule-name"; the sidebar groups on that prefix and each
// group's count must be the sum of its rules, not a rule count.
func TestRuleGroupsSplitOnCategory(t *testing.T) {
	in := []finding.Finding{
		{Rule: &finding.Rule{ID: "cat-01/alpha"}},
		{Rule: &finding.Rule{ID: "cat-01/alpha"}},
		{Rule: &finding.Rule{ID: "cat-01/beta"}},
		{Rule: &finding.Rule{ID: "cat-04/gamma"}},
		{Rule: &finding.Rule{ID: "unprefixed"}},
		{Rule: nil}, // pure-AI findings carry no rule and must not become a group
	}
	got := ruleGroups(in)

	if len(got) != 3 {
		t.Fatalf("want ungrouped + cat-01 + cat-04, got %d: %+v", len(got), got)
	}
	if got[0].Cat != "" || len(got[0].Rules) != 1 || got[0].Rules[0].Leaf != "unprefixed" {
		t.Errorf("an id with no category should sort first and stay whole: %+v", got[0])
	}
	if got[1].Cat != "cat-01" || got[1].N != 3 {
		t.Errorf("cat-01 should total its three findings, got %+v", got[1])
	}
	if len(got[1].Rules) != 2 || got[1].Rules[0].Leaf != "alpha" || got[1].Rules[0].N != 2 {
		t.Errorf("cat-01 rules wrong: %+v", got[1].Rules)
	}
	if got[1].Rules[0].ID != "cat-01/alpha" {
		t.Errorf("the filter value must stay the full id, got %q", got[1].Rules[0].ID)
	}
}

// The run directory name is an internal handle; the heading is the scanned scope.
func TestRenderHTMLHeadingIsScopeNotRunID(t *testing.T) {
	meta := reportMeta{
		RunID:     "2026-08-03-1956-ado-portustrajan__portus-payments",
		Scope:     "PortusTrajan/portus-payments",
		Platform:  "ado",
		Generated: time.Date(2026, 8, 3, 22, 42, 0, 0, time.UTC),
	}
	out := renderOne(t, meta, []finding.Finding{{Severity: "high", Confidence: "high"}})

	heading := "<h1>PortusTrajan/portus-payments</h1>"
	if !strings.Contains(out, heading) {
		t.Errorf("want %s in output", heading)
	}
	before, _, _ := strings.Cut(out, "</h1>")
	if strings.Contains(before, meta.RunID) {
		t.Error("run id must not appear above the heading")
	}
	if !strings.Contains(out, "Generated 3 Aug 2026 22:42 UTC") {
		t.Error("want a human-readable generated stamp, not the iso form")
	}
	if strings.Contains(out, "22:42:00") {
		t.Error("iso timestamp leaked into the html report")
	}
}

func TestLocationOf(t *testing.T) {
	for _, tc := range []struct {
		name       string
		in         finding.Finding
		path, want string
	}{{
		name: "file anchored, no label needed",
		in: finding.Finding{Org: "PortusTrajan", Repo: "portus-payments", File: "/azure-pipelines.yml",
			Subject: finding.Subject{Kind: "pipeline", Display: "portus-payments › portus-payments-ci"}},
		path: "PortusTrajan/portus-payments/azure-pipelines.yml",
	}, {
		name: "no file falls back to scope plus kind",
		in: finding.Finding{Org: "PortusTrajan", Repo: "portus-payments",
			Subject: finding.Subject{Kind: "can_push_to", Display: "portus-payments › …@main"}},
		path: "PortusTrajan/portus-payments", want: "CAN PUSH TO",
	}, {
		name: "org scoped",
		in:   finding.Finding{Org: "PortusTrajan", Subject: finding.Subject{Kind: "org"}},
		path: "PortusTrajan", want: "ORG",
	}, {
		// GitHub repos are "owner/name", so prepending Org would read acme/acme/api.
		name: "github repo already carries its org",
		in: finding.Finding{Org: "acme", Repo: "acme/api", File: ".github/workflows/build.yml",
			Subject: finding.Subject{Kind: "workflow_job"}},
		path: "acme/api/.github/workflows/build.yml",
	}, {
		name: "no scope handles at all",
		in:   finding.Finding{Subject: finding.Subject{Kind: "feed", Display: "org/73575639"}},
		path: "org/73575639",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got := locationOf(tc.in)
			if got.Path != tc.path || got.Label != tc.want {
				t.Errorf("got {%q %q}, want {%q %q}", got.Path, got.Label, tc.path, tc.want)
			}
		})
	}
}

// Older runs wrote no platform into _meta.json, but every finding names its own
// provider.
func TestPlatformLabelFallsBackToFindingProvider(t *testing.T) {
	got := platformLabel(reportMeta{}, []finding.Finding{{Provider: "gitlab"}})
	if got != "GitLab" {
		t.Errorf("want GitLab, got %q", got)
	}
	if got := platformLabel(reportMeta{Platform: "ado"}, nil); got != "Azure DevOps" {
		t.Errorf("want Azure DevOps, got %q", got)
	}
	if got := platformLabel(reportMeta{Platform: "bitbucket"}, nil); got != "bitbucket" {
		t.Errorf("an unmapped platform should pass through, got %q", got)
	}
}
