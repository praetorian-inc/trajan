package ui

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"
)

func render(t *testing.T, tier Tier, color bool, fn func(*Printer)) string {
	t.Helper()
	var b bytes.Buffer
	fn(New(tier, color, &b))
	return b.String()
}

func TestHumanAttrs(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []any
		want string
	}{
		{"count leads its unit", []any{"findings", 32}, "scan complete: 32 findings\n"},
		{"underscores become spaces", []any{"surfaces_unreadable", 3}, "scan complete: 3 surfaces unreadable\n"},
		{"a string stands alone", []any{"detail", "secure-files: 403"}, "scan complete: secure-files: 403\n"},
		{"several attrs join", []any{"rules", 66, "findings", 32}, "scan complete: 66 rules, 32 findings\n"},
		{"no attrs, no separator", nil, "scan complete\n"},
		{"an empty value is dropped", []any{"detail", ""}, "scan complete\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := render(t, Human, false, func(p *Printer) { p.log.Info("scan complete", tc.args...) })
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLevelPrefixes(t *testing.T) {
	got := render(t, Human, false, func(p *Printer) { p.log.Warn("collect degraded", "skipped", 2) })
	if got != "warning: collect degraded: 2 skipped\n" {
		t.Errorf("got %q", got)
	}
	got = render(t, Human, false, func(p *Printer) { p.Error("no run directory found", "run collect first") })
	if got != "error: no run directory found\nrun collect first\n" {
		t.Errorf("got %q", got)
	}
}

func TestSeveritiesDropsZeros(t *testing.T) {
	got := render(t, Human, false, func(p *Printer) {
		p.Severities(map[string]int{"critical": 0, "high": 2, "low": 1})
	})
	if got != "high 2, low 1\n" {
		t.Errorf("got %q", got)
	}
	got = render(t, Human, false, func(p *Printer) { p.Severities(map[string]int{}) })
	if got != "" {
		t.Errorf("empty counts printed %q", got)
	}
}

func TestWithAttrs(t *testing.T) {
	var b bytes.Buffer
	p := New(Human, false, &b)
	slog.New(p.log.Handler()).With("findings", 3).Info("scan complete")
	if b.String() != "scan complete: 3 findings\n" {
		t.Errorf("got %q", b.String())
	}
}

func TestColorLeavesTextIntact(t *testing.T) {
	plain := render(t, Human, false, func(p *Printer) { p.Severities(map[string]int{"critical": 1}) })
	colored := render(t, Human, true, func(p *Printer) { p.Severities(map[string]int{"critical": 1}) })
	if colored == plain {
		t.Fatal("color requested but no escape emitted")
	}
	if stripANSI(colored) != plain {
		t.Errorf("color changed the text: %q vs %q", stripANSI(colored), plain)
	}
}

func stripANSI(s string) string {
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '\x1b' {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

// A remote-supplied value must not be able to forge or erase console output.
func TestControlCharactersAreStripped(t *testing.T) {
	evil := "proj\x1b[2K\rSAFE\x07"
	got := render(t, Human, false, func(p *Printer) { p.log.Info("collect degraded", "detail", evil) })
	if strings.ContainsAny(got, "\x1b\r\x07") {
		t.Errorf("escape survived: %q", got)
	}
	// Dropping the ESC disarms the sequence; the "[2K" left behind is inert.
	if got != "collect degraded: proj[2KSAFE\n" {
		t.Errorf("got %q", got)
	}

	got = render(t, Human, false, func(p *Printer) { p.Item(evil) })
	if strings.ContainsAny(got, "\x1b\r\x07") {
		t.Errorf("escape survived in Item: %q", got)
	}
	got = render(t, Human, false, func(p *Printer) { p.Error("bad \x1b[31mproject", "fix \x1b[0mit") })
	if strings.Count(got, "\x1b") != 0 {
		t.Errorf("escape survived in Error: %q", got)
	}
}

// A step table is read by column, and a run log is commonly redirected to a file
// and diffed. Both properties break silently, so both are pinned here.
func TestStepRowHoldsAnEmptyColumnAndPadsNoFurtherThanItsLastWord(t *testing.T) {
	got := render(t, Human, false, func(p *Printer) {
		p.Step(StepLine{Seq: 9, Total: 15, Action: "await workflow run", Status: "unresolved", Note: "not evaluated"})
		p.Step(StepLine{Seq: 1, Total: 15, Action: "resolve repository", Resource: "acme/widgets", Status: "ok", Note: "topic"})
	})
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	for _, l := range lines {
		if strings.HasSuffix(l, " ") {
			t.Errorf("trailing whitespace would land in a redirected log: %q", l)
		}
	}
	// The first row has no target. Its status must still begin where the second
	// row's detail begins, or the absent value collapses the column.
	if a, b := strings.Index(lines[0], "unresolved"), strings.Index(lines[1], "topic"); a != b {
		t.Errorf("columns diverge: status at %d, detail at %d", a, b)
	}
}

// A clause cut mid-rune lands in a log as a replacement character, and the note a
// row carries is a client error the remote side wrote.
func TestAClippedNoteStaysValidUTF8(t *testing.T) {
	got := render(t, Human, false, func(p *Printer) {
		p.Step(StepLine{Seq: 1, Total: 9, Action: "commit code", Resource: "acme/widgets", Status: "failed", Note: strings.Repeat("é", maxNote+10)})
	})
	if !utf8.ValidString(got) {
		t.Fatalf("clip produced invalid UTF-8: %q", got)
	}
	if strings.Count(got, "é") != maxNote-1 {
		t.Errorf("want %d runes kept, got %q", maxNote-1, got)
	}
}

// The status color is decoration. A log read without it still has to distinguish a
// step that ran from one that did not, which is the whole reason the word stays.
func TestStepNamesItsStatusWithoutColorAndStaysSilentOnSuccess(t *testing.T) {
	failed := render(t, Human, false, func(p *Printer) {
		p.Step(StepLine{Seq: 6, Total: 15, Action: "open pull request", Resource: "acme/widgets", Status: "failed", Note: "422 no commits"})
	})
	if !strings.Contains(failed, "failed") {
		t.Errorf("a failed step must say so with color off: %q", failed)
	}
	ok := render(t, Human, false, func(p *Printer) {
		p.Step(StepLine{Seq: 5, Total: 15, Action: "commit code", Resource: "acme/widgets", Status: "ok", Note: "a.txt"})
	})
	if strings.Contains(ok, "ok") {
		t.Errorf("a successful step should not spend a column saying so: %q", ok)
	}
}

func TestColorLeavesTheStepTableIntact(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func(*Printer)
	}{
		{"step", func(p *Printer) {
			p.Step(StepLine{Seq: 1, Total: 9, Action: "create branch", Resource: "acme/widgets", Status: "ok", Note: "topic"})
		}},
		{"failed step", func(p *Printer) {
			p.Step(StepLine{Seq: 2, Total: 9, Action: "open pull request", Resource: "acme/widgets", Status: "failed", Note: "422"})
		}},
		{"outcome", func(p *Printer) {
			p.Outcome("attack complete", []Count{{"ok", 3}, {"failed", 1}}, "2s")
		}},
		{"head", func(p *Printer) { p.Head("Title", [2]string{"plan", "p1"}) }},
		{"section", func(p *Printer) { p.Section("Attack Steps") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plain, colored := render(t, Human, false, tc.fn), render(t, Human, true, tc.fn)
			if colored == plain {
				t.Fatal("color requested but no escape emitted")
			}
			if stripANSI(colored) != plain {
				t.Errorf("color changed the text: %q vs %q", stripANSI(colored), plain)
			}
		})
	}
}

// A successful surface says so in green on its label, so the status word is spent only
// on the degraded ones — where it also names the reason. A redirected log (color off)
// keeps no trailing space on the rows that succeeded.
func TestRowNamesADegradedSurfaceAndStaysSilentOnOk(t *testing.T) {
	got := render(t, Human, false, func(p *Printer) {
		p.Row(RowLine{Seq: 1, Total: 8, Label: "org", Status: "ok"})
		p.Row(RowLine{Seq: 3, Total: 8, Label: "secrets", Status: "degraded", Note: "403"})
	})
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if strings.Contains(lines[0], "ok") || strings.HasSuffix(lines[0], " ") {
		t.Errorf("a collected surface should not spend a column saying ok, nor trail: %q", lines[0])
	}
	if !strings.Contains(lines[1], "degraded") || !strings.Contains(lines[1], "403") {
		t.Errorf("a degraded surface must name itself and its reason: %q", lines[1])
	}
}

// The label carries the outcome color: green when the surface was collected, yellow
// when it degraded. That color is the whole reason a successful row needs no word.
func TestRowColorsItsLabelByOutcome(t *testing.T) {
	green := render(t, Human, true, func(p *Printer) { p.Row(RowLine{Seq: 1, Total: 8, Label: "org", Status: "ok"}) })
	if !strings.Contains(green, "\x1b[92m") {
		t.Errorf("a collected surface should be green: %q", green)
	}
	yellow := render(t, Human, true, func(p *Printer) { p.Row(RowLine{Seq: 3, Total: 8, Label: "secrets", Status: "degraded", Note: "403"}) })
	if !strings.Contains(yellow, "\x1b[93m") {
		t.Errorf("a degraded surface should be yellow: %q", yellow)
	}
}

// The status word aligns across rows so the degraded ones read as a column; that holds
// only while the label cell keeps its width under a shorter value.
func TestRowStatusColumnAligns(t *testing.T) {
	got := render(t, Human, false, func(p *Printer) {
		p.Row(RowLine{Seq: 1, Total: 8, Label: "org", Status: "degraded", Note: "403"})
		p.Row(RowLine{Seq: 5, Total: 8, Label: "runners", Status: "degraded", Note: "404"})
	})
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if a, b := strings.Index(lines[0], "degraded"), strings.Index(lines[1], "degraded"); a != b {
		t.Errorf("status column diverges: %d vs %d", a, b)
	}
}

// --debug is the machine-parseable tier; a phase row becomes a stock slog line whose
// keys a script can read.
func TestRowUnderDebugKeepsAParseableLine(t *testing.T) {
	got := render(t, Debug, false, func(p *Printer) {
		p.Row(RowLine{Seq: 7, Total: 8, Label: "repositories", Status: "failed", Note: "3 unreadable"})
	})
	for _, want := range []string{"msg=repositories", "status=failed", "note="} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %q", want, got)
		}
	}
}

func TestOutcomeDropsZeroCounts(t *testing.T) {
	got := render(t, Human, false, func(p *Printer) {
		p.Outcome("attack complete", []Count{{"ok", 15}, {"failed", 0}, {"mutations", 14}}, "")
	})
	if got != "\nattack complete: 15 ok, 14 mutations\n" {
		t.Errorf("got %q", got)
	}
}

// --debug is the machine-parseable tier, and the step line it emitted before the
// table existed is the one a script may already read.
func TestStepUnderDebugKeepsItsParseableLine(t *testing.T) {
	got := render(t, Debug, false, func(p *Printer) {
		p.Step(StepLine{Seq: 4, Total: 15, ID: "branch_a", Uses: "ref.create", Action: "create branch",
			Target: "acme/widgets", Resource: "acme/widgets/tree/topic", Status: "ok"})
	})
	for _, want := range []string{`msg="step ok"`, "step=branch_a", "uses=ref.create", "target=acme/widgets", "resource=acme/widgets/tree/topic"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %q", want, got)
		}
	}
}
