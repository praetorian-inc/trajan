package ui

import (
	"bytes"
	"log/slog"
	"testing"
)

func render(t *testing.T, tier Tier, color bool, fn func(*Printer)) string {
	t.Helper()
	var b bytes.Buffer
	fn(New(tier, color, &b))
	return b.String()
}

// The humanized line is the whole point of the default tier: a count reads as
// "32 findings", not "findings=32", and an underscored key becomes the words it
// stands for so the same attribute reads as prose here and as key=value under
// --debug.
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

// A zero count is not news: an absent severity should leave no trace rather than
// printing "critical 0".
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

// The handler must not drop attrs attached with slog.With, or a logger built
// once and reused loses its context.
func TestWithAttrs(t *testing.T) {
	var b bytes.Buffer
	p := New(Human, false, &b)
	slog.New(p.log.Handler()).With("findings", 3).Info("scan complete")
	if b.String() != "scan complete: 3 findings\n" {
		t.Errorf("got %q", b.String())
	}
}

// Color must encode meaning without changing what the line says.
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
