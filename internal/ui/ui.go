// Package ui renders console output as a humanized default or, under --debug,
// stock slog text. Status lines are ordinary slog calls humanized by the handler
// in slog.go; this file holds only what slog cannot express.
package ui

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

type Tier int

const (
	Human Tier = iota
	Debug
)

// Indices 0-15 only, never hex: these resolve through the reader's own theme.
const (
	red     = 9
	green   = 10
	yellow  = 11
	blue    = 12
	magenta = 13
	dim     = 8
	bold    = -1
	plain   = -2
)

type Printer struct {
	tier  Tier
	color bool
	w     io.Writer
	log   *slog.Logger
}

func New(t Tier, color bool, w io.Writer) *Printer {
	p := &Printer{tier: t, color: color && t == Human, w: w}
	// Debug keeps the stock TextHandler so its output stays machine-parseable.
	if t == Debug {
		p.log = slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
	} else {
		p.log = slog.New(&handler{p: p})
	}
	return p
}

var std = New(Human, false, os.Stderr)

// Points slog at the printer, so an ordinary slog.Info anywhere in the tree
// comes out in the selected tier.
func Init(t Tier, color bool) {
	std = New(t, color, os.Stderr)
	slog.SetDefault(std.log)
}

func ColorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stderr.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func (p *Printer) c(idx int, s string) string {
	if !p.color || s == "" || idx == plain {
		return s
	}
	if idx == bold {
		return "\x1b[1m" + s + "\x1b[0m"
	}
	if idx < 8 {
		return fmt.Sprintf("\x1b[3%dm%s\x1b[0m", idx, s)
	}
	return fmt.Sprintf("\x1b[9%dm%s\x1b[0m", idx-8, s)
}

func severityColor(s string) int {
	switch s {
	case "critical":
		return magenta
	case "high":
		return red
	case "medium":
		return yellow
	case "low":
		return blue
	}
	return plain
}

// Green is spent only here, on the one word that says what the step did, because a
// run where every line is colored is a run where a failure no longer stands out.
func stepColor(status string) int {
	switch status {
	case "ok":
		return green
	case "failed":
		return red
	case "skipped", "unresolved":
		return yellow
	}
	return plain
}

// countColor leaves the expected outcomes uncolored, so a clean run closes with
// no color at all and the first red thing on the screen is always news.
func countColor(label string) int {
	switch label {
	case "failed":
		return red
	case "skipped", "unresolved", "partial", "irreversible":
		return yellow
	}
	return plain
}

func (p *Printer) raw(s string) { fmt.Fprintln(p.w, s) }

// Project names and error bodies arrive from the remote side; dropping the ESC
// disarms any sequence they carry. --debug is safe already, TextHandler escapes.
func clean(s string) string {
	if strings.IndexFunc(s, isControl) < 0 {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isControl(r) {
			return -1
		}
		return r
	}, s)
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

func (p *Printer) Item(s string) {
	if p.tier == Human {
		p.raw("  " + clean(s))
		return
	}
	p.log.Info(s)
}

// Note is an indented line of chrome — a path, a next command — that recedes
// because it is not the news of the block it sits under.
func (p *Printer) Note(s string) {
	if p.tier != Human {
		return
	}
	p.raw("  " + p.c(dim, clean(s)))
}

func (p *Printer) Error(msg, remedy string) {
	if p.tier != Human {
		if remedy == "" {
			p.log.Error(msg)
			return
		}
		p.log.Error(msg, "remedy", remedy)
		return
	}
	p.raw(p.c(red, "error:") + " " + clean(msg))
	if remedy != "" {
		p.raw(p.c(dim, clean(remedy)))
	}
}

// Zero counts are dropped: an absent severity is not news.
func (p *Printer) Severities(counts map[string]int) {
	order := []string{"critical", "high", "medium", "low", "info"}
	if p.tier != Human {
		var args []any
		for _, s := range order {
			if counts[s] > 0 {
				args = append(args, s, counts[s])
			}
		}
		if len(args) > 0 {
			p.log.Info("severity", args...)
		}
		return
	}
	var parts []string
	for _, s := range order {
		if counts[s] > 0 {
			parts = append(parts, p.c(severityColor(s), s)+" "+strconv.Itoa(counts[s]))
		}
	}
	if len(parts) > 0 {
		p.raw(strings.Join(parts, ", "))
	}
}

type cell struct {
	s     string
	w     int
	color int
}

// row pads every cell but the last non-empty one, so no row carries trailing
// whitespace into a redirected log. Padding is measured on the plain text and
// applied before coloring, because an escape sequence occupies no columns. An
// empty cell holds its column when it has a width and disappears when it does
// not, which is how the status cell vanishes on the rows that succeeded.
func (p *Printer) row(indent string, cs ...cell) string {
	last := -1
	for i, c := range cs {
		if c.s != "" {
			last = i
		}
	}
	if last < 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(indent)
	for i, c := range cs[:last+1] {
		if c.s == "" && c.w == 0 {
			continue
		}
		s := clean(c.s)
		if i < last && len(s) < c.w {
			s += strings.Repeat(" ", c.w-len(s))
		}
		b.WriteString(p.c(c.color, s))
		if i < last {
			b.WriteByte(' ')
		}
	}
	return b.String()
}

// The labels recede because the value is the news, the rule humanAttrs applies to
// an attr key, in a shape a single line could not hold.
func (p *Printer) Head(subject string, fields ...[2]string) {
	if p.tier != Human {
		args := make([]any, 0, 2*len(fields))
		for _, f := range fields {
			if f[1] != "" {
				args = append(args, f[0], f[1])
			}
		}
		p.log.Info(subject, args...)
		return
	}
	p.raw(p.c(bold, clean(subject)))
	for _, f := range fields {
		if f[1] == "" {
			continue
		}
		p.raw("  " + p.c(dim, fmt.Sprintf("%-8s", f[0])) + "  " + clean(f[1]))
	}
}

// Debug carries the per-item records and has no use for a heading to group them
// under.
func (p *Printer) Section(name string) {
	if p.tier != Human {
		return
	}
	p.raw("")
	p.raw(p.c(bold, clean(name)))
}

// Resource is the object the step acted on and carries the row; Note is a clause the
// caller has already reduced to what a column can hold. Uses and Target reach only
// --debug, which keeps the machine-parseable line it had before this renderer
// existed; ID reaches the table itself on the rows another step can refer to.
type StepLine struct {
	Seq, Total int
	ID, Uses   string
	Action     string
	Target     string
	Resource   string
	Status     string
	Note       string
}

// Any status but ok also names itself: the color on the action is decoration, and a
// log read without it still has to distinguish a step that ran from one that did not.
func (p *Printer) Step(l StepLine) {
	if p.tier != Human {
		args := []any{"step", l.ID, "uses", l.Uses, "target", l.Target, "resource", l.Resource}
		if l.Note != "" {
			args = append(args, "note", l.Note)
		}
		p.log.Info("step "+l.Status, args...)
		return
	}
	w := len(strconv.Itoa(l.Total))
	status := l.Status
	switch l.Status {
	case "ok":
		status = ""
	case "failed", "skipped":
		// The only two statuses another step's note can name ("step %q is failed"),
		// so the only two that have to carry the id that resolves the reference. The
		// colon is load-bearing: without it "skipped branch_b step" reads as a phrase.
		status = strings.TrimSpace(l.Status + " " + l.ID)
		if l.Note != "" {
			status += ":"
		}
	}
	p.raw(p.row("  ",
		cell{fmt.Sprintf("%*d/%d", w, l.Seq, l.Total), 2*w + 1, dim},
		cell{l.Action, 25, stepColor(l.Status)},
		cell{clip(l.Resource, maxResource), 46, plain},
		cell{status, 0, stepColor(l.Status)},
		cell{clip(l.Note, maxNote), 0, dim},
	))
}

// A resource is an identifier and gets the room to stay pasteable; a note is a
// clause and does not. Truncation belongs to this tier alone: a client error runs
// to hundreds of characters with the URL it called and its response body, and
// --debug is where an operator goes to read the whole of it.
const (
	maxResource = 64
	maxNote     = 40
)

func clip(s string, limit int) string {
	r := []rune(s)
	if len(r) <= limit {
		return s
	}
	return string(r[:limit-1]) + "…"
}

type Count struct {
	Label string
	N     int
}

// Zero counts go unsaid for the same reason Severities drops them.
func (p *Printer) Outcome(subject string, counts []Count, trailer string) {
	if p.tier != Human {
		args := make([]any, 0, 2*len(counts))
		for _, c := range counts {
			if c.N > 0 {
				args = append(args, c.Label, c.N)
			}
		}
		p.log.Info(subject, args...)
		return
	}
	var parts []string
	for _, c := range counts {
		if c.N == 0 {
			continue
		}
		parts = append(parts, p.c(bold, strconv.Itoa(c.N))+" "+p.c(countColor(c.Label), c.Label))
	}
	// Outcome closes a block, so it owns the blank line that separates it from the
	// rows above rather than making every caller remember one.
	p.raw("")
	line := clean(subject)
	if len(parts) > 0 {
		line += ": " + strings.Join(parts, ", ")
	}
	if trailer != "" {
		line += " " + p.c(dim, clean(trailer))
	}
	p.raw(line)
}

func Item(s string)                    { std.Item(s) }
func Error(msg, remedy string)         { std.Error(msg, remedy) }
func Severities(counts map[string]int) { std.Severities(counts) }

func Note(s string)                                          { std.Note(s) }
func Head(subject string, fields ...[2]string)               { std.Head(subject, fields...) }
func Section(name string)                                    { std.Section(name) }
func Step(l StepLine)                                        { std.Step(l) }
func Outcome(subject string, counts []Count, trailer string) { std.Outcome(subject, counts, trailer) }
