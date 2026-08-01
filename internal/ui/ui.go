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
	yellow  = 11
	blue    = 12
	magenta = 13
	dim     = 8
	bold    = -1
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
	if !p.color || s == "" {
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
	return 0
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

func Item(s string)                    { std.Item(s) }
func Error(msg, remedy string)         { std.Error(msg, remedy) }
func Severities(counts map[string]int) { std.Severities(counts) }
