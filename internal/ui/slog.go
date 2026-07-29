package ui

import (
	"context"
	"log/slog"
	"slices"
	"strings"
)

type handler struct {
	p     *Printer
	attrs []slog.Attr
}

func (h *handler) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelInfo }

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	attrs := slices.Clone(h.attrs)
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})
	switch {
	case r.Level >= slog.LevelError:
		h.p.raw(h.p.c(red, "error:") + " " + r.Message + h.p.humanAttrs(attrs))
	case r.Level >= slog.LevelWarn:
		h.p.raw(h.p.c(yellow, "warning:") + " " + r.Message + h.p.humanAttrs(attrs))
	default:
		h.p.raw(r.Message + h.p.humanAttrs(attrs))
	}
	return nil
}

func (h *handler) WithAttrs(as []slog.Attr) slog.Handler {
	return &handler{p: h.p, attrs: append(slices.Clip(h.attrs), as...)}
}

// A group name adds nothing to a line meant to be read, so groups are flattened
// into the parent rather than qualifying their attrs.
func (h *handler) WithGroup(string) slog.Handler { return h }

// humanAttrs renders attributes as prose. A number is the news and its key is
// the unit, so it reads "32 findings"; any other value stands alone, because in
// a sentence the key only repeats what the message already said. Underscores in
// a key become spaces, so the same attribute reads as words here and stays
// surfaces_unreadable=3 under --debug.
func (p *Printer) humanAttrs(attrs []slog.Attr) string {
	var parts []string
	for _, a := range attrs {
		v := a.Value.Resolve()
		switch v.Kind() {
		case slog.KindInt64, slog.KindUint64, slog.KindFloat64:
			parts = append(parts, p.c(bold, v.String())+" "+strings.ReplaceAll(a.Key, "_", " "))
		default:
			if s := v.String(); s != "" {
				parts = append(parts, s)
			}
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return ": " + strings.Join(parts, ", ")
}
