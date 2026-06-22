package engine

import (
	"log/slog"
	"os"
)

func InitLogger(dev bool) {
	level := slog.LevelInfo
	var h slog.Handler
	if dev {
		level = slog.LevelDebug
		h = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	} else {
		h = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	}
	slog.SetDefault(slog.New(h))
}
