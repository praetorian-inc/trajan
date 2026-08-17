//go:build js

package main

import (
	"fmt"
	"syscall/js"
)

// Injected via -ldflags from the Makefile.
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

func main() {
	registerAPI()
	js.Global().Set("trajanGetVersion", js.FuncOf(func(this js.Value, args []js.Value) any {
		return map[string]any{
			"version":   Version,
			"buildTime": BuildTime,
			"gitCommit": GitCommit,
		}
	}))
	fmt.Printf("Trajan WASM v%s (commit %s)\n", Version, GitCommit)
	select {}
}
