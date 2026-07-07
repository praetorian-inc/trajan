//go:build js

package main

import (
	"fmt"
	"syscall/js"
)

// Build-time version information (injected via -ldflags)
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func getVersionJS(this js.Value, args []js.Value) interface{} {
	return map[string]interface{}{
		"version":   Version,
		"buildTime": BuildTime,
		"gitCommit": GitCommit,
	}
}

func main() {
	c := make(chan struct{})

	registerFunctions()
	js.Global().Set("trajanGetVersion", js.FuncOf(getVersionJS))
	fmt.Printf("Trajan WASM v%s (commit: %s, built: %s)\n", Version, GitCommit, BuildTime)
	<-c
}
